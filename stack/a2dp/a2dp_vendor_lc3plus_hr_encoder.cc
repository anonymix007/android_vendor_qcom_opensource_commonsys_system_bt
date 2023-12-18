/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "a2dp_vendor_lc3plus_hr_encoder"
#define ATRACE_TAG ATRACE_TAG_AUDIO

#include "a2dp_vendor_lc3plus_hr_encoder.h"

#ifndef OS_GENERIC
#include <cutils/trace.h>
#endif
#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <lc3_cpp.h>

#include "a2dp_vendor.h"
#include "a2dp_vendor_lc3plus_hr.h"
#include "bt_common.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

//
// Encoder for LC3plus HR Source Codec
//

// A2DP LC3plus HR encoder interval in milliseconds
#define A2DP_LC3PLUS_HR_ENCODER_INTERVAL_MS 20
//#define A2DP_LC3PLUS_HR_MEDIA_BYTES_PER_FRAME 128


//#define DEBUG
#ifdef DEBUG
#define LC3PLUS_HR_SAVE_DUMP
#endif
#ifdef LC3PLUS_HR_SAVE_DUMP
#define ENC_RAW_NAME "/sdcard/Download/a2dp_lc3plus_hr.lc3plus"
#define ENC_PCM_NAME "/sdcard/Download/a2dp_lc3plus_hr.pcm"
#endif

// offset
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
#define A2DP_LC3PLUS_HR_OFFSET (AVDT_MEDIA_OFFSET + A2DP_LC3PLUS_HR_MPL_HDR_LEN + 1)
#else
#define A2DP_LC3PLUS_HR_OFFSET (AVDT_MEDIA_OFFSET + A2DP_LC3PLUS_HR_MPL_HDR_LEN)
#endif

typedef struct {
  uint32_t sample_rate;
  uint8_t channel_count;
  uint8_t bits_per_sample;
  float frame_ms;
  lc3::PcmFormat fmt;
  uint32_t bitrate;
  uint32_t abr_bitrate;

  uint32_t tsi;
} tA2DP_LC3PLUS_HR_ENCODER_PARAMS;

typedef struct {
  float counter;
  uint32_t bytes_per_tick; /* pcm bytes read each media task tick */
  uint64_t last_frame_us;
} tA2DP_LC3PLUS_HR_FEEDING_STATE;

typedef struct {
  uint64_t session_start_us;

  size_t media_read_total_expected_packets;
  size_t media_read_total_expected_reads_count;
  size_t media_read_total_expected_read_bytes;

  size_t media_read_total_dropped_packets;
  size_t media_read_total_actual_reads_count;
  size_t media_read_total_actual_read_bytes;
} a2dp_lc3plus_hr_encoder_stats_t;

typedef struct {
  a2dp_source_read_callback_t read_callback;
  a2dp_source_enqueue_callback_t enqueue_callback;
  uint16_t TxAaMtuSize;
  size_t TxQueueLength;

  bool use_SCMS_T;
  bool is_peer_edr;          // True if the peer device supports EDR
  bool peer_supports_3mbps;  // True if the peer device supports 3Mbps EDR
  uint16_t peer_mtu;         // MTU of the A2DP peer
  uint32_t timestamp;        // Timestamp for the A2DP frames

  lc3::Encoder *encoder;
  bool has_lc3plus_hr_handle;  // True if encoder is valid

  tA2DP_FEEDING_PARAMS feeding_params;
  tA2DP_LC3PLUS_HR_ENCODER_PARAMS lc3plus_hr_encoder_params;
  tA2DP_LC3PLUS_HR_FEEDING_STATE lc3plus_hr_feeding_state;

  a2dp_lc3plus_hr_encoder_stats_t stats;

  struct {
    uint8_t data[4096];
    unsigned offset;
    unsigned nbytes;
    unsigned current_bitrate;
    unsigned frames;
    unsigned target_frames;
  } enc_buf;

#ifdef LC3PLUS_HR_SAVE_DUMP
  FILE *recFile;
  FILE *pcmFile;
#endif
} tA2DP_LC3PLUS_HR_ENCODER_CB;

static tA2DP_LC3PLUS_HR_ENCODER_CB a2dp_lc3plus_hr_encoder_cb;

static uint32_t a2dp_lc3plus_hr_block_size(void) {
  return a2dp_lc3plus_hr_encoder_cb.encoder->GetFrameSamples() *
         a2dp_lc3plus_hr_encoder_cb.feeding_params.channel_count *
         a2dp_lc3plus_hr_encoder_cb.feeding_params.bits_per_sample / 8;
}

static uint32_t a2dp_lc3plus_hr_frame_samples(void) {
  return a2dp_lc3plus_hr_encoder_cb.encoder->GetFrameSamples();
}

static uint32_t a2dp_lc3plus_hr_timestamp_increment(void) {
  return a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params.tsi;
}

static uint32_t a2dp_lc3plus_hr_frame_per_packet(void) {
    return A2DP_LC3PLUS_HR_ENCODER_INTERVAL_MS / a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params.frame_ms;
}

static uint32_t a2dp_lc3plus_hr_resolve_bitrate() {
  const uint32_t bitrate = a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params.bitrate;
  const uint32_t abr_bitrate = a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params.abr_bitrate;
  //LOG_INFO(LOG_TAG, "%s: bitrate: %" PRIu32 ", abr: %" PRIu32, __func__, bitrate, abr_bitrate);
  return bitrate == 0 ? abr_bitrate : bitrate;
}

static bool a2dp_lc3plus_hr_enc_buf_ready() {
  auto &buf = a2dp_lc3plus_hr_encoder_cb.enc_buf;
  return buf.frames == buf.target_frames;
}

static bool a2dp_lc3plus_hr_enc_buf_should_update() {
  return a2dp_lc3plus_hr_encoder_cb.enc_buf.frames == 0;
}

static void a2dp_lc3plus_hr_enc_buf_update() {
  auto &buf = a2dp_lc3plus_hr_encoder_cb.enc_buf;
  auto &encoder = *a2dp_lc3plus_hr_encoder_cb.encoder;
  auto &params = a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params;

  if (a2dp_lc3plus_hr_encoder_cb.encoder != nullptr) {
    unsigned current_bitrate = a2dp_lc3plus_hr_resolve_bitrate();
    if (current_bitrate == buf.current_bitrate) {
      return;
    }
    buf.current_bitrate = current_bitrate;
    unsigned channels = params.channel_count;
    buf.nbytes = encoder.GetFrameBytes(current_bitrate / channels);
    LOG_INFO(LOG_TAG, "%s: channels %u, nbytes %u", __func__, channels, buf.nbytes);
    unsigned frame_data_block = buf.nbytes * channels;
    if (a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize < frame_data_block) {
      LOG_INFO(LOG_TAG, "%s: fragmenting frame data block %u", __func__, frame_data_block);
      buf.target_frames = 1;
    } else {
      buf.target_frames = a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize / frame_data_block;
      unsigned limit_frames = A2DP_LC3PLUS_HR_ENCODER_INTERVAL_MS / params.frame_ms;
      if (buf.target_frames > limit_frames) {
        buf.target_frames = limit_frames;
      }
      LOG_INFO(LOG_TAG, "%s: target frames %u", __func__, buf.target_frames);
    }
  } else {
    buf.target_frames = 1;
    buf.nbytes = a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize / params.channel_count;
  }
}

static void a2dp_lc3plus_hr_enc_buf_reset() {
  auto &buf = a2dp_lc3plus_hr_encoder_cb.enc_buf;
  buf.offset = 0;
  buf.frames = 0;
  buf.target_frames = 0;
  buf.nbytes = 0;
  buf.current_bitrate = 0;
  a2dp_lc3plus_hr_enc_buf_update();
}

static int a2dp_lc3plus_hr_enc_buf_encode(void *pcm) {
  auto &buf = a2dp_lc3plus_hr_encoder_cb.enc_buf;
  auto &encoder = *a2dp_lc3plus_hr_encoder_cb.encoder;
  auto &params = a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params;

  uint8_t *out_ptr = buf.data + buf.offset;

#ifdef LC3PLUS_HR_SAVE_DUMP
  if (a2dp_lc3plus_hr_encoder_cb.pcmFile != NULL) {
      fwrite(pcm, sizeof(uint8_t), a2dp_lc3plus_hr_block_size(), a2dp_lc3plus_hr_encoder_cb.pcmFile);
  }
#endif

  int result = encoder.Encode(params.fmt, pcm, buf.nbytes, out_ptr);

  if (result == 0) {
#ifdef LC3PLUS_HR_SAVE_DUMP
    if (a2dp_lc3plus_hr_encoder_cb.recFile != NULL) {
      uint16_t size = buf.nbytes * params.channel_count;
      fwrite(&size, sizeof(size), 1, a2dp_lc3plus_hr_encoder_cb.recFile);
      fwrite(out_ptr, sizeof(uint8_t), size, a2dp_lc3plus_hr_encoder_cb.recFile);
    }
#endif

    buf.offset += buf.nbytes * params.channel_count;
    buf.frames++;
  }

  return result;
}

static uint32_t a2dp_lc3plus_hr_enc_buf_written() {
    return a2dp_lc3plus_hr_encoder_cb.enc_buf.offset;
}

static uint32_t a2dp_lc3plus_hr_enc_buf_frames() {
    return a2dp_lc3plus_hr_encoder_cb.enc_buf.frames;
}

static uint32_t a2dp_lc3plus_hr_enc_buf_target() {
    return a2dp_lc3plus_hr_encoder_cb.enc_buf.target_frames;
}

static void a2dp_lc3plus_hr_enc_buf_move_packet(uint8_t *dst) {
  auto &buf = a2dp_lc3plus_hr_encoder_cb.enc_buf;
  memcpy(dst, buf.data, buf.offset);
  buf.offset = 0;
  buf.frames = 0;
}

static void a2dp_vendor_lc3plus_hr_encoder_update(uint16_t peer_mtu,
                                            A2dpCodecConfig* a2dp_codec_config,
                                            bool* p_restart_input,
                                            bool* p_restart_output,
                                            bool* p_config_updated);
static void a2dp_lc3plus_hr_get_num_frame_iteration(uint8_t* num_of_iterations,
                                              uint8_t* num_of_frames,
                                              uint64_t timestamp_us);
static void a2dp_lc3plus_hr_encode_frames(uint8_t nb_frame);
static bool a2dp_lc3plus_hr_read_feeding(uint8_t* read_buffer, uint32_t* bytes_read);

bool A2DP_VendorLoadEncoderLC3plusHR(void) {
  LOG_WARN(LOG_TAG, "%s: Do nothing, LC3plus HR is statically linked", __func__);
  return true;
}

void A2DP_VendorUnloadEncoderLC3plusHR(void) {
  // Cleanup any LC3plus HR-related state
  LOG_WARN(LOG_TAG, "%s: Do nothing, LC3plus HR is statically linked", __func__);
}

void a2dp_vendor_lc3plus_hr_encoder_init(
    const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params,
    A2dpCodecConfig* a2dp_codec_config,
    a2dp_source_read_callback_t read_callback,
    a2dp_source_enqueue_callback_t enqueue_callback) {
  if (a2dp_lc3plus_hr_encoder_cb.has_lc3plus_hr_handle) {
      delete a2dp_lc3plus_hr_encoder_cb.encoder;
      a2dp_lc3plus_hr_encoder_cb.has_lc3plus_hr_handle = false;
  }
  memset(&a2dp_lc3plus_hr_encoder_cb, 0, sizeof(a2dp_lc3plus_hr_encoder_cb));

  a2dp_lc3plus_hr_encoder_cb.stats.session_start_us = time_get_os_boottime_us();

  a2dp_lc3plus_hr_encoder_cb.read_callback = read_callback;
  a2dp_lc3plus_hr_encoder_cb.enqueue_callback = enqueue_callback;
  a2dp_lc3plus_hr_encoder_cb.is_peer_edr = p_peer_params->is_peer_edr;
  a2dp_lc3plus_hr_encoder_cb.peer_supports_3mbps = p_peer_params->peer_supports_3mbps;
  a2dp_lc3plus_hr_encoder_cb.peer_mtu = p_peer_params->peer_mtu;
  a2dp_lc3plus_hr_encoder_cb.timestamp = 0;

  a2dp_lc3plus_hr_encoder_cb.use_SCMS_T = false;  // TODO: should be a parameter
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
  a2dp_lc3plus_hr_encoder_cb.use_SCMS_T = true;
#endif

  // NOTE: Ignore the restart_input / restart_output flags - this initization
  // happens when the connection is (re)started.
  bool restart_input = false;
  bool restart_output = false;
  bool config_updated = false;
  a2dp_vendor_lc3plus_hr_encoder_update(a2dp_lc3plus_hr_encoder_cb.peer_mtu,
                                  a2dp_codec_config, &restart_input,
                                  &restart_output, &config_updated);
}

bool A2dpCodecConfigLC3plusHR::updateEncoderUserConfig(
    const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params, bool* p_restart_input,
    bool* p_restart_output, bool* p_config_updated) {
  a2dp_lc3plus_hr_encoder_cb.is_peer_edr = p_peer_params->is_peer_edr;
  a2dp_lc3plus_hr_encoder_cb.peer_supports_3mbps = p_peer_params->peer_supports_3mbps;
  a2dp_lc3plus_hr_encoder_cb.peer_mtu = p_peer_params->peer_mtu;
  a2dp_lc3plus_hr_encoder_cb.timestamp = 0;

  if (a2dp_lc3plus_hr_encoder_cb.peer_mtu == 0) {
    LOG_ERROR(LOG_TAG,
              "%s: Cannot update the codec encoder for %s: "
              "invalid peer MTU",
              __func__, name().c_str());
    return false;
  }

  a2dp_vendor_lc3plus_hr_encoder_update(a2dp_lc3plus_hr_encoder_cb.peer_mtu, this,
                                  p_restart_input, p_restart_output,
                                  p_config_updated);
  return true;
}

// Update the A2DP LC3plus HR encoder.
// |peer_mtu| is the peer MTU.
// |a2dp_codec_config| is the A2DP codec to use for the update.
static void a2dp_vendor_lc3plus_hr_encoder_update(uint16_t peer_mtu,
                                            A2dpCodecConfig* a2dp_codec_config,
                                            bool* p_restart_input,
                                            bool* p_restart_output,
                                            bool* p_config_updated) {
  tA2DP_LC3PLUS_HR_ENCODER_PARAMS* p_encoder_params =
      &a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params;
  uint8_t codec_info[AVDT_CODEC_SIZE];

  *p_restart_input = false;
  *p_restart_output = false;
  *p_config_updated = false;

  if (!a2dp_codec_config->copyOutOtaCodecConfig(codec_info)) {
    LOG_ERROR(LOG_TAG,
              "%s: Cannot update the codec encoder for %s: "
              "invalid codec config",
              __func__, a2dp_codec_config->name().c_str());
    return;
  }
  const uint8_t* p_codec_info = codec_info;
  btav_a2dp_codec_config_t codec_config = a2dp_codec_config->getCodecConfig();

  // The feeding parameters
  tA2DP_FEEDING_PARAMS* p_feeding_params = &a2dp_lc3plus_hr_encoder_cb.feeding_params;
  p_feeding_params->sample_rate =
      A2DP_VendorGetTrackSampleRateLC3plusHR(p_codec_info);
  p_feeding_params->bits_per_sample =
      a2dp_codec_config->getAudioBitsPerSample();
  p_feeding_params->channel_count =
      A2DP_VendorGetTrackChannelCountLC3plusHR(p_codec_info);
  LOG_DEBUG(LOG_TAG, "%s: sample_rate=%u bits_per_sample=%u channel_count=%u",
            __func__, p_feeding_params->sample_rate,
            p_feeding_params->bits_per_sample, p_feeding_params->channel_count);

  // The codec parameters

  float old_frame_ms = p_encoder_params->frame_ms;
  uint32_t old_sample_rate = p_encoder_params->sample_rate;

  p_encoder_params->sample_rate =
      a2dp_lc3plus_hr_encoder_cb.feeding_params.sample_rate;
  p_encoder_params->channel_count =
      A2DP_VendorGetTrackChannelCountLC3plusHR(p_codec_info);
  p_encoder_params->frame_ms =
      A2DP_VendorGetFrameMsLC3plusHR(p_codec_info);
  p_encoder_params->bitrate =
      A2DP_VendorGetBitRateLC3plusHR(p_codec_info);
  p_encoder_params->tsi = p_encoder_params->frame_ms * 96;

  LOG_INFO(LOG_TAG, "%s: bitrate: %d", __func__, p_encoder_params->bitrate);

  uint16_t mtu_size =
      BT_DEFAULT_BUFFER_SIZE - A2DP_LC3PLUS_HR_OFFSET - sizeof(BT_HDR);

#if 0
  if (mtu_size < peer_mtu) {
    a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize = mtu_size;
  } else {
    a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize = peer_mtu;
  }
#else
  a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize = peer_mtu;
#endif

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
  a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize--;
#endif

  p_encoder_params->bits_per_sample =
      a2dp_lc3plus_hr_encoder_cb.feeding_params.bits_per_sample;

  switch (p_encoder_params->bits_per_sample) {
      case 16: p_encoder_params->fmt = lc3::PcmFormat::kS16; break;
      case 24: p_encoder_params->fmt = lc3::PcmFormat::kS24In3Le; break;
      case 32: p_encoder_params->fmt = lc3::PcmFormat::kS32; break;
  }

  if (p_encoder_params->frame_ms != old_frame_ms || p_encoder_params->sample_rate != old_sample_rate) {
    *p_config_updated = true;
    *p_restart_output = true;
    LOG_DEBUG(LOG_TAG, "%s: LC3plus HR config updated, recreating the encoder...", __func__);
    if (a2dp_lc3plus_hr_encoder_cb.has_lc3plus_hr_handle) {
      delete a2dp_lc3plus_hr_encoder_cb.encoder;
      a2dp_lc3plus_hr_encoder_cb.has_lc3plus_hr_handle = true;
    }
    a2dp_lc3plus_hr_enc_buf_reset();
    a2dp_lc3plus_hr_encoder_cb.encoder = new lc3::Encoder(p_encoder_params->frame_ms*1000, p_encoder_params->sample_rate, 0, p_encoder_params->channel_count, true);
    if (a2dp_lc3plus_hr_encoder_cb.encoder == nullptr) {
        LOG_ERROR(LOG_TAG, "%s: Cannot get LC3plus HR encoder handle", __func__);
        return;  // TODO: Return an error?
    }
  }

  LOG_DEBUG(LOG_TAG, "%s: MTU=%d, peer_mtu=%d", __func__,
            a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize, peer_mtu);
  LOG_DEBUG(LOG_TAG,
            "%s: sample_rate: %d channel_count: %d "
            "bits_per_sample: %d ",
            "frame_dms: %d ",
            "pcm_fmt: %d ",
            "bitrate: %d",
            __func__, p_encoder_params->sample_rate,
            p_encoder_params->channel_count,
            p_encoder_params->bits_per_sample,
            (int) (p_encoder_params->frame_ms * 10),
            p_encoder_params->fmt,
            p_encoder_params->bitrate);

#ifdef LC3PLUS_HR_SAVE_DUMP
  if (a2dp_lc3plus_hr_encoder_cb.recFile == NULL) {
    a2dp_lc3plus_hr_encoder_cb.recFile = fopen(ENC_RAW_NAME, "wb");
    LOG_DEBUG(LOG_TAG, "%s: create recFile = %p", __func__, a2dp_lc3plus_hr_encoder_cb.recFile);
  }
  if (a2dp_lc3plus_hr_encoder_cb.recFile != NULL) {
    struct lc3bin_header {
      uint16_t file_id;
      uint16_t header_size;
      uint16_t srate_100hz;
      uint16_t bitrate_100bps;
      uint16_t channels;
      uint16_t frame_10us;
      uint16_t rfu;
      uint16_t nsamples_low;
      uint16_t nsamples_high;
      uint16_t hrmode;
    } hdr = {
      .file_id = (0x1C | (0xCC << 8)),
      .header_size = sizeof(hdr),
      .srate_100hz = (uint16_t) (p_encoder_params->sample_rate / 100),
      .bitrate_100bps = (uint16_t) (p_encoder_params->bitrate / 100),
      .channels = (uint16_t) (p_encoder_params->channel_count),
      .frame_10us = (uint16_t) (p_encoder_params->frame_ms*100),
      .nsamples_low = 0,
      .nsamples_high = 0,
      .hrmode = true,
    };
    fwrite(&hdr, sizeof(hdr), 1, a2dp_lc3plus_hr_encoder_cb.recFile);
  }
  if (a2dp_lc3plus_hr_encoder_cb.pcmFile == NULL) {
    a2dp_lc3plus_hr_encoder_cb.pcmFile = fopen(ENC_PCM_NAME,"wb");
    LOG_DEBUG(LOG_TAG, "%s: create pcmFile = %p", __func__, a2dp_lc3plus_hr_encoder_cb.pcmFile);
  }
#endif
}

void a2dp_vendor_lc3plus_hr_encoder_cleanup(void) {
  if (a2dp_lc3plus_hr_encoder_cb.has_lc3plus_hr_handle) {
    delete a2dp_lc3plus_hr_encoder_cb.encoder;
  }

#ifdef LC3PLUS_HR_SAVE_DUMP
  if (a2dp_lc3plus_hr_encoder_cb.recFile != NULL) {
    fclose(a2dp_lc3plus_hr_encoder_cb.recFile);
    a2dp_lc3plus_hr_encoder_cb.recFile = NULL;
    remove(ENC_RAW_NAME);
  }
  if (a2dp_lc3plus_hr_encoder_cb.pcmFile != NULL) {
    fclose(a2dp_lc3plus_hr_encoder_cb.pcmFile);
    a2dp_lc3plus_hr_encoder_cb.pcmFile = NULL;
    remove(ENC_PCM_NAME);
  }
#endif

  memset(&a2dp_lc3plus_hr_encoder_cb, 0, sizeof(a2dp_lc3plus_hr_encoder_cb));
}

void a2dp_vendor_lc3plus_hr_feeding_reset(void) {
  /* By default, just clear the entire state */
  memset(&a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state, 0,
         sizeof(a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state));

  a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.bytes_per_tick =
      (a2dp_lc3plus_hr_encoder_cb.feeding_params.sample_rate *
       a2dp_lc3plus_hr_encoder_cb.feeding_params.bits_per_sample / 8 *
       a2dp_lc3plus_hr_encoder_cb.feeding_params.channel_count *
       A2DP_LC3PLUS_HR_ENCODER_INTERVAL_MS) /
      1000;

  LOG_DEBUG(LOG_TAG, "%s: PCM bytes per tick %u", __func__,
            a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.bytes_per_tick);
}

void a2dp_vendor_lc3plus_hr_feeding_flush(void) {
  a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.counter = 0.0f;
}

period_ms_t a2dp_vendor_lc3plus_hr_get_encoder_interval_ms(void) {
  return A2DP_LC3PLUS_HR_ENCODER_INTERVAL_MS;
}

void a2dp_vendor_lc3plus_hr_send_frames(uint64_t timestamp_us) {
  uint8_t nb_frame = 0;
  uint8_t nb_iterations = 0;

  a2dp_lc3plus_hr_get_num_frame_iteration(&nb_iterations, &nb_frame, timestamp_us);
  LOG_DEBUG(LOG_TAG, "%s: Sending %d frames per iteration, %d iterations",
              __func__, nb_frame, nb_iterations);
  if (nb_frame == 0) return;

  for (uint8_t counter = 0; counter < nb_iterations; counter++) {
    // Transcode frame and enqueue
    a2dp_lc3plus_hr_encode_frames(nb_frame);
  }
}

// Obtains the number of frames to send and number of iterations
// to be used. |num_of_iterations| and |num_of_frames| parameters
// are used as output param for returning the respective values.
static void a2dp_lc3plus_hr_get_num_frame_iteration(uint8_t* num_of_iterations,
                                              uint8_t* num_of_frames,
                                              uint64_t timestamp_us) {
  uint32_t result = 0;
  uint8_t nof = 0;
  uint8_t noi = 1;

  uint32_t pcm_bytes_per_frame = a2dp_lc3plus_hr_block_size();
  LOG_DEBUG(LOG_TAG, "%s: pcm_bytes_per_frame %u", __func__,
              pcm_bytes_per_frame);

  uint32_t us_this_tick = A2DP_LC3PLUS_HR_ENCODER_INTERVAL_MS * 1000;

  uint64_t now_us = timestamp_us;
  if (a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.last_frame_us != 0)
    us_this_tick =
        (now_us - a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.last_frame_us);
  a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.last_frame_us = now_us;

  a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.counter +=
      (float)a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.bytes_per_tick * us_this_tick /
      (A2DP_LC3PLUS_HR_ENCODER_INTERVAL_MS * 1000);

  result =
      a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.counter / pcm_bytes_per_frame;
  a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.counter -=
      result * pcm_bytes_per_frame;

  nof = result;
  //noi = result;

  LOG_DEBUG(LOG_TAG, "%s: effective num of frames %u, iterations %u",
              __func__, nof, noi);

  *num_of_frames = nof;
  *num_of_iterations = noi;
}

static void a2dp_lc3plus_hr_encode_frames(uint8_t nb_frame) {
  tA2DP_LC3PLUS_HR_ENCODER_PARAMS* p_encoder_params =
      &a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params;
  uint8_t remain_nb_frame = nb_frame;
  uint8_t read_buffer[1920 * sizeof(int32_t) * 2 /* ch */];

  uint32_t count;
  int32_t out_frames = 0;
  int written = 0;

  uint32_t bytes_read = 0;
  while (nb_frame) {
#define LC3PLUS_HR_BUFFER_SIZE BT_DEFAULT_BUFFER_SIZE
    BT_HDR* p_buf = (BT_HDR*)osi_malloc(LC3PLUS_HR_BUFFER_SIZE);
    p_buf->offset = A2DP_LC3PLUS_HR_OFFSET;
    p_buf->len = 0;
    p_buf->layer_specific = 0;
    a2dp_lc3plus_hr_encoder_cb.stats.media_read_total_expected_packets++;
    //LOG_DEBUG(LOG_TAG, "%s: starting encoding loop, nb_frame: %d", __func__, nb_frame);

    count = 0;
    do {
      //
      // Read the PCM data and encode it
      //
      uint32_t temp_bytes_read = 0;

      if (a2dp_lc3plus_hr_read_feeding(read_buffer, &temp_bytes_read)) {
        bytes_read += temp_bytes_read;
        uint8_t* packet = (uint8_t*)(p_buf + 1) + p_buf->offset + p_buf->len;
        if (a2dp_lc3plus_hr_encoder_cb.encoder == nullptr) {
          LOG_ERROR(LOG_TAG, "%s: invalid LC3plus HR handle", __func__);
          a2dp_lc3plus_hr_encoder_cb.stats.media_read_total_dropped_packets++;
          osi_free(p_buf);
          return;
        }
        written = 0;
        out_frames = 0;

        if (a2dp_lc3plus_hr_enc_buf_should_update()) {
          a2dp_lc3plus_hr_enc_buf_update();
        }
        int result = a2dp_lc3plus_hr_enc_buf_encode((void *) read_buffer);
        if (result != 0) {
          LOG_ERROR(LOG_TAG, "%s: LC3plus HR encoding error: %d", __func__, result);
          a2dp_lc3plus_hr_encoder_cb.stats.media_read_total_dropped_packets++;
          osi_free(p_buf);
          return;
        } else {
            LOG_DEBUG(LOG_TAG, "%s: LC3plus HR encoding OK", __func__);
        }

        if (a2dp_lc3plus_hr_enc_buf_ready() /*|| nb_frame == 1*/) {
          written = a2dp_lc3plus_hr_enc_buf_written();
          out_frames = a2dp_lc3plus_hr_enc_buf_frames();
          const unsigned target = a2dp_lc3plus_hr_encoder_cb.enc_buf.target_frames;
          LOG_INFO(LOG_TAG, "%s: LC3plus HR encoded full packet: written %u, out_frames/target %u/%u!", __func__, written, out_frames, target);
          uint8_t *packet = (uint8_t*)(p_buf + 1) + p_buf->offset + p_buf->len;
          a2dp_lc3plus_hr_enc_buf_move_packet(packet);
        } else {
          const int space = a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize - a2dp_lc3plus_hr_enc_buf_written();
          const int frames = a2dp_lc3plus_hr_encoder_cb.enc_buf.frames;
          const int target = a2dp_lc3plus_hr_encoder_cb.enc_buf.target_frames;
          LOG_INFO(LOG_TAG, "%s: LC3plus HR packet left space: %d, frames/target %d/%d", __func__, space, frames, target);
        }

        count += written;
        p_buf->len += written;
        nb_frame--;
        p_buf->layer_specific += out_frames;  // added a frame to the buffer
      } else {
        LOG_WARN(LOG_TAG, "%s: underflow %d", __func__, nb_frame);
        a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_feeding_state.counter +=
            nb_frame * a2dp_lc3plus_hr_block_size();
        // no more pcm to read
        nb_frame = 0;
      }
    } while ((written == 0) && nb_frame);

    if (p_buf->len) {
      /*
       * Timestamp of the media packet header represent the TS of the
       * first frame, i.e the timestamp before including this frame.
       */
      *((uint32_t*)(p_buf + 1)) = a2dp_lc3plus_hr_encoder_cb.timestamp;

      //LOG_INFO(LOG_TAG, "%s: LC3plus HR frame samples: %d, tsi %d", __func__, a2dp_lc3plus_hr_frame_samples(), a2dp_lc3plus_hr_timestamp_increment());


      a2dp_lc3plus_hr_encoder_cb.timestamp += p_buf->layer_specific * a2dp_lc3plus_hr_timestamp_increment();

      uint8_t done_nb_frame = remain_nb_frame - nb_frame;
      remain_nb_frame = nb_frame;
      if (!a2dp_lc3plus_hr_encoder_cb.enqueue_callback(p_buf, done_nb_frame,
                                                 bytes_read))
        return;
    } else {
      // NOTE: Unlike the execution path for other codecs, it is normal for
      // LC3plus HR to NOT write encoded data to the last buffer if there wasn't
      // enough data to write to. That data is accumulated internally by
      // the codec and included in the next iteration. Therefore, here we
      // don't increment the "media_read_total_dropped_packets" counter.
      osi_free(p_buf);
    }
  }
}

static bool a2dp_lc3plus_hr_read_feeding(uint8_t* read_buffer, uint32_t* bytes_read) {
  uint32_t read_size = a2dp_lc3plus_hr_block_size();

  a2dp_lc3plus_hr_encoder_cb.stats.media_read_total_expected_reads_count++;
  a2dp_lc3plus_hr_encoder_cb.stats.media_read_total_expected_read_bytes += read_size;

  /* Read Data from UIPC channel */
  uint32_t nb_byte_read =
      a2dp_lc3plus_hr_encoder_cb.read_callback(read_buffer, read_size);
  a2dp_lc3plus_hr_encoder_cb.stats.media_read_total_actual_read_bytes += nb_byte_read;

  if (nb_byte_read < read_size) {
    if (nb_byte_read == 0) return false;

    /* Fill the unfilled part of the read buffer with silence (0) */
    LOG_INFO(LOG_TAG, "%s: filling %zu pcm bytes with 0", __func__, read_size - nb_byte_read);
    memset(((uint8_t*)read_buffer) + nb_byte_read, 0, read_size - nb_byte_read);
    nb_byte_read = read_size;
  }
  a2dp_lc3plus_hr_encoder_cb.stats.media_read_total_actual_reads_count++;
  *bytes_read = nb_byte_read;
  return true;
}

// ABR Processing

void a2dp_vendor_lc3plus_hr_set_transmit_queue_length(size_t transmit_queue_length) {
  a2dp_lc3plus_hr_encoder_cb.TxQueueLength = transmit_queue_length;
  tA2DP_LC3PLUS_HR_ENCODER_PARAMS* p_encoder_params =
      &a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params;
  if (p_encoder_params->bitrate == 0) {
      // TODO: Implement ABR
      p_encoder_params->abr_bitrate = 396800;
  }
}

period_ms_t A2dpCodecConfigLC3plusHR::encoderIntervalMs() const {
  return a2dp_vendor_lc3plus_hr_get_encoder_interval_ms();
}

void A2dpCodecConfigLC3plusHR::debug_codec_dump(int fd) {
  a2dp_lc3plus_hr_encoder_stats_t* stats = &a2dp_lc3plus_hr_encoder_cb.stats;
  tA2DP_LC3PLUS_HR_ENCODER_PARAMS* p_encoder_params =
      &a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params;

  A2dpCodecConfig::debug_codec_dump(fd);

  dprintf(fd,
          "  Packet counts (expected/dropped)                        : %zu / "
          "%zu\n",
          stats->media_read_total_expected_packets,
          stats->media_read_total_dropped_packets);

  dprintf(fd,
          "  PCM read counts (expected/actual)                       : %zu / "
          "%zu\n",
          stats->media_read_total_expected_reads_count,
          stats->media_read_total_actual_reads_count);

  dprintf(fd,
          "  PCM read bytes (expected/actual)                        : %zu / "
          "%zu\n",
          stats->media_read_total_expected_read_bytes,
          stats->media_read_total_actual_read_bytes);

  dprintf(fd,
          "  LC3plus HR saved transmit queue length                        : %zu\n",
          a2dp_lc3plus_hr_encoder_cb.TxQueueLength);
}
