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
  bool has_lc3plus_hr_handle;  // True if lc3plus_hr_handle is valid
  bool already_init;
  bool mix_channels;

  tA2DP_FEEDING_PARAMS feeding_params;
  tA2DP_LC3PLUS_HR_ENCODER_PARAMS lc3plus_hr_encoder_params;
  tA2DP_LC3PLUS_HR_FEEDING_STATE lc3plus_hr_feeding_state;

  a2dp_lc3plus_hr_encoder_stats_t stats;

  uint8_t *pbuf;
  uint32_t written;
  uint32_t samples;
  uint32_t out_frames;

#ifdef LC3PLUS_HR_SAVE_DUMP
  FILE *recFile;
  FILE *pcmFile;
#endif
} tA2DP_LC3PLUS_HR_ENCODER_CB;

static tA2DP_LC3PLUS_HR_ENCODER_CB a2dp_lc3plus_hr_encoder_cb;

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

  if (a2dp_lc3plus_hr_encoder_cb.already_init) return;

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

  p_encoder_params->sample_rate =
      a2dp_lc3plus_hr_encoder_cb.feeding_params.sample_rate;
  p_encoder_params->channel_count =
      A2DP_VendorGetTrackChannelCountLC3plusHR(p_codec_info);
  p_encoder_params->frame_ms =
      A2DP_VendorGetFrameMsLC3plusHR(p_codec_info);
  p_encoder_params->bitrate =
      A2DP_VendorGetBitRateLC3plusHR(p_codec_info);

  uint16_t mtu_size =
      BT_DEFAULT_BUFFER_SIZE - A2DP_LC3PLUS_HR_OFFSET - sizeof(BT_HDR);

  if (!a2dp_lc3plus_hr_encoder_cb.has_lc3plus_hr_handle) {//Encoder enc(dt_us, sr_hz, sr_pcm_hz, nchannels);
    a2dp_lc3plus_hr_encoder_cb.encoder = new lc3::Encoder(p_encoder_params->frame_ms*1000, p_encoder_params->sample_rate, 0, p_encoder_params->channel_count, true);
    if (a2dp_lc3plus_hr_encoder_cb.encoder == nullptr) {
      LOG_ERROR(LOG_TAG, "%s: Cannot get LC3plus HR encoder handle", __func__);
      return;  // TODO: Return an error?
    }
    a2dp_lc3plus_hr_encoder_cb.has_lc3plus_hr_handle = true;
    a2dp_lc3plus_hr_encoder_cb.already_init = true;
  }

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

  if (p_encoder_params->frame_ms != old_frame_ms) {
    *p_config_updated = true;
    *p_restart_output = true;
  }

  LOG_DEBUG(LOG_TAG, "%s: MTU=%d, peer_mtu=%d", __func__,
            a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize, peer_mtu);
  LOG_DEBUG(LOG_TAG,
            "%s: sample_rate: %d channel_count: %d "
            "bits_per_sample: %d ",
            "frame_ms: %f ",
            "pcm_fmt: %d ",
            "bitrate: %d",
            __func__, p_encoder_params->sample_rate,
            p_encoder_params->channel_count,
            p_encoder_params->bits_per_sample,
            p_encoder_params->frame_ms,
            p_encoder_params->fmt,
            p_encoder_params->bitrate);

#ifdef LC3PLUS_HR_SAVE_DUMP
  if (a2dp_lc3plus_hr_encoder_cb.recFile == NULL) {
    a2dp_lc3plus_hr_encoder_cb.recFile = fopen(ENC_RAW_NAME,"wb");
    LOG_DEBUG(LOG_TAG, "%s: create recFile = %p", __func__, a2dp_lc3plus_hr_encoder_cb.recFile);
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

static uint32_t a2dp_lc3plus_hr_block_size(void) {
  return a2dp_lc3plus_hr_encoder_cb.encoder->GetFrameSamples() *
         a2dp_lc3plus_hr_encoder_cb.feeding_params.channel_count *
         a2dp_lc3plus_hr_encoder_cb.feeding_params.bits_per_sample / 8;
}

static uint32_t a2dp_lc3plus_hr_frame_samples(void) {
  return a2dp_lc3plus_hr_encoder_cb.encoder->GetFrameSamples();
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
  nof = result < 15 ? result : 15;
  //noi = result;

  LOG_DEBUG(LOG_TAG, "%s: effective num of frames %u, iterations %u",
              __func__, nof, noi);

  *num_of_frames = nof;
  *num_of_iterations = noi;
}

static uint32_t a2dp_lc3plus_hr_resolve_bitrate() {
    const uint32_t bitrate = a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params.bitrate;
    const uint32_t abr_bitrate = a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params.abr_bitrate;
    return bitrate == 0 ? abr_bitrate : bitrate;
}

static void a2dp_lc3plus_hr_encode_frames(uint8_t nb_frame) {
  tA2DP_LC3PLUS_HR_ENCODER_PARAMS* p_encoder_params =
      &a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params;
  uint8_t remain_nb_frame = nb_frame;
  uint8_t read_buffer[1920 * sizeof(int32_t) * 2 /* ch */];

  uint8_t write_buffer[2048];
  uint8_t *out_ptr = write_buffer;
  int lc3plus_frames = 0;
  int nbytes = a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize;

  if (a2dp_lc3plus_hr_encoder_cb.encoder != nullptr) {
      uint32_t current_bitrate = a2dp_lc3plus_hr_resolve_bitrate() / p_encoder_params->channel_count;
      nbytes = a2dp_lc3plus_hr_encoder_cb.encoder->GetFrameBytes(current_bitrate);
  }

  uint32_t count;
  int32_t encode_count = 0;
  int32_t out_frames = 0;
  int written = 0;

  uint32_t bytes_read = 0;
  while (nb_frame) {
#define LC3PLUS_HR_BUFFER_SIZE 16*BT_DEFAULT_BUFFER_SIZE
    BT_HDR* p_buf = (BT_HDR*)osi_malloc(LC3PLUS_HR_BUFFER_SIZE);
    p_buf->offset = A2DP_LC3PLUS_HR_OFFSET;
    p_buf->len = 0;
    p_buf->layer_specific = 0;
    lc3plus_frames = 0;
    out_ptr = write_buffer;
    a2dp_lc3plus_hr_encoder_cb.stats.media_read_total_expected_packets++;

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

#ifdef LC3PLUS_HR_SAVE_DUMP
        if (a2dp_lc3plus_hr_encoder_cb.pcmFile != NULL) {
          fwrite(read_buffer, sizeof(uint8_t), temp_bytes_read, a2dp_lc3plus_hr_encoder_cb.pcmFile);
        }
#endif
        int result = a2dp_lc3plus_hr_encoder_cb.encoder->Encode(p_encoder_params->fmt, (void *) read_buffer, nbytes, out_ptr);
        if (result == 0) {
          out_ptr += nbytes * p_encoder_params->channel_count;
          lc3plus_frames++;
          LOG_INFO(LOG_TAG, "%s: LC3plus HR encoding OK, written %d, out_frames %d!", __func__, nbytes * lc3plus_frames * p_encoder_params->channel_count, lc3plus_frames);
        } else {
          LOG_ERROR(LOG_TAG,
                    "%s: LC3plus HR encoding error: %d, dropping %d encoded bytes",
                    __func__, result, nbytes * lc3plus_frames);
          a2dp_lc3plus_hr_encoder_cb.stats.media_read_total_dropped_packets++;
          osi_free(p_buf);
          return;
        }

        if (nbytes * p_encoder_params->channel_count * (lc3plus_frames + 1) >= a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize || nb_frame == 1) {
            LOG_INFO(LOG_TAG, "%s: LC3plus HR encoded full packet: written %d, out_frames %d!", __func__, nbytes * lc3plus_frames * p_encoder_params->channel_count, lc3plus_frames);
            written = nbytes * lc3plus_frames * p_encoder_params->channel_count;
            out_frames = lc3plus_frames;
            uint8_t* packet = (uint8_t*)(p_buf + 1) + p_buf->offset + p_buf->len;
            out_ptr = write_buffer;
            lc3plus_frames = 0;
            nb_frame = 0;
            memcpy(packet, write_buffer, written);
        } else {
            LOG_INFO(LOG_TAG, "%s: LC3plus HR packet left space: %d!", __func__, a2dp_lc3plus_hr_encoder_cb.TxAaMtuSize - nbytes * lc3plus_frames * p_encoder_params->channel_count);
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

      LOG_INFO(LOG_TAG, "%s: LC3plus HR frame samples: %d", __func__, a2dp_lc3plus_hr_frame_samples());


      a2dp_lc3plus_hr_encoder_cb.timestamp += p_buf->layer_specific * a2dp_lc3plus_hr_frame_samples();

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
    memset(((uint8_t*)read_buffer) + nb_byte_read, 0, read_size - nb_byte_read);
    nb_byte_read = read_size;
  }
  a2dp_lc3plus_hr_encoder_cb.stats.media_read_total_actual_reads_count++;
  *bytes_read = nb_byte_read;
  return true;
}

// ABR Processing
// TODO: Implement ABR

void a2dp_vendor_lc3plus_hr_set_transmit_queue_length(size_t transmit_queue_length) {
  a2dp_lc3plus_hr_encoder_cb.TxQueueLength = transmit_queue_length;
  tA2DP_LC3PLUS_HR_ENCODER_PARAMS* p_encoder_params =
      &a2dp_lc3plus_hr_encoder_cb.lc3plus_hr_encoder_params;
  if (p_encoder_params->bitrate == 0) {
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
