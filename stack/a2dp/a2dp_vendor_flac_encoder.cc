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

#define LOG_TAG "a2dp_vendor_flac_encoder"
#define ATRACE_TAG ATRACE_TAG_AUDIO

#include "a2dp_vendor_flac_encoder.h"

#ifndef OS_GENERIC
#include <cutils/trace.h>
#endif
#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <FLAC/stream_encoder.h>

#include "a2dp_vendor.h"
#include "a2dp_vendor_flac.h"
#include "bt_common.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

//
// Encoder for FLAC Source Codec
//

// A2DP FLAC encoder interval in milliseconds
#define A2DP_FLAC_ENCODER_INTERVAL_MS 20
//#define A2DP_FLAC_MEDIA_BYTES_PER_FRAME 128


//#define DEBUG
#ifdef DEBUG
#define FLAC_SAVE_DUMP
#endif
#ifdef FLAC_SAVE_DUMP
#define ENC_RAW_NAME "/sdcard/Download/a2dp_flac.flac"
#define ENC_PCM_NAME "/sdcard/Download/a2dp_flac.pcm"
#endif

// offset
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
#define A2DP_FLAC_OFFSET (AVDT_MEDIA_OFFSET + A2DP_FLAC_MPL_HDR_LEN + 1)
#else
#define A2DP_FLAC_OFFSET (AVDT_MEDIA_OFFSET + A2DP_FLAC_MPL_HDR_LEN)
#endif

typedef struct {
  uint32_t sample_rate;
  uint8_t channel_count;
  uint8_t bits_per_sample;
  int block_size;
  int pcm_bits_per_sample;
} tA2DP_FLAC_ENCODER_PARAMS;

typedef struct {
  float counter;
  uint32_t bytes_per_tick; /* pcm bytes read each media task tick */
  uint64_t last_frame_us;
} tA2DP_FLAC_FEEDING_STATE;

typedef struct {
  uint64_t session_start_us;

  size_t media_read_total_expected_packets;
  size_t media_read_total_expected_reads_count;
  size_t media_read_total_expected_read_bytes;

  size_t media_read_total_dropped_packets;
  size_t media_read_total_actual_reads_count;
  size_t media_read_total_actual_read_bytes;
} a2dp_flac_encoder_stats_t;

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

  FLAC__StreamEncoder *flac_handle;
  bool has_flac_handle;  // True if flac_handle is valid
  bool already_init;
  bool mix_channels;

  tA2DP_FEEDING_PARAMS feeding_params;
  tA2DP_FLAC_ENCODER_PARAMS flac_encoder_params;
  tA2DP_FLAC_FEEDING_STATE flac_feeding_state;

  a2dp_flac_encoder_stats_t stats;

  uint8_t *pbuf;
  uint32_t written;
  uint32_t samples;
  uint32_t out_frames;

#ifdef FLAC_SAVE_DUMP
  FILE *recFile;
  FILE *pcmFile;
#endif
} tA2DP_FLAC_ENCODER_CB;

static tA2DP_FLAC_ENCODER_CB a2dp_flac_encoder_cb;

static void a2dp_vendor_flac_encoder_update(uint16_t peer_mtu,
                                            A2dpCodecConfig* a2dp_codec_config,
                                            bool* p_restart_input,
                                            bool* p_restart_output,
                                            bool* p_config_updated);
static void a2dp_flac_get_num_frame_iteration(uint8_t* num_of_iterations,
                                              uint8_t* num_of_frames,
                                              uint64_t timestamp_us);
static void a2dp_flac_encode_frames(uint8_t nb_frame);
static bool a2dp_flac_read_feeding(uint8_t* read_buffer, uint32_t* bytes_read);

bool A2DP_VendorLoadEncoderFlac(void) {
  LOG_WARN(LOG_TAG, "%s: Do nothing, FLAC is statically linked", __func__);
  return true;
}

void A2DP_VendorUnloadEncoderFlac(void) {
  // Cleanup any FLAC-related state
  LOG_WARN(LOG_TAG, "%s: Do nothing, FLAC is statically linked", __func__);
}

typedef struct {
    uint16_t sync;
    uint8_t reserved1;
    uint8_t blocking;

    uint16_t block_size;
    uint32_t sample_rate;

    uint8_t channel_assignment;
    uint8_t sample_size;
    uint8_t reserved2;
    uint64_t coded_number;
} flac_header_t;

static uint64_t read_utf8_coded_number(const uint8_t *utf8, size_t *idx)
{
    uint64_t result;
    int byteCount;
    int i;

    if ((utf8[0] & 0x80) == 0) {
        *idx = 1;
        return utf8[0];
    }

    /*byteCount = 1;*/
    if ((utf8[0] & 0xE0) == 0xC0) {
        byteCount = 2;
    } else if ((utf8[0] & 0xF0) == 0xE0) {
        byteCount = 3;
    } else if ((utf8[0] & 0xF8) == 0xF0) {
        byteCount = 4;
    } else if ((utf8[0] & 0xFC) == 0xF8) {
        byteCount = 5;
    } else if ((utf8[0] & 0xFE) == 0xFC) {
        byteCount = 6;
    } else if ((utf8[0] & 0xFF) == 0xFE) {
        byteCount = 7;
    } else {
        return 0;
    }

    result = (uint64_t)(utf8[0] & (0xFF >> (byteCount + 1)));
    for (i = 1; i < byteCount; ++i) {
        result = (result << 6) | (utf8[i] & 0x3F);
    }
    *idx = byteCount;
    return result;
}


static flac_header_t decode_header(const uint8_t *buffer) {
    const uint32_t sampleRateTable[16]  = {0, 88200, 176400, 192000, 8000, 16000, 22050, 24000, 32000, 44100, 48000, 96000, 0, 0, 0, 0};
    const uint16_t blockSizeTable[16] = {0, 192, 576, 1152, 2304, 4608, 6, 7, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768};
    const uint8_t bitsPerSampleTable[8] = {0, 8, 12, 0, 16, 20, 24, 0};
    size_t idx;

    flac_header_t hdr = {
        .sync = (uint16_t) ((buffer[0] << 8) | (buffer[1] >> 2)),
        .reserved1 = (uint8_t) (buffer[1] & 1),
        .blocking = (uint8_t) ((buffer[1] >> 1) & 1),

        .block_size = blockSizeTable[buffer[2] >> 4],
        .sample_rate = sampleRateTable[buffer[2] & 0xf],

        .channel_assignment = (uint8_t) (buffer[3] >> 4),
        .sample_size  = bitsPerSampleTable[(buffer[3] >> 1) & 0x7],
        .reserved2 = (uint8_t) (buffer[3] & 1),
        .coded_number = read_utf8_coded_number(&buffer[4], &idx),
    };

    idx += 4;

    if (hdr.block_size == 6) {
        hdr.block_size = buffer[idx];
        hdr.block_size++;
    } else if (hdr.block_size == 7) {
        hdr.block_size = buffer[idx + 1] | (buffer[idx] << 8);
        hdr.block_size++;
    }

    return hdr;
}
#ifdef DEBUG
const char *chs[] = {
    [0b0000] = "mono",
    [0b0001] = "ster",
    [0b0010] = "xxxx",
    [0b0011] = "xxxx",
    [0b0100] = "xxxx",
    [0b0101] = "xxxx",
    [0b0110] = "xxxx",
    [0b0111] = "xxxx",
    [0b1000] = "lsid",
    [0b1001] = "rsid",
    [0b1010] = "msid",
    [0b1011] = "xxxx",
    [0b1100] = "xxxx",
    [0b1101] = "xxxx",
    [0b1110] = "xxxx",
    [0b1111] = "xxxx",
};
#endif

FLAC__StreamEncoderWriteStatus flac_stream_encoder_write_callback(const FLAC__StreamEncoder *encoder, const FLAC__byte buffer[], size_t bytes, uint32_t samples, uint32_t current_frame, void *client_data) {
  LOG_DEBUG(LOG_TAG, "%s: FLAC encoded buffer, bytes %lu, samples %u, current_frame %u", __func__, bytes, samples, current_frame);
  tA2DP_FLAC_ENCODER_CB *cb = (tA2DP_FLAC_ENCODER_CB *) client_data;

  flac_header_t hdr = decode_header(buffer);

  if (hdr.sync != 0xff3e) {
    // It probably is just metadata or file header, we don't need it for streaming
    return FLAC__STREAM_ENCODER_WRITE_STATUS_OK;
  }
  uint32_t packet_size = bytes;
#ifdef FLAC_SAVE_DUMP
  LOG_DEBUG(LOG_TAG, "%s: File %p, bytes %zu", __func__, cb->recFile, bytes);
  if (cb->recFile != NULL && bytes > 0) {
    size_t wrote = 0;
    uint32_t packet_size = bytes;
    fwrite(&packet_size, sizeof(packet_size), 1, cb->recFile);
    if((wrote = fwrite(buffer, sizeof(uint8_t), bytes, cb->recFile)) == bytes) {
        LOG_DEBUG(LOG_TAG, "%s: Wrote %zu bytes into dump", __func__, bytes);
    } else {
        LOG_DEBUG(LOG_TAG, "%s: Couldn't write all bytes into dump, only %zu/%zu", __func__, wrote, bytes);
    }
    fflush(cb->recFile);
  }
#endif
  if (cb->pbuf != NULL) {
#ifdef DEBUG_PREPEND_SIZE
    memcpy(cb->pbuf, &packet_size, sizeof(packet_size));
    memcpy(&cb->pbuf[sizeof(packet_size)], buffer, bytes);
    cb->written = sizeof(packet_size) + (bytes + 3) & ~0x03;
#else
    memcpy(cb->pbuf, buffer, bytes);
    cb->written = bytes;//(bytes + 3) & ~0x03;
#endif
    //LOG_DEBUG(LOG_TAG, "%s: %u bytes written in buffer, orig %zu", __func__, cb->written, bytes);
    cb->samples = samples;
    cb->out_frames++;
  } else {
    LOG_DEBUG(LOG_TAG, "%s: Cannot write to buffer, it haven't yet been set up", __func__);
  }
#ifdef DEBUG
  LOG_DEBUG(LOG_TAG, "%s: Frame header: sync 0x%02x res %d b %d "
                      "size 0x%x rate %d ch %s bps %d res %d\n",
                       __func__, hdr.sync, hdr.reserved1,
                       hdr.blocking, hdr.block_size,
                       hdr.sample_rate, chs[hdr.channel_assignment],
                       hdr.sample_size, hdr.reserved2);
#endif
  return FLAC__STREAM_ENCODER_WRITE_STATUS_OK;
}

void a2dp_vendor_flac_encoder_init(
    const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params,
    A2dpCodecConfig* a2dp_codec_config,
    a2dp_source_read_callback_t read_callback,
    a2dp_source_enqueue_callback_t enqueue_callback) {
  if (a2dp_flac_encoder_cb.has_flac_handle) {
      FLAC__stream_encoder_finish(a2dp_flac_encoder_cb.flac_handle);
      FLAC__stream_encoder_delete(a2dp_flac_encoder_cb.flac_handle);
  }
  memset(&a2dp_flac_encoder_cb, 0, sizeof(a2dp_flac_encoder_cb));

  a2dp_flac_encoder_cb.stats.session_start_us = time_get_os_boottime_us();

  a2dp_flac_encoder_cb.read_callback = read_callback;
  a2dp_flac_encoder_cb.enqueue_callback = enqueue_callback;
  a2dp_flac_encoder_cb.is_peer_edr = p_peer_params->is_peer_edr;
  a2dp_flac_encoder_cb.peer_supports_3mbps = p_peer_params->peer_supports_3mbps;
  a2dp_flac_encoder_cb.peer_mtu = p_peer_params->peer_mtu;
  a2dp_flac_encoder_cb.timestamp = 0;

  a2dp_flac_encoder_cb.use_SCMS_T = false;  // TODO: should be a parameter
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
  a2dp_flac_encoder_cb.use_SCMS_T = true;
#endif

  // NOTE: Ignore the restart_input / restart_output flags - this initization
  // happens when the connection is (re)started.
  bool restart_input = false;
  bool restart_output = false;
  bool config_updated = false;
  a2dp_vendor_flac_encoder_update(a2dp_flac_encoder_cb.peer_mtu,
                                  a2dp_codec_config, &restart_input,
                                  &restart_output, &config_updated);
}

bool A2dpCodecConfigFlac::updateEncoderUserConfig(
    const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params, bool* p_restart_input,
    bool* p_restart_output, bool* p_config_updated) {
  a2dp_flac_encoder_cb.is_peer_edr = p_peer_params->is_peer_edr;
  a2dp_flac_encoder_cb.peer_supports_3mbps = p_peer_params->peer_supports_3mbps;
  a2dp_flac_encoder_cb.peer_mtu = p_peer_params->peer_mtu;
  a2dp_flac_encoder_cb.timestamp = 0;

  if (a2dp_flac_encoder_cb.peer_mtu == 0) {
    LOG_ERROR(LOG_TAG,
              "%s: Cannot update the codec encoder for %s: "
              "invalid peer MTU",
              __func__, name().c_str());
    return false;
  }

  a2dp_vendor_flac_encoder_update(a2dp_flac_encoder_cb.peer_mtu, this,
                                  p_restart_input, p_restart_output,
                                  p_config_updated);
  return true;
}

// Update the A2DP FLAC encoder.
// |peer_mtu| is the peer MTU.
// |a2dp_codec_config| is the A2DP codec to use for the update.
static void a2dp_vendor_flac_encoder_update(uint16_t peer_mtu,
                                            A2dpCodecConfig* a2dp_codec_config,
                                            bool* p_restart_input,
                                            bool* p_restart_output,
                                            bool* p_config_updated) {
  tA2DP_FLAC_ENCODER_PARAMS* p_encoder_params =
      &a2dp_flac_encoder_cb.flac_encoder_params;
  uint8_t codec_info[AVDT_CODEC_SIZE];

  *p_restart_input = false;
  *p_restart_output = false;
  *p_config_updated = false;

  if (!a2dp_flac_encoder_cb.has_flac_handle) {
    a2dp_flac_encoder_cb.flac_handle = FLAC__stream_encoder_new();
    if (a2dp_flac_encoder_cb.flac_handle == NULL) {
      LOG_ERROR(LOG_TAG, "%s: Cannot get FLAC encoder handle", __func__);
      return;  // TODO: Return an error?
    }
    a2dp_flac_encoder_cb.has_flac_handle = true;
    a2dp_flac_encoder_cb.already_init = false;
  }

  if (!a2dp_codec_config->copyOutOtaCodecConfig(codec_info)) {
    LOG_ERROR(LOG_TAG,
              "%s: Cannot update the codec encoder for %s: "
              "invalid codec config",
              __func__, a2dp_codec_config->name().c_str());
    return;
  }
  const uint8_t* p_codec_info = codec_info;
  btav_a2dp_codec_config_t codec_config = a2dp_codec_config->getCodecConfig();

  // TODO: Recalculate block size if changed
  bool mix_channels = (codec_config.codec_specific_1 & A2DP_FLAC_STEREO_MONO_MASK) == A2DP_FLAC_MONO;
  if (a2dp_flac_encoder_cb.mix_channels != mix_channels) {
      FLAC__stream_encoder_finish(a2dp_flac_encoder_cb.flac_handle);
      FLAC__stream_encoder_delete(a2dp_flac_encoder_cb.flac_handle);
      a2dp_flac_encoder_cb.flac_handle = FLAC__stream_encoder_new();
      a2dp_flac_encoder_cb.already_init = false;
      a2dp_flac_encoder_cb.mix_channels = mix_channels;
      //*p_restart_output = true;
      //*p_restart_input = true;
  }

  if (a2dp_flac_encoder_cb.already_init) return;

  // The feeding parameters
  tA2DP_FEEDING_PARAMS* p_feeding_params = &a2dp_flac_encoder_cb.feeding_params;
  p_feeding_params->sample_rate =
      A2DP_VendorGetTrackSampleRateFlac(p_codec_info);
  p_feeding_params->bits_per_sample =
      a2dp_codec_config->getAudioBitsPerSample();
  p_feeding_params->channel_count =
      A2DP_VendorGetTrackChannelCountFlac(p_codec_info);
  LOG_DEBUG(LOG_TAG, "%s: sample_rate=%u bits_per_sample=%u channel_count=%u",
            __func__, p_feeding_params->sample_rate,
            p_feeding_params->bits_per_sample, p_feeding_params->channel_count);

  // The codec parameters
  p_encoder_params->sample_rate =
      a2dp_flac_encoder_cb.feeding_params.sample_rate;
  p_encoder_params->channel_count =
      A2DP_VendorGetTrackChannelCountFlac(p_codec_info);

  int old_block_size = p_encoder_params->block_size;

  uint16_t mtu_size =
      BT_DEFAULT_BUFFER_SIZE - A2DP_FLAC_OFFSET - sizeof(BT_HDR);

#if 0
  if (mtu_size < peer_mtu) {
    a2dp_flac_encoder_cb.TxAaMtuSize = mtu_size;
  } else {
    a2dp_flac_encoder_cb.TxAaMtuSize = peer_mtu;
  }
#else
  a2dp_flac_encoder_cb.TxAaMtuSize = peer_mtu;
#endif

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
  a2dp_flac_encoder_cb.TxAaMtuSize--;
#endif

  p_encoder_params->pcm_bits_per_sample =
      a2dp_flac_encoder_cb.feeding_params.bits_per_sample;

  int channel_count = 2;
  if (a2dp_flac_encoder_cb.mix_channels) channel_count = 1;

  //TODO: Verbatim frames might not fit

  p_encoder_params->block_size = a2dp_flac_encoder_cb.TxAaMtuSize * 8 /
                                 (channel_count *
                                  p_encoder_params->pcm_bits_per_sample);

  //if (p_encoder_params->block_size != old_block_size) {
  //  *p_config_updated = true;
  //  *p_restart_output = true;
  //}

  LOG_DEBUG(LOG_TAG, "%s: MTU=%d, peer_mtu=%d", __func__,
            a2dp_flac_encoder_cb.TxAaMtuSize, peer_mtu);
  LOG_DEBUG(LOG_TAG,
            "%s: sample_rate: %d channel_count: %d "
            "block_size: %d "
            "pcm_bits_per_sample: %d",
            __func__, p_encoder_params->sample_rate,
            p_encoder_params->channel_count,
            p_encoder_params->block_size,
            p_encoder_params->pcm_bits_per_sample);

  // Initialize the encoder.
  // NOTE: MTU in the initialization must include the AVDT media header size.

  bool result = TRUE;

  result &= FLAC__stream_encoder_set_channels(a2dp_flac_encoder_cb.flac_handle, p_encoder_params->channel_count);
  result &= FLAC__stream_encoder_set_bits_per_sample(a2dp_flac_encoder_cb.flac_handle, p_encoder_params->pcm_bits_per_sample);
  result &= FLAC__stream_encoder_set_sample_rate(a2dp_flac_encoder_cb.flac_handle, p_encoder_params->sample_rate);
  result &= FLAC__stream_encoder_set_blocksize(a2dp_flac_encoder_cb.flac_handle, p_encoder_params->block_size);
  result &= FLAC__stream_encoder_set_limit_min_bitrate(a2dp_flac_encoder_cb.flac_handle, true);
  result &= FLAC__stream_encoder_set_streamable_subset(a2dp_flac_encoder_cb.flac_handle, true);
  //result &= FLAC__stream_encoder_set_compression_level(a2dp_flac_encoder_cb.flac_handle, 9);

#ifdef FLAC_SAVE_DUMP
  if (a2dp_flac_encoder_cb.recFile == NULL) {
    a2dp_flac_encoder_cb.recFile = fopen(ENC_RAW_NAME,"wb");
    LOG_DEBUG(LOG_TAG, "%s: create recFile = %p", __func__, a2dp_flac_encoder_cb.recFile);
  }
  if (a2dp_flac_encoder_cb.pcmFile == NULL) {
    a2dp_flac_encoder_cb.pcmFile = fopen(ENC_PCM_NAME,"wb");
    LOG_DEBUG(LOG_TAG, "%s: create pcmFile = %p", __func__, a2dp_flac_encoder_cb.pcmFile);
  }
#endif
  if (!result) {
    LOG_ERROR(LOG_TAG, "%s: error setting the FLAC encoder params: %d", __func__,
              FLAC__stream_encoder_get_state(a2dp_flac_encoder_cb.flac_handle));
    return;
  }

  if (FLAC__stream_encoder_init_stream(a2dp_flac_encoder_cb.flac_handle, flac_stream_encoder_write_callback,
                                       NULL, NULL, NULL, &a2dp_flac_encoder_cb) != FLAC__STREAM_ENCODER_INIT_STATUS_OK) {
    return;
  }

  a2dp_flac_encoder_cb.already_init = true;
}

void a2dp_vendor_flac_encoder_cleanup(void) {
  if (a2dp_flac_encoder_cb.has_flac_handle) {
    FLAC__stream_encoder_finish(a2dp_flac_encoder_cb.flac_handle);
    FLAC__stream_encoder_delete(a2dp_flac_encoder_cb.flac_handle);
  }

#ifdef FLAC_SAVE_DUMP
  if (a2dp_flac_encoder_cb.recFile != NULL) {
    fclose(a2dp_flac_encoder_cb.recFile);
    a2dp_flac_encoder_cb.recFile = NULL;
    remove(ENC_RAW_NAME);
  }
  if (a2dp_flac_encoder_cb.pcmFile != NULL) {
    fclose(a2dp_flac_encoder_cb.pcmFile);
    a2dp_flac_encoder_cb.pcmFile = NULL;
    remove(ENC_PCM_NAME);
  }
#endif

  memset(&a2dp_flac_encoder_cb, 0, sizeof(a2dp_flac_encoder_cb));
}

void a2dp_vendor_flac_feeding_reset(void) {
  /* By default, just clear the entire state */
  memset(&a2dp_flac_encoder_cb.flac_feeding_state, 0,
         sizeof(a2dp_flac_encoder_cb.flac_feeding_state));

  a2dp_flac_encoder_cb.flac_feeding_state.bytes_per_tick =
      (a2dp_flac_encoder_cb.feeding_params.sample_rate *
       a2dp_flac_encoder_cb.feeding_params.bits_per_sample / 8 *
       a2dp_flac_encoder_cb.feeding_params.channel_count *
       A2DP_FLAC_ENCODER_INTERVAL_MS) /
      1000;

  LOG_DEBUG(LOG_TAG, "%s: PCM bytes per tick %u", __func__,
            a2dp_flac_encoder_cb.flac_feeding_state.bytes_per_tick);
}

void a2dp_vendor_flac_feeding_flush(void) {
  a2dp_flac_encoder_cb.flac_feeding_state.counter = 0.0f;
}

period_ms_t a2dp_vendor_flac_get_encoder_interval_ms(void) {
  return A2DP_FLAC_ENCODER_INTERVAL_MS;
}

void a2dp_vendor_flac_send_frames(uint64_t timestamp_us) {
  uint8_t nb_frame = 0;
  uint8_t nb_iterations = 0;

  a2dp_flac_get_num_frame_iteration(&nb_iterations, &nb_frame, timestamp_us);
  LOG_DEBUG(LOG_TAG, "%s: Sending %d frames per iteration, %d iterations",
              __func__, nb_frame, nb_iterations);
  if (nb_frame == 0) return;

  for (uint8_t counter = 0; counter < nb_iterations; counter++) {
    // Transcode frame and enqueue
    a2dp_flac_encode_frames(nb_frame);
  }
}

static uint32_t a2dp_flac_block_size(void) {
  return a2dp_flac_encoder_cb.flac_encoder_params.block_size *
         a2dp_flac_encoder_cb.feeding_params.channel_count *
         a2dp_flac_encoder_cb.feeding_params.bits_per_sample / 8;
}

// Obtains the number of frames to send and number of iterations
// to be used. |num_of_iterations| and |num_of_frames| parameters
// are used as output param for returning the respective values.
static void a2dp_flac_get_num_frame_iteration(uint8_t* num_of_iterations,
                                              uint8_t* num_of_frames,
                                              uint64_t timestamp_us) {
  uint32_t result = 0;
  uint8_t nof = 0;
  uint8_t noi = 1;

  uint32_t pcm_bytes_per_frame = a2dp_flac_block_size();
  LOG_DEBUG(LOG_TAG, "%s: pcm_bytes_per_frame %u", __func__,
              pcm_bytes_per_frame);

  uint32_t us_this_tick = A2DP_FLAC_ENCODER_INTERVAL_MS * 1000;

  uint64_t now_us = timestamp_us;
  if (a2dp_flac_encoder_cb.flac_feeding_state.last_frame_us != 0)
    us_this_tick =
        (now_us - a2dp_flac_encoder_cb.flac_feeding_state.last_frame_us);
  a2dp_flac_encoder_cb.flac_feeding_state.last_frame_us = now_us;

  a2dp_flac_encoder_cb.flac_feeding_state.counter +=
      (float)a2dp_flac_encoder_cb.flac_feeding_state.bytes_per_tick * us_this_tick /
      (A2DP_FLAC_ENCODER_INTERVAL_MS * 1000);

  result =
      a2dp_flac_encoder_cb.flac_feeding_state.counter / pcm_bytes_per_frame;
  a2dp_flac_encoder_cb.flac_feeding_state.counter -=
      result * pcm_bytes_per_frame;
  nof = result;
  //noi = result;

  LOG_DEBUG(LOG_TAG, "%s: effective num of frames %u, iterations %u",
              __func__, nof, noi);

  *num_of_frames = nof;
  *num_of_iterations = noi;
}

static void flac_deinterleave(size_t pcm_bits_per_sample, size_t shift, uint8_t *buf, size_t samples, size_t channels, int *out[2]) {
    for (size_t s = 0; s < samples; s++) {
        for (size_t c = 0; c < channels; c++) {
            switch(pcm_bits_per_sample) {
                case 16:
                    out[c][s] = (*(int16_t *)buf);// >> shift;
                    buf += 2;
                    break;
                case 24:
                    out[c][s] = ((buf[0] << 8) | (buf[1] << 16) | (buf[2] << 24)) >> (8);// + shift);
                    buf += 3;
                    break;
                default:
                    out[c] = NULL;
                    return;
            }
        }
    }
}

static void flac_deinterleave_mix(size_t pcm_bits_per_sample, size_t shift, uint8_t *buf, size_t samples, int *out[2]) {
    for (size_t s = 0; s < samples; s++) {
        int left, right, avg;
        switch(pcm_bits_per_sample) {
            case 16:
                left = ((int16_t *)buf)[0];// >> shift;
                right = ((int16_t *)buf)[1];// >> shift;
                buf += 4;
                break;
            case 24:
                left = ((buf[0] << 8) | (buf[1] << 16) | (buf[2] << 24)) >> (8);// + shift);
                right = ((buf[3] << 8) | (buf[4] << 16) | (buf[5] << 24)) >> (8);// + shift);
                buf += 6;
                break;
            default:
                out[0] = NULL;
                out[1] = NULL;
                return;
        }
        avg = (left + right) / 2;
        out[0][s] = avg;
        out[1][s] = avg;
    }
}
#ifdef DEBUG
#include <sstream>

static void flac_print_pcm(size_t pcm_bits_per_sample, size_t samples, size_t channels, int *in[2]) {
    std::stringstream pcm;
    LOG_DEBUG(LOG_TAG, "%s: PCM sample range is [%d, %d], %zu samples", __func__, -1U << (pcm_bits_per_sample-1), (1U << (pcm_bits_per_sample-1)) - 1, samples);
    for (size_t c = 0; c < channels; c++) {
        pcm << "Channel " << c << ":";
        for (size_t s = 0; s < samples; s++) {
            pcm << " " << in[c][s];
        }
        pcm << std::endl;
    }
    auto x = pcm.str();

    LOG_DEBUG(LOG_TAG, "%s: PCM dump:\n%s", __func__, x.c_str());
}
#endif

static void a2dp_flac_encode_frames(uint8_t nb_frame) {
  tA2DP_FLAC_ENCODER_PARAMS* p_encoder_params =
      &a2dp_flac_encoder_cb.flac_encoder_params;
  uint8_t remain_nb_frame = nb_frame;
  uint16_t flac_frame_size = p_encoder_params->block_size;
  uint8_t read_buffer[4096 * 4 /* byte/sample */ * 2 /* ch */];
  int left[4096];
  int right[4096];

  uint32_t count;
  int32_t encode_count = 0;
  int32_t out_frames = 0;
  int written = 0;

  uint32_t bytes_read = 0;
  while (nb_frame) {
#define FLAC_BUFFER_SIZE 16*BT_DEFAULT_BUFFER_SIZE
    BT_HDR* p_buf = (BT_HDR*)osi_malloc(FLAC_BUFFER_SIZE);
    p_buf->offset = A2DP_FLAC_OFFSET;
    p_buf->len = 0;
    p_buf->layer_specific = 0;
    a2dp_flac_encoder_cb.stats.media_read_total_expected_packets++;

    count = 0;
    do {
      //
      // Read the PCM data and encode it
      //
      uint32_t temp_bytes_read = 0;
      if (a2dp_flac_read_feeding(read_buffer, &temp_bytes_read)) {
        bytes_read += temp_bytes_read;
        uint8_t* packet = (uint8_t*)(p_buf + 1) + p_buf->offset + p_buf->len;
        if (a2dp_flac_encoder_cb.flac_handle == NULL) {
          LOG_ERROR(LOG_TAG, "%s: invalid FLAC handle", __func__);
          a2dp_flac_encoder_cb.stats.media_read_total_dropped_packets++;
          osi_free(p_buf);
          return;
        }
        a2dp_flac_encoder_cb.pbuf = packet + count;
        a2dp_flac_encoder_cb.written = 0;
        a2dp_flac_encoder_cb.samples = 0;
        a2dp_flac_encoder_cb.out_frames = 0;
        int *buffer[] = {left, right};
        //static void flac_deinterleave(size_t pcm_bits_per_sample, size_t shift, uint8_t *buf, size_t samples, size_t channels, int *out[2]) {

        int samples = temp_bytes_read / a2dp_flac_encoder_cb.flac_encoder_params.channel_count / (a2dp_flac_encoder_cb.flac_encoder_params.pcm_bits_per_sample / 8);
        if (a2dp_flac_encoder_cb.mix_channels) {
          flac_deinterleave_mix(a2dp_flac_encoder_cb.flac_encoder_params.pcm_bits_per_sample, 0 /* may be useful for 12/20 bit depth, but for know it doesn't work*/, read_buffer, samples, buffer);
        } else {
          flac_deinterleave(a2dp_flac_encoder_cb.flac_encoder_params.pcm_bits_per_sample, 0 /* may be useful for 12/20 bit depth, but for know it doesn't work*/, read_buffer, samples, a2dp_flac_encoder_cb.flac_encoder_params.channel_count, buffer);
        }
#ifdef FLAC_SAVE_DUMP
        if (a2dp_flac_encoder_cb.pcmFile != NULL) {
          fwrite(read_buffer, sizeof(uint8_t), temp_bytes_read, a2dp_flac_encoder_cb.pcmFile);
        }
#endif

        bool result = FLAC__stream_encoder_process(a2dp_flac_encoder_cb.flac_handle, buffer, a2dp_flac_encoder_cb.flac_encoder_params.block_size);
        written = a2dp_flac_encoder_cb.written;
        out_frames = a2dp_flac_encoder_cb.out_frames;
        if (result) {
          LOG_INFO(LOG_TAG, "%s: FLAC encoding OK, written %d, out_frames %d!", __func__, written, out_frames);
        } else {
          LOG_ERROR(LOG_TAG,
                    "%s: FLAC encoding error: %s, dropping %d encoded bytes",
                    __func__, FLAC__StreamEncoderStateString[FLAC__stream_encoder_get_state(a2dp_flac_encoder_cb.flac_handle)], written);
          a2dp_flac_encoder_cb.stats.media_read_total_dropped_packets++;
          osi_free(p_buf);
          return;
        }
        count += written;
        p_buf->len += written;
        nb_frame--;
        p_buf->layer_specific += out_frames;  // added a frame to the buffer
      } else {
        LOG_WARN(LOG_TAG, "%s: underflow %d", __func__, nb_frame);
        a2dp_flac_encoder_cb.flac_feeding_state.counter +=
            nb_frame * a2dp_flac_encoder_cb.flac_encoder_params.block_size *
            a2dp_flac_encoder_cb.feeding_params.channel_count *
            a2dp_flac_encoder_cb.feeding_params.bits_per_sample / 8;
        // no more pcm to read
        nb_frame = 0;
      }
    } while ((written == 0) && nb_frame);

    if (p_buf->len) {
      /*
       * Timestamp of the media packet header represent the TS of the
       * first frame, i.e the timestamp before including this frame.
       */
      *((uint32_t*)(p_buf + 1)) = a2dp_flac_encoder_cb.timestamp;

      a2dp_flac_encoder_cb.timestamp += p_buf->layer_specific * flac_frame_size;

      uint8_t done_nb_frame = remain_nb_frame - nb_frame;
      remain_nb_frame = nb_frame;
      if (!a2dp_flac_encoder_cb.enqueue_callback(p_buf, done_nb_frame,
                                                 bytes_read))
        return;
    } else {
      // NOTE: Unlike the execution path for other codecs, it is normal for
      // FLAC to NOT write encoded data to the last buffer if there wasn't
      // enough data to write to. That data is accumulated internally by
      // the codec and included in the next iteration. Therefore, here we
      // don't increment the "media_read_total_dropped_packets" counter.
      osi_free(p_buf);
    }
  }
}

static bool a2dp_flac_read_feeding(uint8_t* read_buffer, uint32_t* bytes_read) {
  uint32_t read_size = a2dp_flac_block_size();

  a2dp_flac_encoder_cb.stats.media_read_total_expected_reads_count++;
  a2dp_flac_encoder_cb.stats.media_read_total_expected_read_bytes += read_size;

  /* Read Data from UIPC channel */
  uint32_t nb_byte_read =
      a2dp_flac_encoder_cb.read_callback(read_buffer, read_size);
  a2dp_flac_encoder_cb.stats.media_read_total_actual_read_bytes += nb_byte_read;

  if (nb_byte_read < read_size) {
    if (nb_byte_read == 0) return false;

    /* Fill the unfilled part of the read buffer with silence (0) */
    memset(((uint8_t*)read_buffer) + nb_byte_read, 0, read_size - nb_byte_read);
    nb_byte_read = read_size;
  }
  a2dp_flac_encoder_cb.stats.media_read_total_actual_reads_count++;
  *bytes_read = nb_byte_read;
  return true;
}

void a2dp_vendor_flac_set_transmit_queue_length(size_t transmit_queue_length) {
  a2dp_flac_encoder_cb.TxQueueLength = transmit_queue_length;
}

period_ms_t A2dpCodecConfigFlac::encoderIntervalMs() const {
  return a2dp_vendor_flac_get_encoder_interval_ms();
}

void A2dpCodecConfigFlac::debug_codec_dump(int fd) {
  a2dp_flac_encoder_stats_t* stats = &a2dp_flac_encoder_cb.stats;
  tA2DP_FLAC_ENCODER_PARAMS* p_encoder_params =
      &a2dp_flac_encoder_cb.flac_encoder_params;

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
          "  FLAC saved transmit queue length                        : %zu\n",
          a2dp_flac_encoder_cb.TxQueueLength);
}
