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

/******************************************************************************
 *
 *  Utility functions to help build and parse the LC3plus HR Codec Information
 *  Element and Media Payload.
 *
 ******************************************************************************/

#define LOG_TAG "a2dp_vendor_lc3plus_hr"

#include "bt_target.h"

#include "a2dp_vendor_lc3plus_hr.h"

#include <string.h>

#include <base/logging.h>
#include "a2dp_vendor.h"
#include "a2dp_vendor_lc3plus_hr_encoder.h"
#include "btif_av_co.h"
#include "bt_utils.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

// data type for the LC3plus HR Codec Information Element */
// NOTE: bits_per_sample is needed only for LC3plus HR encoder initialization.
typedef struct {
  uint32_t vendorId;
  uint16_t codecId;     /* Codec ID for LC3plus HR */
  uint16_t sampleRate;   /* Sampling Frequency */
  uint8_t channelMode;  /* STEREO/MONO */
  uint8_t frameLength; /* 2.5, 5 or 10 ms */
  btav_a2dp_codec_bits_per_sample_t bits_per_sample;
} tA2DP_LC3PLUS_HR_CIE;

/* LC3plus HR Source codec capabilities */
static const tA2DP_LC3PLUS_HR_CIE a2dp_lc3plus_hr_caps = {
    A2DP_LC3PLUS_HR_VENDOR_ID,  // vendorId
    A2DP_LC3PLUS_HR_CODEC_ID,   // codecId
    // sampleRate
    (A2DP_LC3PLUS_HR_SAMPLING_RATE_48000 | A2DP_LC3PLUS_HR_SAMPLING_RATE_96000),
    // channelMode
    A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO,
    // frameLength
    (A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS |
     A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS |
     A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS),
    // bits_per_sample
    (BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16 |
     BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24 |
     BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32)
};

/* Default LC3plus HR codec configuration */
static const tA2DP_LC3PLUS_HR_CIE a2dp_lc3plus_hr_src_default_config = {
    A2DP_LC3PLUS_HR_VENDOR_ID,          // vendorId
    A2DP_LC3PLUS_HR_CODEC_ID,           // codecId
    A2DP_LC3PLUS_HR_SAMPLING_RATE_48000,  // sampleRate
    A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO,// channelMode
    A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS,
    BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24, // bits_per_sample
};

tA2DP_LC3PLUS_HR_CIE a2dp_lc3plus_hr_default_config;

static const tA2DP_ENCODER_INTERFACE a2dp_encoder_interface_lc3plus_hr = {
    a2dp_vendor_lc3plus_hr_encoder_init,
    a2dp_vendor_lc3plus_hr_encoder_cleanup,
    a2dp_vendor_lc3plus_hr_feeding_reset,
    a2dp_vendor_lc3plus_hr_feeding_flush,
    a2dp_vendor_lc3plus_hr_get_encoder_interval_ms,
    a2dp_vendor_lc3plus_hr_send_frames,
    a2dp_vendor_lc3plus_hr_set_transmit_queue_length};

UNUSED_ATTR static tA2DP_STATUS A2DP_CodecInfoMatchesCapabilityLC3plusHR(
    const tA2DP_LC3PLUS_HR_CIE* p_cap, const uint8_t* p_codec_info,
    bool is_peer_codec_info);

// Builds the LC3plus HR Media Codec Capabilities byte sequence beginning from the
// LOSC octet. |media_type| is the media type |AVDT_MEDIA_TYPE_*|.
// |p_ie| is a pointer to the LC3plus HR Codec Information Element information.
// The result is stored in |p_result|. Returns A2DP_SUCCESS on success,
// otherwise the corresponding A2DP error status code.
static tA2DP_STATUS A2DP_BuildInfoLC3plusHR(uint8_t media_type,
                                       const tA2DP_LC3PLUS_HR_CIE* p_ie,
                                       uint8_t* p_result) {
  if (p_ie == NULL || p_result == NULL) {
    return A2DP_INVALID_PARAMS;
  }

  *p_result++ = A2DP_LC3PLUS_HR_CODEC_LEN;
  *p_result++ = (media_type << 4);
  *p_result++ = A2DP_MEDIA_CT_NON_A2DP;

  // Vendor ID and Codec ID
  *p_result++ = (uint8_t)(p_ie->vendorId & 0x000000FF);
  *p_result++ = (uint8_t)((p_ie->vendorId & 0x0000FF00) >> 8);
  *p_result++ = (uint8_t)((p_ie->vendorId & 0x00FF0000) >> 16);
  *p_result++ = (uint8_t)((p_ie->vendorId & 0xFF000000) >> 24);
  *p_result++ = (uint8_t)(p_ie->codecId & 0x00FF);
  *p_result++ = (uint8_t)((p_ie->codecId & 0xFF00) >> 8);

  // Frame Duration
  *p_result = (uint8_t)(p_ie->frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_MASK);
  if (*p_result == 0) return A2DP_INVALID_PARAMS;
  p_result++;

  // Channel Mode
  *p_result = (uint8_t)(p_ie->channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_MASK);
  if (*p_result == 0) return A2DP_INVALID_PARAMS;
  p_result++;

  // Sampling Frequency
  *p_result++ = (uint8_t)((p_ie->sampleRate >> 8) & 0xFF);
  *p_result++ = (uint8_t)(p_ie->sampleRate & 0xFF);
  if (p_ie->sampleRate == 0) return A2DP_INVALID_PARAMS;

  return A2DP_SUCCESS;
}

// Parses the LC3plus HR Media Codec Capabilities byte sequence beginning from the
// LOSC octet. The result is stored in |p_ie|. The byte sequence to parse is
// |p_codec_info|. If |is_capability| is true, the byte sequence is
// codec capabilities, otherwise is codec configuration.
// Returns A2DP_SUCCESS on success, otherwise the corresponding A2DP error
// status code.
static tA2DP_STATUS A2DP_ParseInfoLC3plusHR(tA2DP_LC3PLUS_HR_CIE* p_ie,
                                       const uint8_t* p_codec_info,
                                       bool is_capability) {
  uint8_t losc;
  uint8_t media_type;
  tA2DP_CODEC_TYPE codec_type;

  LOG_DEBUG(LOG_TAG, "%s: parsing LC3plus HR info: p_ie = %p, p_codec_info = %p", __func__, p_ie, p_codec_info);


  if (p_ie == NULL || p_codec_info == NULL) return A2DP_INVALID_PARAMS;

  // Check the codec capability length
  losc = *p_codec_info++;
  LOG_DEBUG(LOG_TAG, "%s: parsing LC3plus HR info: losc %u", __func__, losc);

  if (losc != A2DP_LC3PLUS_HR_CODEC_LEN) return A2DP_WRONG_CODEC;

  media_type = (*p_codec_info++) >> 4;
  codec_type = *p_codec_info++;

  LOG_DEBUG(LOG_TAG, "%s: parsing LC3plus HR info: media_type %u, codec_type %u", __func__, media_type, codec_type);

  /* Check the Media Type and Media Codec Type */
  if (media_type != AVDT_MEDIA_TYPE_AUDIO ||
      codec_type != A2DP_MEDIA_CT_NON_A2DP) {
    return A2DP_WRONG_CODEC;
  }

  // Check the Vendor ID and Codec ID */
  p_ie->vendorId = (*p_codec_info & 0x000000FF) |
                   (*(p_codec_info + 1) << 8 & 0x0000FF00) |
                   (*(p_codec_info + 2) << 16 & 0x00FF0000) |
                   (*(p_codec_info + 3) << 24 & 0xFF000000);
  p_codec_info += 4;
  p_ie->codecId =
      (*p_codec_info & 0x00FF) | (*(p_codec_info + 1) << 8 & 0xFF00);
  p_codec_info += 2;

  LOG_DEBUG(LOG_TAG, "%s: parsing LC3plus HR info: vendorId %04x, codecId %02x", __func__, p_ie->vendorId, p_ie->codecId);

  if (p_ie->vendorId != A2DP_LC3PLUS_HR_VENDOR_ID ||
      p_ie->codecId != A2DP_LC3PLUS_HR_CODEC_ID) {
    return A2DP_WRONG_CODEC;
  }

    // Frame Duration
  p_ie->frameLength = *p_codec_info++ & A2DP_LC3PLUS_HR_FRAME_DURATION_MASK;
  p_ie->channelMode = *p_codec_info++ & A2DP_LC3PLUS_HR_CHANNEL_MODE_MASK;
  p_ie->sampleRate = *p_codec_info++ << 8;
  p_ie->sampleRate |= *p_codec_info++;
  p_ie->sampleRate &= A2DP_LC3PLUS_HR_SAMPLING_RATE_MASK;
  p_ie->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE;

  if (*p_codec_info & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32)
    p_ie->bits_per_sample |= BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32;
  if (*p_codec_info & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24)
    p_ie->bits_per_sample |= BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24;
  if (*p_codec_info & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16)
    p_ie->bits_per_sample |= BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16;

  p_codec_info++;

  LOG_DEBUG(LOG_TAG, "%s: parsing LC3plus HR info: frame len %x, sample rate %x, channel mode %x, bits per sample %x", __func__, p_ie->frameLength, p_ie->sampleRate, p_ie->channelMode, p_ie->bits_per_sample);

  if (is_capability) {
    LOG_DEBUG(LOG_TAG, "%s: parsing LC3plus HR info: SUCCESS!", __func__);
    return A2DP_SUCCESS;
  }

  if (A2DP_BitsSet(p_ie->sampleRate) != A2DP_SET_ONE_BIT) {
    LOG_DEBUG(LOG_TAG, "%s: parsing LC3plus HR info: bad sample rate", __func__);
    return A2DP_BAD_SAMP_FREQ;
  }
  if (A2DP_BitsSet(p_ie->channelMode) != A2DP_SET_ONE_BIT) {
    LOG_DEBUG(LOG_TAG, "%s: parsing LC3plus HR info: bad channel mode", __func__);
    return A2DP_BAD_CH_MODE;
  }
  if (A2DP_BitsSet(p_ie->frameLength) != A2DP_SET_ONE_BIT) {
    LOG_DEBUG(LOG_TAG, "%s: parsing LC3plus HR info: bad frame length", __func__);
    return A2DP_BAD_BLOCK_LEN;
  }
  LOG_DEBUG(LOG_TAG, "%s: parsing LC3plus HR info: SUCCESS!", __func__);
  return A2DP_SUCCESS;
}

// Build the LC3plus HR Media Payload Header.
// |p_dst| points to the location where the header should be written to.
// If |frag| is true, the media payload frame is fragmented.
// |start| is true for the first packet of a fragmented frame.
// |last| is true for the last packet of a fragmented frame.
// If |frag| is false, |num| is the number of number of frames in the packet,
// otherwise is the number of remaining fragments (including this one).
static void A2DP_BuildMediaPayloadHeaderLC3plusHR(uint8_t* p_dst, bool frag,
                                             bool start, bool last,
                                             uint8_t num) {
  if (p_dst == NULL) return;

  *p_dst = 0;
  if (frag) *p_dst |= A2DP_LC3PLUS_HR_HDR_F_MSK;
  if (start) *p_dst |= A2DP_LC3PLUS_HR_HDR_S_MSK;
  if (last) *p_dst |= A2DP_LC3PLUS_HR_HDR_L_MSK;
  *p_dst |= (A2DP_LC3PLUS_HR_HDR_NUM_MSK & num);
}

bool A2DP_IsVendorSourceCodecValidLC3plusHR(const uint8_t* p_codec_info) {
  tA2DP_LC3PLUS_HR_CIE cfg_cie;

  LOG_DEBUG(LOG_TAG, "%s", __func__);

  /* Use a liberal check when parsing the codec info */
  return (A2DP_ParseInfoLC3plusHR(&cfg_cie, p_codec_info, false) == A2DP_SUCCESS) ||
         (A2DP_ParseInfoLC3plusHR(&cfg_cie, p_codec_info, true) == A2DP_SUCCESS);
}

bool A2DP_IsVendorPeerSinkCodecValidLC3plusHR(const uint8_t* p_codec_info) {
  tA2DP_LC3PLUS_HR_CIE cfg_cie;

  LOG_DEBUG(LOG_TAG, "%s", __func__);

  /* Use a liberal check when parsing the codec info */
  return (A2DP_ParseInfoLC3plusHR(&cfg_cie, p_codec_info, false) == A2DP_SUCCESS) ||
         (A2DP_ParseInfoLC3plusHR(&cfg_cie, p_codec_info, true) == A2DP_SUCCESS);
}

// Checks whether A2DP LC3plus HR codec configuration matches with a device's codec
// capabilities. |p_cap| is the LC3plus HR codec configuration. |p_codec_info| is
// the device's codec capabilities.
// If |is_capability| is true, the byte sequence is codec capabilities,
// otherwise is codec configuration.
// |p_codec_info| contains the codec capabilities for a peer device that
// is acting as an A2DP source.
// Returns A2DP_SUCCESS if the codec configuration matches with capabilities,
// otherwise the corresponding A2DP error status code.
static tA2DP_STATUS A2DP_CodecInfoMatchesCapabilityLC3plusHR(
    const tA2DP_LC3PLUS_HR_CIE* p_cap, const uint8_t* p_codec_info,
    bool is_capability) {
  tA2DP_STATUS status;
  tA2DP_LC3PLUS_HR_CIE cfg_cie;

  /* parse configuration */
  status = A2DP_ParseInfoLC3plusHR(&cfg_cie, p_codec_info, is_capability);
  if (status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: parsing failed %d", __func__, status);
    return status;
  }

  /* verify that each parameter is in range */

  LOG_VERBOSE(LOG_TAG, "%s: FREQ peer: 0x%x, capability 0x%x", __func__,
              cfg_cie.sampleRate, p_cap->sampleRate);
  LOG_VERBOSE(LOG_TAG, "%s: CH_MODE peer: 0x%x, capability 0x%x", __func__,
              cfg_cie.channelMode, p_cap->channelMode);
  LOG_VERBOSE(LOG_TAG, "%s: FRAME_LEN peer: 0x%x, capability 0x%x", __func__,
              cfg_cie.frameLength, p_cap->frameLength);

  /* sampling frequency */
  if ((cfg_cie.sampleRate & p_cap->sampleRate) == 0) return A2DP_NS_SAMP_FREQ;

  /* channel mode */
  if ((cfg_cie.channelMode & p_cap->channelMode) == 0) return A2DP_NS_CH_MODE;

  if ((cfg_cie.frameLength & p_cap->frameLength) == 0) return A2DP_BAD_BLOCK_LEN;

  return A2DP_SUCCESS;
}

bool A2DP_VendorUsesRtpHeaderLC3plusHR(UNUSED_ATTR bool content_protection_enabled,
                                  UNUSED_ATTR const uint8_t* p_codec_info) {
  // TODO: Is this correct? The RTP header is always included?
  return true;
}

const char* A2DP_VendorCodecNameLC3plusHR(UNUSED_ATTR const uint8_t* p_codec_info) {
  return "LC3plus HR";
}

bool A2DP_VendorCodecTypeEqualsLC3plusHR(const uint8_t* p_codec_info_a,
                                    const uint8_t* p_codec_info_b) {
  tA2DP_LC3PLUS_HR_CIE lc3plus_hr_cie_a;
  tA2DP_LC3PLUS_HR_CIE lc3plus_hr_cie_b;

  // Check whether the codec info contains valid data
  tA2DP_STATUS a2dp_status =
      A2DP_ParseInfoLC3plusHR(&lc3plus_hr_cie_a, p_codec_info_a, true);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return false;
  }
  a2dp_status = A2DP_ParseInfoLC3plusHR(&lc3plus_hr_cie_b, p_codec_info_b, true);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return false;
  }

  return true;
}

bool A2DP_VendorCodecEqualsLC3plusHR(const uint8_t* p_codec_info_a,
                                const uint8_t* p_codec_info_b) {
  tA2DP_LC3PLUS_HR_CIE lc3plus_hr_cie_a;
  tA2DP_LC3PLUS_HR_CIE lc3plus_hr_cie_b;

  // Check whether the codec info contains valid data
  tA2DP_STATUS a2dp_status =
      A2DP_ParseInfoLC3plusHR(&lc3plus_hr_cie_a, p_codec_info_a, true);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return false;
  }
  a2dp_status = A2DP_ParseInfoLC3plusHR(&lc3plus_hr_cie_b, p_codec_info_b, true);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return false;
  }

  return (lc3plus_hr_cie_a.sampleRate == lc3plus_hr_cie_b.sampleRate) &&
         (lc3plus_hr_cie_a.channelMode == lc3plus_hr_cie_b.channelMode) &&
         (lc3plus_hr_cie_a.frameLength == lc3plus_hr_cie_b.frameLength);
}

int A2DP_VendorGetBitRateLC3plusHR(const uint8_t* p_codec_info) {
  A2dpCodecConfig* current_codec = bta_av_get_a2dp_current_codec();
  if (current_codec == nullptr) {
    LOG_ERROR(LOG_TAG, "%s: Failed to get current a2dp codec", __func__);
    return 0;
  }
  btav_a2dp_codec_config_t codec_config_ = current_codec->getCodecConfig();
#if 1
  return codec_config_.codec_specific_1;
#else
  return 0;
#endif
}

float A2DP_VendorGetFrameMsLC3plusHR(const uint8_t* p_codec_info) {
  A2dpCodecConfig* current_codec = bta_av_get_a2dp_current_codec();
  if (current_codec == nullptr) {
    LOG_ERROR(LOG_TAG, "%s: Failed to get current a2dp codec", __func__);
    return 0;
  }
  btav_a2dp_codec_config_t codec_config_ = current_codec->getCodecConfig();
  switch (codec_config_.codec_specific_2) {
    case A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS:
      return 10.f;
    case A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS:
      return 5.f;
    case A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS:
      return 2.5f;
  }
  LOG_ERROR(LOG_TAG, "%s: Failed to get frame length: cs2: %" PRIi64, __func__, codec_config_.codec_specific_2);
  return 0;
}

int A2DP_VendorGetTrackSampleRateLC3plusHR(const uint8_t* p_codec_info) {
  tA2DP_LC3PLUS_HR_CIE lc3plus_hr_cie;

  // Check whether the codec info contains valid data
  tA2DP_STATUS a2dp_status = A2DP_ParseInfoLC3plusHR(&lc3plus_hr_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (lc3plus_hr_cie.sampleRate) {
    case A2DP_LC3PLUS_HR_SAMPLING_RATE_48000:
      return 48000;
    case A2DP_LC3PLUS_HR_SAMPLING_RATE_96000:
      return 96000;
  }

  return -1;
}

int A2DP_VendorGetTrackBitsPerSampleLC3plusHR(const uint8_t* p_codec_info) {
  tA2DP_LC3PLUS_HR_CIE lc3plus_hr_cie;

  // Check whether the codec info contains valid data
  tA2DP_STATUS a2dp_status = A2DP_ParseInfoLC3plusHR(&lc3plus_hr_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (lc3plus_hr_cie.sampleRate) {
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16:
      return 16;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24:
      return 24;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32:
      return 32;
  }

  return -1;
}

int A2DP_VendorGetTrackChannelCountLC3plusHR(const uint8_t* p_codec_info) {
  tA2DP_LC3PLUS_HR_CIE lc3plus_hr_cie;

  // Check whether the codec info contains valid data
  tA2DP_STATUS a2dp_status = A2DP_ParseInfoLC3plusHR(&lc3plus_hr_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (lc3plus_hr_cie.channelMode) {
    case A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO:
      return 1;
    case A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO:
      return 2;
  }

  return -1;
}

int A2DP_VendorGetChannelModeCodeLC3plusHR(const uint8_t* p_codec_info) {
  tA2DP_LC3PLUS_HR_CIE lc3plus_hr_cie;

  // Check whether the codec info contains valid data
  tA2DP_STATUS a2dp_status = A2DP_ParseInfoLC3plusHR(&lc3plus_hr_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (lc3plus_hr_cie.channelMode) {
    case A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO:
    case A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO:
      return lc3plus_hr_cie.channelMode;
    default:
      break;
  }

  return -1;
}

bool A2DP_VendorGetPacketTimestampLC3plusHR(UNUSED_ATTR const uint8_t* p_codec_info,
                                       const uint8_t* p_data,
                                       uint32_t* p_timestamp) {
  // TODO: Is this function really codec-specific?
  *p_timestamp = *(const uint32_t*)p_data;
  return true;
}

bool A2DP_VendorBuildCodecHeaderLC3plusHR(UNUSED_ATTR const uint8_t* p_codec_info,
                                     BT_HDR* p_buf,
                                     uint16_t frames_per_packet) {
  uint8_t* p;

  p_buf->offset -= A2DP_LC3PLUS_HR_MPL_HDR_LEN;
  p = (uint8_t*)(p_buf + 1) + p_buf->offset;
  p_buf->len += A2DP_LC3PLUS_HR_MPL_HDR_LEN;
  A2DP_BuildMediaPayloadHeaderLC3plusHR(p, false, false, false,
                                   (uint8_t)frames_per_packet);

  return true;
}

bool A2DP_VendorBuildCodecHeaderLC3plusHR(UNUSED_ATTR const uint8_t* p_codec_info,
                                     BT_HDR* p_buf, bool frag, bool start,
                                     bool last, uint16_t fragments) {
  uint8_t* p;

  p_buf->offset -= A2DP_LC3PLUS_HR_MPL_HDR_LEN;
  p = (uint8_t*)(p_buf + 1) + p_buf->offset;
  p_buf->len += A2DP_LC3PLUS_HR_MPL_HDR_LEN;
  A2DP_BuildMediaPayloadHeaderLC3plusHR(p, frag, start, last,
                                   (uint8_t)fragments);

  return true;
}

bool A2DP_VendorDumpCodecInfoLC3plusHR(const uint8_t* p_codec_info) {
  tA2DP_STATUS a2dp_status;
  tA2DP_LC3PLUS_HR_CIE lc3plus_hr_cie;

  LOG_VERBOSE(LOG_TAG, "%s", __func__);

  a2dp_status = A2DP_ParseInfoLC3plusHR(&lc3plus_hr_cie, p_codec_info, true);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: A2DP_ParseInfoLC3plusHR fail:%d", __func__, a2dp_status);
    return false;
  }

  LOG_VERBOSE(LOG_TAG, "\tframe_len: 0x%x", lc3plus_hr_cie.frameLength);
  if (lc3plus_hr_cie.frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS) {
    LOG_VERBOSE(LOG_TAG, "\tframe_len: (2.5)");
  }
  if (lc3plus_hr_cie.frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS) {
    LOG_VERBOSE(LOG_TAG, "\tframe_len: (5)");
  }
  if (lc3plus_hr_cie.frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS) {
    LOG_VERBOSE(LOG_TAG, "\tframe_len: (10)");
  }

  LOG_VERBOSE(LOG_TAG, "\tsamp_freq: 0x%x", lc3plus_hr_cie.sampleRate);
  if (lc3plus_hr_cie.sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_48000) {
    LOG_VERBOSE(LOG_TAG, "\tsamp_freq: (48000)");
  }
  if (lc3plus_hr_cie.sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_96000) {
    LOG_VERBOSE(LOG_TAG, "\tsamp_freq: (96000)");
  }

  LOG_VERBOSE(LOG_TAG, "\tch_mode: 0x%x", lc3plus_hr_cie.channelMode);
  if (lc3plus_hr_cie.channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO) {
    LOG_VERBOSE(LOG_TAG, "\tch_mode: (Mono)");
  }
  if (lc3plus_hr_cie.channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO) {
    LOG_VERBOSE(LOG_TAG, "\tch_mode: (Stereo)");
  }

  LOG_VERBOSE(LOG_TAG, "\tbit_format: 0x%x", lc3plus_hr_cie.bits_per_sample);
  if (lc3plus_hr_cie.bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16) {
    LOG_VERBOSE(LOG_TAG, "\tch_mode: (16)");
  }
  if (lc3plus_hr_cie.bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24) {
    LOG_VERBOSE(LOG_TAG, "\tch_mode: (24)");
  }
  if (lc3plus_hr_cie.bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32) {
    LOG_VERBOSE(LOG_TAG, "\tch_mode: (32)");
  }
  return true;
}

tA2DP_STATUS A2DP_VendorIsCodecConfigMatchLC3plusHR(const uint8_t* p_codec_info) {
  tA2DP_STATUS a2dp_status;
  tA2DP_LC3PLUS_HR_CIE lc3plus_hr_cie;

  LOG_DEBUG(LOG_TAG, "%s", __func__);

  a2dp_status = A2DP_ParseInfoLC3plusHR(&lc3plus_hr_cie, p_codec_info, false);
  LOG_DEBUG(LOG_TAG, "%s: a2dp_status: %d", __func__, a2dp_status);
  return a2dp_status;
}

const tA2DP_ENCODER_INTERFACE* A2DP_VendorGetEncoderInterfaceLC3plusHR(
    const uint8_t* p_codec_info) {
  if (!A2DP_IsVendorSourceCodecValidLC3plusHR(p_codec_info)) return NULL;

  return &a2dp_encoder_interface_lc3plus_hr;
}

bool A2DP_VendorAdjustCodecLC3plusHR(uint8_t* p_codec_info) {
  tA2DP_LC3PLUS_HR_CIE cfg_cie;

  // Nothing to do: just verify the codec info is valid
  if (A2DP_ParseInfoLC3plusHR(&cfg_cie, p_codec_info, true) != A2DP_SUCCESS)
    return false;

  return true;
}

btav_a2dp_codec_index_t A2DP_VendorSourceCodecIndexLC3plusHR(
    UNUSED_ATTR const uint8_t* p_codec_info) {
  return BTAV_A2DP_CODEC_INDEX_SOURCE_LC3PLUS_HR;
}

const char* A2DP_VendorCodecIndexStrLC3plusHR(void) { return "LC3plus HR"; }

bool A2DP_VendorInitCodecConfigLC3plusHR(tAVDT_CFG* p_cfg) {
  if (!A2DP_IsCodecEnabled(BTAV_A2DP_CODEC_INDEX_SOURCE_LC3PLUS_HR)){
    LOG_ERROR(LOG_TAG, "%s: LC3plus HR disabled in both SW and HW mode", __func__);
    return false;
  }

  if (A2DP_BuildInfoLC3plusHR(AVDT_MEDIA_TYPE_AUDIO, &a2dp_lc3plus_hr_caps,
                         p_cfg->codec_info) != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: Failed to build LC3plus HR info", __func__);
    return false;
  }

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
  /* Content protection info - support SCMS-T */
  uint8_t* p = p_cfg->protect_info;
  *p++ = AVDT_CP_LOSC;
  UINT16_TO_STREAM(p, AVDT_CP_SCMS_T_ID);
  p_cfg->num_protect = 1;
#endif

  return true;
}

UNUSED_ATTR static void build_codec_config(const tA2DP_LC3PLUS_HR_CIE& config_cie,
                                           btav_a2dp_codec_config_t* result) {
  if (config_cie.sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_48000)
    result->sample_rate |= BTAV_A2DP_CODEC_SAMPLE_RATE_48000;
  if (config_cie.sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_96000)
    result->sample_rate |= BTAV_A2DP_CODEC_SAMPLE_RATE_96000;

  result->bits_per_sample = config_cie.bits_per_sample;

  if (config_cie.channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO)
    result->channel_mode |= BTAV_A2DP_CODEC_CHANNEL_MODE_MONO;
  if (config_cie.channelMode & (A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO)) {
    result->channel_mode |= BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO;
  }

  result->codec_specific_2 = config_cie.frameLength;
}

A2dpCodecConfigLC3plusHR::A2dpCodecConfigLC3plusHR(
    btav_a2dp_codec_priority_t codec_priority)
    : A2dpCodecConfig(BTAV_A2DP_CODEC_INDEX_SOURCE_LC3PLUS_HR, "LC3plus HR",
                      codec_priority) {
  // Compute the local capability
  a2dp_lc3plus_hr_default_config = a2dp_lc3plus_hr_src_default_config;

  if (a2dp_lc3plus_hr_caps.sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_48000) {
    codec_local_capability_.sample_rate |= BTAV_A2DP_CODEC_SAMPLE_RATE_48000;
  }
  if (a2dp_lc3plus_hr_caps.sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_96000) {
    codec_local_capability_.sample_rate |= BTAV_A2DP_CODEC_SAMPLE_RATE_96000;
  }
  if (a2dp_lc3plus_hr_caps.channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO) {
    codec_local_capability_.channel_mode |= BTAV_A2DP_CODEC_CHANNEL_MODE_MONO;
  }
  if (a2dp_lc3plus_hr_caps.channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO) {
    codec_local_capability_.channel_mode |= BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO;
  }
  codec_local_capability_.bits_per_sample = a2dp_lc3plus_hr_caps.bits_per_sample;

  codec_local_capability_.codec_specific_2 = a2dp_lc3plus_hr_caps.frameLength;

}

A2dpCodecConfigLC3plusHR::~A2dpCodecConfigLC3plusHR() {}

bool A2dpCodecConfigLC3plusHR::init() {
  if (!isValid()) return false;

  LOG_DEBUG(LOG_TAG, "%s: LC3plus HR enabled in SW mode", __func__);

  // Load the encoder
  if (!A2DP_VendorLoadEncoderLC3plusHR()) {
    LOG_ERROR(LOG_TAG, "%s: cannot load the encoder", __func__);
    return false;
  }

  return true;
}

bool A2dpCodecConfigLC3plusHR::useRtpHeaderMarkerBit() const { return false; }

//
// Selects the best sample rate from |sampleRate|.
// The result is stored in |p_result| and |p_codec_config|.
// Returns true if a selection was made, otherwise false.
//
static bool select_best_sample_rate(uint16_t sampleRate,
                                    tA2DP_LC3PLUS_HR_CIE* p_result,
                                    btav_a2dp_codec_config_t* p_codec_config) {
  if (sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_96000) {
    p_result->sampleRate = A2DP_LC3PLUS_HR_SAMPLING_RATE_96000;
    p_codec_config->sample_rate = BTAV_A2DP_CODEC_SAMPLE_RATE_96000;
    return true;
  }
  if (sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_48000) {
    p_result->sampleRate = A2DP_LC3PLUS_HR_SAMPLING_RATE_48000;
    p_codec_config->sample_rate = BTAV_A2DP_CODEC_SAMPLE_RATE_48000;
    return true;
  }

  return false;
}

//
// Selects the audio sample rate from |p_codec_audio_config|.
// |sampleRate| contains the capability.
// The result is stored in |p_result| and |p_codec_config|.
// Returns true if a selection was made, otherwise false.
//
static bool select_audio_sample_rate(
    const btav_a2dp_codec_config_t* p_codec_audio_config, uint16_t sampleRate,
    tA2DP_LC3PLUS_HR_CIE* p_result, btav_a2dp_codec_config_t* p_codec_config) {
  switch (p_codec_audio_config->sample_rate) {
    case BTAV_A2DP_CODEC_SAMPLE_RATE_48000:
      if (sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_48000) {
        p_result->sampleRate = A2DP_LC3PLUS_HR_SAMPLING_RATE_48000;
        p_codec_config->sample_rate = BTAV_A2DP_CODEC_SAMPLE_RATE_48000;
        return true;
      }
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_96000:
      if (sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_96000) {
        p_result->sampleRate = A2DP_LC3PLUS_HR_SAMPLING_RATE_96000;
        p_codec_config->sample_rate = BTAV_A2DP_CODEC_SAMPLE_RATE_96000;
        return true;
      }
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_NONE:
      break;
    default:
      break;
  }
  return false;
}

//
// Selects the best bits per sample from |bits_per_sample|.
// |bits_per_sample| contains the capability.
// The result is stored in |p_result| and |p_codec_config|.
// Returns true if a selection was made, otherwise false.
//
static bool select_best_bits_per_sample(
    btav_a2dp_codec_bits_per_sample_t bits_per_sample, tA2DP_LC3PLUS_HR_CIE* p_result,
    btav_a2dp_codec_config_t* p_codec_config) {
  if (bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32) {
    p_codec_config->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32;
    p_result->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32;
    return true;
  }
  if (bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24) {
    p_codec_config->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24;
    p_result->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24;
    return true;
  }
  if (bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16) {
    p_codec_config->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16;
    p_result->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16;
    return true;
  }
  return false;
}

//
// Selects the audio bits per sample from |p_codec_audio_config|.
// |bits_per_sample| contains the capability.
// The result is stored in |p_result| and |p_codec_config|.
// Returns true if a selection was made, otherwise false.
//
static bool select_audio_bits_per_sample(
    const btav_a2dp_codec_config_t* p_codec_audio_config,
    btav_a2dp_codec_bits_per_sample_t bits_per_sample, tA2DP_LC3PLUS_HR_CIE* p_result,
    btav_a2dp_codec_config_t* p_codec_config) {
  switch (p_codec_audio_config->bits_per_sample) {
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16:
      if (bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16) {
        p_codec_config->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16;
        p_result->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16;
        return true;
      }
      break;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24:
      if (bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24) {
        p_codec_config->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24;
        p_result->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24;
        return true;
      }
      break;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32:
      if (bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32) {
        p_codec_config->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32;
        p_result->bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32;
        return true;
      }
      break;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE:
      break;
  }
  return false;
}

//
// Selects the best frame length from |channelMode|.
// The result is stored in |p_result| and |p_codec_config|.
// Returns true if a selection was made, otherwise false.
//
static bool select_best_frame_length(uint8_t frameLength,
                                     tA2DP_LC3PLUS_HR_CIE* p_result,
                                     btav_a2dp_codec_config_t* p_codec_config) {
  if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS) {
    p_result->frameLength = A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS;
    p_codec_config->codec_specific_2 = A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS;
    return true;
  }
  if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS) {
    p_result->frameLength = A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS;
    p_codec_config->codec_specific_2 = A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS;
    return true;
  }
  if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS) {
    p_result->frameLength = A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS;
    p_codec_config->codec_specific_2 = A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS;
    return true;
  }
  return false;
}

//
// Selects the audio channel mode from |p_codec_audio_config|.
// |channelMode| contains the capability.
// The result is stored in |p_result| and |p_codec_config|.
// Returns true if a selection was made, otherwise false.
//
static bool select_audio_frame_length(
    const btav_a2dp_codec_config_t* p_codec_audio_config, uint8_t frameLength,
    tA2DP_LC3PLUS_HR_CIE* p_result, btav_a2dp_codec_config_t* p_codec_config) {
  switch (p_codec_audio_config->codec_specific_2) {
    case A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS:
      if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS) {
        p_result->frameLength = A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS;
        p_codec_config->codec_specific_2 = A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS;
        return true;
      }
      break;
    case A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS:
      if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS) {
        p_result->frameLength = A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS;
        p_codec_config->codec_specific_2 = A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS;
        return true;
      }
    case A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS:
      if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS) {
        p_result->frameLength = A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS;
        p_codec_config->codec_specific_2 = A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS;
        return true;
      }

    default:
      break;
  }

  return false;
}

//
// Selects the best channel mode from |channelMode|.
// The result is stored in |p_result| and |p_codec_config|.
// Returns true if a selection was made, otherwise false.
//
static bool select_best_channel_mode(uint8_t channelMode,
                                     tA2DP_LC3PLUS_HR_CIE* p_result,
                                     btav_a2dp_codec_config_t* p_codec_config) {
  if (channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO) {
    p_result->channelMode = A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO;
    p_codec_config->channel_mode = BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO;
    return true;
  }
  if (channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO) {
    p_result->channelMode = A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO;
    p_codec_config->channel_mode = BTAV_A2DP_CODEC_CHANNEL_MODE_MONO;
    return true;
  }
  return false;
}

//
// Selects the audio channel mode from |p_codec_audio_config|.
// |channelMode| contains the capability.
// The result is stored in |p_result| and |p_codec_config|.
// Returns true if a selection was made, otherwise false.
//
static bool select_audio_channel_mode(
    const btav_a2dp_codec_config_t* p_codec_audio_config, uint8_t channelMode,
    tA2DP_LC3PLUS_HR_CIE* p_result, btav_a2dp_codec_config_t* p_codec_config) {
  switch (p_codec_audio_config->channel_mode) {
    case BTAV_A2DP_CODEC_CHANNEL_MODE_MONO:
      if (channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO) {
        p_result->channelMode = A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO;
        p_codec_config->channel_mode = BTAV_A2DP_CODEC_CHANNEL_MODE_MONO;
        return true;
      }
      break;
    case BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO:
      if (channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO) {
        p_result->channelMode = A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO;
        p_codec_config->channel_mode = BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO;
        return true;
      }
    case BTAV_A2DP_CODEC_CHANNEL_MODE_NONE:
      break;
  }

  return false;
}

void print_lc3plus_hr_codec_config(uint8_t codec_config_arry[]) {
   for(int i = 0; i < AVDT_CODEC_SIZE; i++)
   {
      LOG_INFO(LOG_TAG, "%s: codec_config_arry[%d] = %d", __func__, i, codec_config_arry[i]);
   }
}

void print_lc3plus_hr_codec_parameters(btav_a2dp_codec_config_t config) {
  LOG_DEBUG(
     LOG_TAG,
     "codec_type=%d codec_priority=%d "
     "sample_rate=0x%x bits_per_sample=0x%x "
     "channel_mode=0x%x codec_specific_1=%" PRIi64
     " "
     "codec_specific_2=%" PRIi64
     " "
     "codec_specific_3=%" PRIi64
     " "
     "codec_specific_4=%" PRIi64,
     config.codec_type, config.codec_priority,
     config.sample_rate, config.bits_per_sample,
     config.channel_mode, config.codec_specific_1,
     config.codec_specific_2, config.codec_specific_3,
     config.codec_specific_4);
}

bool A2dpCodecConfigLC3plusHR::setCodecConfig(const uint8_t* p_peer_codec_info,
                                         bool is_capability,
                                         uint8_t* p_result_codec_config) {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);
  tA2DP_LC3PLUS_HR_CIE sink_info_cie;
  tA2DP_LC3PLUS_HR_CIE result_config_cie;
  uint8_t channelMode;
  uint16_t sampleRate;
  uint8_t frameLength;
  btav_a2dp_codec_bits_per_sample_t bits_per_sample;

  // Save the internal state
  btav_a2dp_codec_config_t saved_codec_config = codec_config_;
  btav_a2dp_codec_config_t saved_codec_capability = codec_capability_;
  btav_a2dp_codec_config_t saved_codec_selectable_capability =
      codec_selectable_capability_;
  btav_a2dp_codec_config_t saved_codec_user_config = codec_user_config_;
  btav_a2dp_codec_config_t saved_codec_audio_config = codec_audio_config_;

  LOG_DEBUG(LOG_TAG, "%s: saved_codec_user_config: ", __func__);
  print_lc3plus_hr_codec_parameters(saved_codec_user_config);
  LOG_DEBUG(LOG_TAG, "%s: saved_codec_audio_config: ", __func__);
  print_lc3plus_hr_codec_parameters(saved_codec_audio_config);

  uint8_t saved_ota_codec_config[AVDT_CODEC_SIZE];
  uint8_t saved_ota_codec_peer_capability[AVDT_CODEC_SIZE];
  uint8_t saved_ota_codec_peer_config[AVDT_CODEC_SIZE];
  memcpy(saved_ota_codec_config, ota_codec_config_, sizeof(ota_codec_config_));
  memcpy(saved_ota_codec_peer_capability, ota_codec_peer_capability_,
         sizeof(ota_codec_peer_capability_));
  memcpy(saved_ota_codec_peer_config, ota_codec_peer_config_,
         sizeof(ota_codec_peer_config_));
  //print_lc3plus_hr_codec_config(saved_ota_codec_config);
  //print_lc3plus_hr_codec_config(saved_ota_codec_peer_capability);
  //print_lc3plus_hr_codec_config(saved_ota_codec_peer_config);

  tA2DP_STATUS status =
      A2DP_ParseInfoLC3plusHR(&sink_info_cie, p_peer_codec_info, is_capability);
  if (status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: can't parse peer's Sink capabilities: error = %d",
              __func__, status);
    goto fail;
  }

  LOG_DEBUG(LOG_TAG, "%s: is_capability: %d", __func__, is_capability);
  //
  // Build the preferred configuration
  //
  memset(&result_config_cie, 0, sizeof(result_config_cie));
  result_config_cie.vendorId = a2dp_lc3plus_hr_caps.vendorId;
  result_config_cie.codecId = a2dp_lc3plus_hr_caps.codecId;

  //
  // Select the sample frequency
  //
  sampleRate = a2dp_lc3plus_hr_caps.sampleRate & sink_info_cie.sampleRate;
  codec_config_.sample_rate = BTAV_A2DP_CODEC_SAMPLE_RATE_NONE;

  LOG_DEBUG(LOG_TAG, "%s: caps sampleRate: %d, user sampleRate: %d", __func__, sampleRate, codec_user_config_.sample_rate);

  switch (codec_user_config_.sample_rate) {
    case BTAV_A2DP_CODEC_SAMPLE_RATE_48000:
      if (sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_48000) {
        result_config_cie.sampleRate = A2DP_LC3PLUS_HR_SAMPLING_RATE_48000;
        codec_capability_.sample_rate = codec_user_config_.sample_rate;
        codec_config_.sample_rate = codec_user_config_.sample_rate;
      }
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_96000:
      if (sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_96000) {
        result_config_cie.sampleRate = A2DP_LC3PLUS_HR_SAMPLING_RATE_96000;
        codec_capability_.sample_rate = codec_user_config_.sample_rate;
        codec_config_.sample_rate = codec_user_config_.sample_rate;
      }
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_NONE:
      codec_capability_.sample_rate = BTAV_A2DP_CODEC_SAMPLE_RATE_NONE;
      codec_config_.sample_rate = BTAV_A2DP_CODEC_SAMPLE_RATE_NONE;
      break;
    default:
      break;
  }

  // Select the sample frequency if there is no user preference
  do {
    // Compute the selectable capability
    if (sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_48000) {
      codec_selectable_capability_.sample_rate |=
          BTAV_A2DP_CODEC_SAMPLE_RATE_48000;
    }
    if (sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_96000) {
      codec_selectable_capability_.sample_rate |=
          BTAV_A2DP_CODEC_SAMPLE_RATE_96000;
    }

    if (codec_config_.sample_rate != BTAV_A2DP_CODEC_SAMPLE_RATE_NONE) break;

    // Compute the common capability
    if (sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_48000)
      codec_capability_.sample_rate |= BTAV_A2DP_CODEC_SAMPLE_RATE_48000;
    if (sampleRate & A2DP_LC3PLUS_HR_SAMPLING_RATE_96000)
      codec_capability_.sample_rate |= BTAV_A2DP_CODEC_SAMPLE_RATE_96000;

    // No user preference - try the codec audio config
    if (select_audio_sample_rate(&codec_audio_config_, sampleRate,
                                 &result_config_cie, &codec_config_)) {
      break;
    }

    // No user preference - try the default config
    if (select_best_sample_rate(
            a2dp_lc3plus_hr_default_config.sampleRate & sink_info_cie.sampleRate,
            &result_config_cie, &codec_config_)) {
      break;
    }

    // No user preference - use the best match
    if (select_best_sample_rate(sampleRate, &result_config_cie,
                                &codec_config_)) {
      break;
    }
  } while (false);
  if (codec_config_.sample_rate == BTAV_A2DP_CODEC_SAMPLE_RATE_NONE) {
    LOG_ERROR(LOG_TAG,
              "%s: cannot match sample frequency: source caps = 0x%x "
              "sink info = 0x%x",
              __func__, a2dp_lc3plus_hr_caps.sampleRate, sink_info_cie.sampleRate);
    goto fail;
  }

  //
  // Select the bits per sample
  //
  // NOTE: this information is not included in the LC3plus HR A2DP codec description
  // that is sent OTA.
  bits_per_sample = a2dp_lc3plus_hr_caps.bits_per_sample;
  codec_config_.bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE;
  switch (codec_user_config_.bits_per_sample) {
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16:
      if (bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16) {
        result_config_cie.bits_per_sample = codec_user_config_.bits_per_sample;
        codec_capability_.bits_per_sample = codec_user_config_.bits_per_sample;
        codec_config_.bits_per_sample = codec_user_config_.bits_per_sample;
      }
      break;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24:
      if (bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24) {
        result_config_cie.bits_per_sample = codec_user_config_.bits_per_sample;
        codec_capability_.bits_per_sample = codec_user_config_.bits_per_sample;
        codec_config_.bits_per_sample = codec_user_config_.bits_per_sample;
      }
      break;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32:
      if (bits_per_sample & BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32) {
        result_config_cie.bits_per_sample = codec_user_config_.bits_per_sample;
        codec_capability_.bits_per_sample = codec_user_config_.bits_per_sample;
        codec_config_.bits_per_sample = codec_user_config_.bits_per_sample;
      }
      break;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE:
      result_config_cie.bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE;
      codec_capability_.bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE;
      codec_config_.bits_per_sample = BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE;
      break;
  }

  // Select the bits per sample if there is no user preference
  do {
    // Compute the selectable capability
    codec_selectable_capability_.bits_per_sample =
        a2dp_lc3plus_hr_caps.bits_per_sample;

    if (codec_config_.bits_per_sample != BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE)
      break;

    // Compute the common capability
    codec_capability_.bits_per_sample = bits_per_sample;

    // No user preference - the the codec audio config
    if (select_audio_bits_per_sample(&codec_audio_config_,
                                     a2dp_lc3plus_hr_caps.bits_per_sample,
                                     &result_config_cie, &codec_config_)) {
      break;
    }

    // No user preference - try the default config
    if (select_best_bits_per_sample(a2dp_lc3plus_hr_default_config.bits_per_sample,
                                    &result_config_cie, &codec_config_)) {
      break;
    }

    // No user preference - use the best match
    if (select_best_bits_per_sample(a2dp_lc3plus_hr_caps.bits_per_sample,
                                    &result_config_cie, &codec_config_)) {
      break;
    }
  } while (false);
  if (codec_config_.bits_per_sample == BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE) {
    LOG_ERROR(LOG_TAG,
              "%s: cannot match bits per sample: default = 0x%x "
              "user preference = 0x%x",
              __func__, a2dp_lc3plus_hr_default_config.bits_per_sample,
              codec_user_config_.bits_per_sample);
    goto fail;
  }

  //
  // Select the channel mode
  //
  channelMode = a2dp_lc3plus_hr_caps.channelMode & sink_info_cie.channelMode;
  codec_config_.channel_mode = BTAV_A2DP_CODEC_CHANNEL_MODE_NONE;
  switch (codec_user_config_.channel_mode) {
    case BTAV_A2DP_CODEC_CHANNEL_MODE_MONO:
      if (channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO) {
        result_config_cie.channelMode = A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO;
        codec_capability_.channel_mode = codec_user_config_.channel_mode;
        codec_config_.channel_mode = codec_user_config_.channel_mode;
      }
      break;
    case BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO:
      if (channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO) {
        result_config_cie.channelMode = A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO;
        codec_capability_.channel_mode = codec_user_config_.channel_mode;
        codec_config_.channel_mode = codec_user_config_.channel_mode;
        break;
      }
      break;
    case BTAV_A2DP_CODEC_CHANNEL_MODE_NONE:
      codec_capability_.channel_mode = BTAV_A2DP_CODEC_CHANNEL_MODE_NONE;
      codec_config_.channel_mode = BTAV_A2DP_CODEC_CHANNEL_MODE_NONE;
      break;
  }

  // Select the channel mode if there is no user preference
  do {
    // Compute the selectable capability
    if (channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO) {
      codec_selectable_capability_.channel_mode |=
          BTAV_A2DP_CODEC_CHANNEL_MODE_MONO;
    }
    if (channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO) {
      codec_selectable_capability_.channel_mode |=
          BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO;
    }

    if (codec_config_.channel_mode != BTAV_A2DP_CODEC_CHANNEL_MODE_NONE) break;

    // Compute the common capability
    if (channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO)
      codec_capability_.channel_mode |= BTAV_A2DP_CODEC_CHANNEL_MODE_MONO;
    if (channelMode & A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO) {
      codec_capability_.channel_mode |= BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO;
    }

    // No user preference - try the codec audio config
    if (select_audio_channel_mode(&codec_audio_config_, channelMode,
                                  &result_config_cie, &codec_config_)) {
      break;
    }

    // No user preference - try the default config
    if (select_best_channel_mode(
            a2dp_lc3plus_hr_default_config.channelMode & sink_info_cie.channelMode,
            &result_config_cie, &codec_config_)) {
      break;
    }

    // No user preference - use the best match
    if (select_best_channel_mode(channelMode, &result_config_cie,
                                 &codec_config_)) {
      break;
    }

  } while (false);
  if (codec_config_.channel_mode == BTAV_A2DP_CODEC_CHANNEL_MODE_NONE) {
    LOG_ERROR(LOG_TAG,
              "%s: cannot match channel mode: source caps = 0x%x "
              "sink info = 0x%x",
              __func__, a2dp_lc3plus_hr_caps.channelMode, sink_info_cie.channelMode);
    goto fail;
  }

  //
  // Select the frame length
  //
  frameLength = a2dp_lc3plus_hr_caps.frameLength & sink_info_cie.frameLength;
  codec_config_.codec_specific_2 = 0;
  switch (codec_user_config_.codec_specific_2) {
    case A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS:
      if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS) {
        result_config_cie.frameLength = A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS;
        codec_capability_.codec_specific_2 = codec_user_config_.codec_specific_2;
        codec_config_.codec_specific_2 = codec_user_config_.codec_specific_2;
      }
      break;
    case A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS:
      if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS) {
        result_config_cie.frameLength = A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS;
        codec_capability_.codec_specific_2 = codec_user_config_.codec_specific_2;
        codec_config_.codec_specific_2 = codec_user_config_.codec_specific_2;
        break;
      }
      break;
    case A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS:
      if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS) {
        result_config_cie.frameLength = A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS;
        codec_capability_.codec_specific_2 = codec_user_config_.codec_specific_2;
        codec_config_.codec_specific_2 = codec_user_config_.codec_specific_2;
        break;
      }
      break;

    default:
      codec_capability_.codec_specific_2 = 0;
      codec_config_.codec_specific_2 = 0;
      break;
  }

  // Select the frame length if there is no user preference
  do {
    // Compute the selectable capability
    if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS) {
      codec_selectable_capability_.codec_specific_2 |=
          A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS;
    }
    if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS) {
      codec_selectable_capability_.codec_specific_2 |=
          A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS;
    }
    if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS) {
      codec_selectable_capability_.codec_specific_2 |=
          A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS;
    }

    if (codec_config_.codec_specific_2 != 0) break;

    // Compute the common capability
    if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS)
      codec_capability_.codec_specific_2 |= A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS;
    if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS) {
      codec_capability_.codec_specific_2 |= A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS;
    }
    if (frameLength & A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS) {
      codec_capability_.codec_specific_2 |= A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS;
    }

    // No user preference - try the codec audio config
    if (select_audio_frame_length(&codec_audio_config_, frameLength,
                                  &result_config_cie, &codec_config_)) {
      break;
    }

    // No user preference - try the default config
    if (select_best_frame_length(
            a2dp_lc3plus_hr_default_config.frameLength & sink_info_cie.frameLength,
            &result_config_cie, &codec_config_)) {
      break;
    }

    // No user preference - use the best match
    if (select_best_frame_length(frameLength, &result_config_cie,
                                 &codec_config_)) {
      break;
    }
  } while (false);
  if (codec_config_.codec_specific_2 == 0) {
    LOG_ERROR(LOG_TAG,
              "%s: cannot match frame length: source caps = 0x%x "
              "sink info = 0x%x",
              __func__, a2dp_lc3plus_hr_caps.frameLength, sink_info_cie.frameLength);
    goto fail;
  }

  if (A2DP_BuildInfoLC3plusHR(AVDT_MEDIA_TYPE_AUDIO, &result_config_cie,
                         p_result_codec_config) != A2DP_SUCCESS) {
    goto fail;
  }

  //
  // Copy the codec-specific fields if they are not zero
  //
   LOG_DEBUG(
     LOG_TAG,
     "%s: codec_user_config_:codec_specific_1=%" PRIi64
     " "
     "codec_specific_2=%" PRIi64
     " "
     "codec_specific_3=%" PRIi64
     " "
     "codec_specific_4=%" PRIi64,
     __func__,  codec_user_config_.codec_specific_1,
     codec_user_config_.codec_specific_2, codec_user_config_.codec_specific_3,
     codec_user_config_.codec_specific_4);
  //if (codec_user_config_.codec_specific_1 != 0) // 0 is a valid bitrate value
  codec_config_.codec_specific_1 = codec_user_config_.codec_specific_1;
  //if (codec_user_config_.codec_specific_2 != 0) // already set by now
  //  codec_config_.codec_specific_2 = codec_user_config_.codec_specific_2;
  if (codec_user_config_.codec_specific_3 != 0)
    codec_config_.codec_specific_3 = codec_user_config_.codec_specific_3;
  if (codec_user_config_.codec_specific_4 != 0)
    codec_config_.codec_specific_4 = codec_user_config_.codec_specific_4;

  // Create a local copy of the peer codec capability, and the
  // result codec config.
  if (is_capability) {
    status = A2DP_BuildInfoLC3plusHR(AVDT_MEDIA_TYPE_AUDIO, &sink_info_cie,
                                ota_codec_peer_capability_);
  } else {
    status = A2DP_BuildInfoLC3plusHR(AVDT_MEDIA_TYPE_AUDIO, &sink_info_cie,
                                ota_codec_peer_config_);
  }
  CHECK(status == A2DP_SUCCESS);
  status = A2DP_BuildInfoLC3plusHR(AVDT_MEDIA_TYPE_AUDIO, &result_config_cie,
                              ota_codec_config_);
  CHECK(status == A2DP_SUCCESS);
  return true;

fail:
  // Restore the internal state
  codec_config_ = saved_codec_config;
  codec_capability_ = saved_codec_capability;
  codec_selectable_capability_ = saved_codec_selectable_capability;
  codec_user_config_ = saved_codec_user_config;
  codec_audio_config_ = saved_codec_audio_config;
  memcpy(ota_codec_config_, saved_ota_codec_config, sizeof(ota_codec_config_));
  memcpy(ota_codec_peer_capability_, saved_ota_codec_peer_capability,
         sizeof(ota_codec_peer_capability_));
  memcpy(ota_codec_peer_config_, saved_ota_codec_peer_config,
         sizeof(ota_codec_peer_config_));
  return false;
}
