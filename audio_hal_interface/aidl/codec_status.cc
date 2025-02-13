/*
 * Copyright 2022 The Android Open Source Project
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
/*
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.

    * Redistribution and use in source and binary forms, with or without
      modification, are permitted (subject to the limitations in the
      disclaimer below) provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

    * Neither the name of Qualcomm Innovation Center, Inc. nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE
GRANTED BY THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
*/

#define LOG_TAG "bluetooth"

#include "codec_status.h"

#include <unordered_set>
#include "a2dp_aac_constants.h"
#include "a2dp_sbc_constants.h"
#include "a2dp_vendor_aptx_constants.h"
#include "a2dp_vendor_aptx_hd_constants.h"
#include "a2dp_vendor_ldac_constants.h"
#include "a2dp_vendor_aptx_adaptive.h"
#include "btif_av.h"
#include "bta/av/bta_av_int.h"
#include "client_interface.h"

extern bool btif_av_current_device_is_tws();

namespace bluetooth {
namespace audio {
namespace aidl {
namespace codec {

using ::aidl::android::hardware::bluetooth::audio::AacCapabilities;
using ::aidl::android::hardware::bluetooth::audio::AacConfiguration;
using ::aidl::android::hardware::bluetooth::audio::AacObjectType;
using ::aidl::android::hardware::bluetooth::audio::AptxCapabilities;
using ::aidl::android::hardware::bluetooth::audio::AptxConfiguration;
using ::aidl::android::hardware::bluetooth::audio::AptxAdaptiveConfiguration;
using ::aidl::android::hardware::bluetooth::audio::AptxAdaptiveCapabilities;
using ::aidl::android::hardware::bluetooth::audio::AptxAdaptiveChannelMode;
using ::aidl::android::hardware::bluetooth::audio::AptxAdaptiveInputMode;
using ::aidl::android::hardware::bluetooth::audio::AptxMode;
using ::aidl::android::hardware::bluetooth::audio::AudioCapabilities;
using ::aidl::android::hardware::bluetooth::audio::ChannelMode;
using ::aidl::android::hardware::bluetooth::audio::CodecCapabilities;
using ::aidl::android::hardware::bluetooth::audio::CodecType;
using ::aidl::android::hardware::bluetooth::audio::LdacCapabilities;
using ::aidl::android::hardware::bluetooth::audio::LdacChannelMode;
using ::aidl::android::hardware::bluetooth::audio::LdacConfiguration;
using ::aidl::android::hardware::bluetooth::audio::LdacQualityIndex;
using ::aidl::android::hardware::bluetooth::audio::SbcAllocMethod;
using ::aidl::android::hardware::bluetooth::audio::SbcCapabilities;
using ::aidl::android::hardware::bluetooth::audio::SbcChannelMode;
using ::aidl::android::hardware::bluetooth::audio::SbcConfiguration;

namespace {

// capabilities from BluetoothAudioSinkClientInterface::GetAudioCapabilities()
std::vector<AudioCapabilities> audio_hal_capabilities(0);
// capabilities that audio HAL supports and frameworks / Bluetooth SoC / runtime
// preference would like to use.
std::vector<AudioCapabilities> offloading_preference(0);

template <typename T>
struct identity {
  typedef T type;
};

template <class T>
bool ContainedInVector(const std::vector<T>& vector,
                       const typename identity<T>::type& target) {
  return std::find(vector.begin(), vector.end(), target) != vector.end();
}

bool sbc_offloading_capability_match(const SbcCapabilities& sbc_capability,
                                     const SbcConfiguration& sbc_config) {
  if (!ContainedInVector(sbc_capability.channelMode, sbc_config.channelMode) ||
      !ContainedInVector(sbc_capability.allocMethod, sbc_config.allocMethod) ||
      !ContainedInVector(sbc_capability.blockLength, sbc_config.blockLength) ||
      !ContainedInVector(sbc_capability.numSubbands, sbc_config.numSubbands) ||
      !ContainedInVector(sbc_capability.bitsPerSample,
                         sbc_config.bitsPerSample) ||
      !ContainedInVector(sbc_capability.sampleRateHz,
                         sbc_config.sampleRateHz) ||
      (sbc_config.minBitpool < sbc_capability.minBitpool ||
       sbc_config.maxBitpool < sbc_config.minBitpool ||
       sbc_capability.maxBitpool < sbc_config.maxBitpool)) {
    LOG(WARNING) << __func__ << ": software codec=" << sbc_config.toString()
                 << " capability=" << sbc_capability.toString();
    return false;
  }
  LOG(INFO) << __func__ << ": offload codec=" << sbc_config.toString()
            << " capability=" << sbc_capability.toString();
  return true;
}

bool aac_offloading_capability_match(const AacCapabilities& aac_capability,
                                     const AacConfiguration& aac_config) {
  if (!ContainedInVector(aac_capability.channelMode, aac_config.channelMode) ||
      !ContainedInVector(aac_capability.objectType, aac_config.objectType) ||
      !ContainedInVector(aac_capability.bitsPerSample,
                         aac_config.bitsPerSample) ||
      !ContainedInVector(aac_capability.sampleRateHz,
                         aac_config.sampleRateHz) ||
      (!aac_capability.variableBitRateSupported &&
       aac_config.variableBitRateEnabled)) {
    LOG(WARNING) << __func__ << ": software codec=" << aac_config.toString()
                 << " capability=" << aac_capability.toString();
    return false;
  }
  LOG(INFO) << __func__ << ": offloading codec=" << aac_config.toString()
            << " capability=" << aac_capability.toString();
  return true;
}

bool aptx_offloading_capability_match(const AptxCapabilities& aptx_capability,
                                      const AptxConfiguration& aptx_config) {
  if (!ContainedInVector(aptx_capability.channelMode,
                         aptx_config.channelMode) ||
      !ContainedInVector(aptx_capability.bitsPerSample,
                         aptx_config.bitsPerSample) ||
      !ContainedInVector(aptx_capability.sampleRateHz,
                         aptx_config.sampleRateHz)) {
    LOG(WARNING) << __func__ << ": software codec=" << aptx_config.toString()
                 << " capability=" << aptx_capability.toString();
    return false;
  }
  LOG(INFO) << __func__ << ": offloading codec=" << aptx_config.toString()
            << " capability=" << aptx_capability.toString();
  return true;
}

bool ldac_offloading_capability_match(const LdacCapabilities& ldac_capability,
                                      const LdacConfiguration& ldac_config) {
  if (!ContainedInVector(ldac_capability.channelMode,
                         ldac_config.channelMode) ||
      !ContainedInVector(ldac_capability.bitsPerSample,
                         ldac_config.bitsPerSample) ||
      !ContainedInVector(ldac_capability.sampleRateHz,
                         ldac_config.sampleRateHz)) {
    LOG(WARNING) << __func__ << ": software codec=" << ldac_config.toString()
                 << " capability=" << ldac_capability.toString();
    return false;
  }
  LOG(INFO) << __func__ << ": offloading codec=" << ldac_config.toString()
            << " capability=" << ldac_capability.toString();
  return true;
}
}  // namespace

const CodecConfiguration kInvalidCodecConfiguration = {};

int32_t A2dpCodecToHalSampleRate(
    const btav_a2dp_codec_config_t& a2dp_codec_config) {
  switch (a2dp_codec_config.sample_rate) {
    case BTAV_A2DP_CODEC_SAMPLE_RATE_44100:
      return 44100;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_48000:
      return 48000;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_88200:
      return 88200;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_96000:
      return 96000;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_176400:
      return 176400;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_192000:
      return 192000;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_16000:
      return 16000;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_24000:
      return 24000;
    default:
      return 0;
  }
}

int8_t A2dpCodecToHalBitsPerSample(
    const btav_a2dp_codec_config_t& a2dp_codec_config) {
  switch (a2dp_codec_config.bits_per_sample) {
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16:
      return 16;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24:
      return 24;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32:
      return 32;
    default:
      return 0;
  }
}

ChannelMode A2dpCodecToHalChannelMode(
    const btav_a2dp_codec_config_t& a2dp_codec_config) {
  switch (a2dp_codec_config.channel_mode) {
    case BTAV_A2DP_CODEC_CHANNEL_MODE_MONO:
      return ChannelMode::MONO;
    case BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO:
      return ChannelMode::STEREO;
    default:
      return ChannelMode::UNKNOWN;
  }
}

AptxAdaptiveChannelMode AptxAdaptiveCodecToHalChannelMode(
    const btav_a2dp_codec_config_t& a2dp_codec_config) {
  switch (a2dp_codec_config.channel_mode) {
    case BTAV_A2DP_CODEC_CHANNEL_MODE_MONO:
      return AptxAdaptiveChannelMode::MONO;
    case BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO:
      return AptxAdaptiveChannelMode::JOINT_STEREO;
    default:
      return AptxAdaptiveChannelMode::UNKNOWN;
   }
}

LdacQualityIndex a2dp_codec_to_hal_ldac_quality_index (
    const btav_a2dp_codec_config_t& a2dp_codec_config) {
  switch (a2dp_codec_config.codec_specific_1) {
    case 1000:
      return LdacQualityIndex::HIGH;
    case 1001:
      return LdacQualityIndex::MID;
    case 1002:
      return LdacQualityIndex::LOW;
    case 1003:
      return LdacQualityIndex::ABR;
    default:
      return LdacQualityIndex::ABR;
  }
}

bool a2dp_is_audio_codec_config_params_changed_aidl(
                        CodecConfiguration* codec_config, A2dpCodecConfig* a2dp_config) {
  uint8_t p_codec_info[AVDT_CODEC_SIZE];
  bool changed = false;
  if (codec_config == nullptr) return false;
  if (a2dp_config == nullptr) {
    LOG(WARNING) << __func__ << ": failure to get A2DP codec config";
    return false;
  }

  btav_a2dp_codec_config_t current_codec = a2dp_config->getCodecConfig();
  LOG(ERROR) << __func__
             << ": current codec_type=" << current_codec.codec_type
             << ": hidl codec type=" << ( uint32_t) codec_config->codecType;
  tBT_A2DP_OFFLOAD a2dp_offload;
  a2dp_config->getCodecSpecificConfig(&a2dp_offload);
  memset(p_codec_info, 0, AVDT_CODEC_SIZE);
  if (!a2dp_config->copyOutOtaCodecConfig(p_codec_info))
  {
    LOG(ERROR) << "No valid codec config";
    return false;
  }
  switch (current_codec.codec_type) {
    case BTAV_A2DP_CODEC_INDEX_SOURCE_SBC:
      [[fallthrough]];
    case BTAV_A2DP_CODEC_INDEX_SINK_SBC: {
      LOG(WARNING) << __func__ << ": sbc";
      if(codec_config->codecType != CodecType::SBC) {
        changed = true;
        break;
      }
      SbcConfiguration sbc_config = codec_config->config.get<CodecConfiguration::CodecSpecific::sbcConfig>();
      if(sbc_config.sampleRateHz !=
          A2dpCodecToHalSampleRate(current_codec)) {
        changed = true;
        break;
      }
      if(sbc_config.bitsPerSample !=
          A2dpCodecToHalBitsPerSample(current_codec)) {
        changed = true;
        break;
      }
      uint8_t channel_mode = a2dp_offload.codec_info[0] & A2DP_SBC_IE_CH_MD_MSK;
      switch (channel_mode) {
        case A2DP_SBC_IE_CH_MD_JOINT:
          if(sbc_config.channelMode != SbcChannelMode::JOINT_STEREO) {
            changed = true;
          }
          break;
        case A2DP_SBC_IE_CH_MD_STEREO:
          if(sbc_config.channelMode != SbcChannelMode::STEREO) {
            changed = true;
          }
          break;
        case A2DP_SBC_IE_CH_MD_DUAL:
          if(sbc_config.channelMode != SbcChannelMode::DUAL) {
            changed = true;
          }
          break;
        case A2DP_SBC_IE_CH_MD_MONO:
          if(sbc_config.channelMode != SbcChannelMode::MONO) {
            changed = true;
          }
          break;
        default:
          LOG(ERROR) << __func__
                     << ": Unknown SBC channel_mode=" << channel_mode;
          break;
      }
      break;
    }
    case BTAV_A2DP_CODEC_INDEX_SOURCE_AAC:
      [[fallthrough]];
    case BTAV_A2DP_CODEC_INDEX_SINK_AAC: {
      if(codec_config->codecType != CodecType::AAC) {
        changed = true;
        break;
      }
      AacConfiguration aac_config = codec_config->config.get<CodecConfiguration::CodecSpecific::aacConfig>();
      if(aac_config.sampleRateHz != A2dpCodecToHalSampleRate(current_codec)){
        changed = true;
        break;
      }
      if(aac_config.channelMode != A2dpCodecToHalChannelMode
                                    (current_codec)) {
        changed = true;
        break;
      }
      if(aac_config.bitsPerSample !=
          A2dpCodecToHalBitsPerSample(current_codec)) {
        changed = true;
        break;
      }
      break;
    }
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX:
      [[fallthrough]];
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_HD: {
      if (current_codec.codec_type == BTAV_A2DP_CODEC_INDEX_SOURCE_APTX) {
        if(codec_config->codecType != CodecType::APTX) {
          changed = true;
          break;
        }
      } else {
        if(codec_config->codecType != CodecType::APTX_HD) {
          changed = true;
          break;
        }
      }
      AptxConfiguration aptx_config = codec_config->config.get<CodecConfiguration::CodecSpecific::aptxConfig>();
      if(aptx_config.sampleRateHz !=
             A2dpCodecToHalSampleRate(current_codec)) {
        changed = true;
        break;
      }
      if(aptx_config.channelMode !=
          A2dpCodecToHalChannelMode(current_codec)) {
        changed = true;
        break;
      }
      if(aptx_config.bitsPerSample !=
          A2dpCodecToHalBitsPerSample(current_codec)) {
        changed = true;
        break;
      }
      break;
    }
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_ADAPTIVE: {
      //tA2DP_APTX_ADAPTIVE_CIE adaptive_cie;
      if(codec_config->codecType != CodecType::APTX_ADAPTIVE) {
        changed = true;
        break;
      }
      AptxAdaptiveConfiguration aptx_adaptive_config = codec_config->config.get<CodecConfiguration::CodecSpecific::aptxAdaptiveConfig>();
      if(aptx_adaptive_config.sampleRateHz !=
                A2dpCodecToHalSampleRate(current_codec)) {
        changed = true;
        break;
      }
      if(aptx_adaptive_config.bitsPerSample !=
          A2dpCodecToHalBitsPerSample(current_codec)) {
        changed = true;
        break;
      }
      if(aptx_adaptive_config.channelMode !=
		AptxAdaptiveCodecToHalChannelMode(current_codec)) {
        changed = true;
        break;
      }
      break;
    }
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LDAC: {
      if(codec_config->codecType != CodecType::LDAC) {
        changed = true;
        break;
      }
      LdacConfiguration ldac_config = codec_config->config.get<CodecConfiguration::CodecSpecific::ldacConfig>();
      if(ldac_config.sampleRateHz !=
           A2dpCodecToHalSampleRate(current_codec)) {
        changed = true;
        break;
      }

      if(ldac_config.bitsPerSample !=
          A2dpCodecToHalBitsPerSample(current_codec)) {
        changed = true;
        break;
      }
      switch (a2dp_offload.codec_info[6]) {
        case A2DP_LDAC_QUALITY_HIGH:
        case A2DP_LDAC_QUALITY_MID:
        case A2DP_LDAC_QUALITY_LOW:
        case A2DP_LDAC_QUALITY_ABR_OFFLOAD:
          if (ldac_config.qualityIndex != a2dp_codec_to_hal_ldac_quality_index(current_codec)) {
            changed = true;
          }
          break;
        default:
          LOG(ERROR) << __func__ << ": Unknown LDAC quality index="
                     << a2dp_offload.codec_info[6];
          break;
      }
      switch (a2dp_offload.codec_info[7]) {
        case A2DP_LDAC_CHANNEL_MODE_STEREO:
          if(ldac_config.channelMode != LdacChannelMode::STEREO) {
            changed = true;
          }
          break;
        case A2DP_LDAC_CHANNEL_MODE_DUAL:
          if(ldac_config.channelMode != LdacChannelMode::DUAL) {
            changed = true;
          }
          break;
        case A2DP_LDAC_CHANNEL_MODE_MONO:
          if(ldac_config.channelMode != LdacChannelMode::MONO) {
            changed = true;
          }
          break;
        default:
          LOG(ERROR) << __func__ << ": Unknown LDAC channel_mode="
                     << a2dp_offload.codec_info[7];
          break;
      }
      break;
    } /*
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_TWS: {
      //SampleRate sampleRate;
      //ChannelMode channelMode;
      //uint8_t syncMode;
      if(codec_config->codecType != CodecType_2_1::APTX_TWS) {
        changed = true;
        break;
      }
      auto aptx_tws_config = codec_config->config.aptxTwsConfig;
      if(aptx_tws_config.sampleRate !=
               A2dpCodecToHalSampleRate(current_codec)) {
        changed = true;
        break;
      }
      if(aptx_tws_config.channelMode !=
                A2dpCodecToHalChannelMode(current_codec)) {
        changed = true;
        break;
      }
      break;
    }*/
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LHDCV2:
      [[fallthrough]];
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LHDCV3:
      [[fallthrough]];
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LHDCV5:
      changed = true;
      LOG(ERROR) << __func__
                 << ": Consider changed to LHDC from " << (int) codec_config->codecType;
      break;
    case BTAV_A2DP_CODEC_INDEX_MAX:
      [[fallthrough]];
    default:
      LOG(ERROR) << __func__
                 << ": Unknown codec_type=" << current_codec.codec_type;
      break;
  }
  return changed;
}

bool a2dp_is_audio_pcm_config_params_changed_aidl(PcmConfiguration* pcm_config,
                                                                    A2dpCodecConfig* a2dp_config) {
  if (pcm_config == nullptr) return false;
  //A2dpCodecConfig* a2dp_codec_configs = bta_av_get_a2dp_current_codec();
  if (a2dp_config == nullptr) {
    LOG(WARNING) << __func__ << ": failure to get A2DP codec config";
    *pcm_config = BluetoothAudioClientInterface::
        kInvalidPcmConfiguration;
    return false;
  }

  btav_a2dp_codec_config_t current_codec = a2dp_config->getCodecConfig();
  if((pcm_config->sampleRateHz != A2dpCodecToHalSampleRate(current_codec)) ||
     (pcm_config->bitsPerSample !=
          A2dpCodecToHalBitsPerSample(current_codec)) ||
     (pcm_config->channelMode !=
          A2dpCodecToHalChannelMode(current_codec))) {
    return true;
  }
  return false;
}

bool A2dpSbcToHalConfig(CodecConfiguration* codec_config,
                        A2dpCodecConfig* a2dp_config) {
  btav_a2dp_codec_config_t current_codec = a2dp_config->getCodecConfig();
  if (current_codec.codec_type != BTAV_A2DP_CODEC_INDEX_SOURCE_SBC &&
      current_codec.codec_type != BTAV_A2DP_CODEC_INDEX_SINK_SBC) {
    return false;
  }
  tBT_A2DP_OFFLOAD a2dp_offload;
  a2dp_config->getCodecSpecificConfig(&a2dp_offload);
  codec_config->codecType = CodecType::SBC;
  SbcConfiguration sbc_config = {};
  sbc_config.sampleRateHz = A2dpCodecToHalSampleRate(current_codec);
  if (sbc_config.sampleRateHz <= 0) {
    LOG(ERROR) << __func__
               << ": Unknown SBC sample_rate=" << current_codec.sample_rate;
    return false;
  }
  uint8_t channel_mode = a2dp_offload.codec_info[0] & A2DP_SBC_IE_CH_MD_MSK;
  switch (channel_mode) {
    case A2DP_SBC_IE_CH_MD_JOINT:
      sbc_config.channelMode = SbcChannelMode::JOINT_STEREO;
      break;
    case A2DP_SBC_IE_CH_MD_STEREO:
      sbc_config.channelMode = SbcChannelMode::STEREO;
      break;
    case A2DP_SBC_IE_CH_MD_DUAL:
      sbc_config.channelMode = SbcChannelMode::DUAL;
      break;
    case A2DP_SBC_IE_CH_MD_MONO:
      sbc_config.channelMode = SbcChannelMode::MONO;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown SBC channel_mode=" << channel_mode;
      sbc_config.channelMode = SbcChannelMode::UNKNOWN;
      return false;
  }
  uint8_t block_length = a2dp_offload.codec_info[1] & A2DP_SBC_IE_BLOCKS_MSK;
  switch (block_length) {
    case A2DP_SBC_IE_BLOCKS_4:
      sbc_config.blockLength = 4;
      break;
    case A2DP_SBC_IE_BLOCKS_8:
      sbc_config.blockLength = 8;
      break;
    case A2DP_SBC_IE_BLOCKS_12:
      sbc_config.blockLength = 12;
      break;
    case A2DP_SBC_IE_BLOCKS_16:
      sbc_config.blockLength = 16;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown SBC block_length=" << block_length;
      return false;
  }
  uint8_t sub_bands = a2dp_offload.codec_info[1] & A2DP_SBC_IE_SUBBAND_MSK;
  switch (sub_bands) {
    case A2DP_SBC_IE_SUBBAND_4:
      sbc_config.numSubbands = 4;
      break;
    case A2DP_SBC_IE_SUBBAND_8:
      sbc_config.numSubbands = 8;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown SBC Subbands=" << sub_bands;
      return false;
  }
  uint8_t alloc_method = a2dp_offload.codec_info[1] & A2DP_SBC_IE_ALLOC_MD_MSK;
  switch (alloc_method) {
    case A2DP_SBC_IE_ALLOC_MD_S:
      sbc_config.allocMethod = SbcAllocMethod::ALLOC_MD_S;
      break;
    case A2DP_SBC_IE_ALLOC_MD_L:
      sbc_config.allocMethod = SbcAllocMethod::ALLOC_MD_L;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown SBC alloc_method=" << alloc_method;
      return false;
  }
  sbc_config.minBitpool = a2dp_offload.codec_info[2];
  sbc_config.maxBitpool = a2dp_offload.codec_info[3];
  sbc_config.bitsPerSample = A2dpCodecToHalBitsPerSample(current_codec);
  if (sbc_config.bitsPerSample <= 0) {
    LOG(ERROR) << __func__ << ": Unknown SBC bits_per_sample="
               << current_codec.bits_per_sample;
    return false;
  }
  codec_config->config.set<CodecConfiguration::CodecSpecific::sbcConfig>(
      sbc_config);
  return true;
}

bool A2dpAacToHalConfig(CodecConfiguration* codec_config,
                        A2dpCodecConfig* a2dp_config) {
  btav_a2dp_codec_config_t current_codec = a2dp_config->getCodecConfig();
  if (current_codec.codec_type != BTAV_A2DP_CODEC_INDEX_SOURCE_AAC &&
      current_codec.codec_type != BTAV_A2DP_CODEC_INDEX_SINK_AAC) {
    return false;
  }
  tBT_A2DP_OFFLOAD a2dp_offload;
  a2dp_config->getCodecSpecificConfig(&a2dp_offload);
  codec_config->codecType = CodecType::AAC;
  AacConfiguration aac_config = {};
  uint8_t object_type = a2dp_offload.codec_info[0];
  switch (object_type) {
    case A2DP_AAC_OBJECT_TYPE_MPEG2_LC:
      aac_config.objectType = AacObjectType::MPEG2_LC;
      break;
    case A2DP_AAC_OBJECT_TYPE_MPEG4_LC:
      aac_config.objectType = AacObjectType::MPEG4_LC;
      break;
    case A2DP_AAC_OBJECT_TYPE_MPEG4_LTP:
      aac_config.objectType = AacObjectType::MPEG4_LTP;
      break;
    case A2DP_AAC_OBJECT_TYPE_MPEG4_SCALABLE:
      aac_config.objectType = AacObjectType::MPEG4_SCALABLE;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown AAC object_type=" << +object_type;
      return false;
  }
  aac_config.sampleRateHz = A2dpCodecToHalSampleRate(current_codec);
  if (aac_config.sampleRateHz <= 0) {
    LOG(ERROR) << __func__
               << ": Unknown AAC sample_rate=" << current_codec.sample_rate;
    return false;
  }
  aac_config.channelMode = A2dpCodecToHalChannelMode(current_codec);
  if (aac_config.channelMode == ChannelMode::UNKNOWN) {
    LOG(ERROR) << __func__
               << ": Unknown AAC channel_mode=" << current_codec.channel_mode;
    return false;
  }
  uint8_t vbr_enabled =
      a2dp_offload.codec_info[1] & A2DP_AAC_VARIABLE_BIT_RATE_MASK;
  switch (vbr_enabled) {
    case A2DP_AAC_VARIABLE_BIT_RATE_ENABLED:
      aac_config.variableBitRateEnabled = true;
      break;
    case A2DP_AAC_VARIABLE_BIT_RATE_DISABLED:
      aac_config.variableBitRateEnabled = false;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown AAC VBR=" << +vbr_enabled;
      return false;
  }
  aac_config.bitsPerSample = A2dpCodecToHalBitsPerSample(current_codec);
  if (aac_config.bitsPerSample <= 0) {
    LOG(ERROR) << __func__ << ": Unknown AAC bits_per_sample="
               << current_codec.bits_per_sample;
    return false;
  }
  codec_config->config.set<CodecConfiguration::CodecSpecific::aacConfig>(
      aac_config);
  return true;
}

bool A2dpAptxToHalConfig(CodecConfiguration* codec_config,
                         A2dpCodecConfig* a2dp_config) {
  btav_a2dp_codec_config_t current_codec = a2dp_config->getCodecConfig();
  if (current_codec.codec_type != BTAV_A2DP_CODEC_INDEX_SOURCE_APTX &&
      current_codec.codec_type != BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_HD) {
    return false;
  }
  tBT_A2DP_OFFLOAD a2dp_offload;
  a2dp_config->getCodecSpecificConfig(&a2dp_offload);
  if (current_codec.codec_type == BTAV_A2DP_CODEC_INDEX_SOURCE_APTX) {
    codec_config->codecType = CodecType::APTX;
  } else {
    codec_config->codecType = CodecType::APTX_HD;
  }
  AptxConfiguration aptx_config = {};
  aptx_config.sampleRateHz = A2dpCodecToHalSampleRate(current_codec);
  if (aptx_config.sampleRateHz <= 0) {
    LOG(ERROR) << __func__
               << ": Unknown aptX sample_rate=" << current_codec.sample_rate;
    return false;
  }
  aptx_config.channelMode = A2dpCodecToHalChannelMode(current_codec);
  if (aptx_config.channelMode == ChannelMode::UNKNOWN) {
    LOG(ERROR) << __func__
               << ": Unknown aptX channel_mode=" << current_codec.channel_mode;
    return false;
  }
  aptx_config.bitsPerSample = A2dpCodecToHalBitsPerSample(current_codec);
  if (aptx_config.bitsPerSample <= 0) {
    LOG(ERROR) << __func__ << ": Unknown aptX bits_per_sample="
               << current_codec.bits_per_sample;
    return false;
  }
  codec_config->config.set<CodecConfiguration::CodecSpecific::aptxConfig>(
      aptx_config);
  return true;
}

bool A2dpLdacToHalConfig(CodecConfiguration* codec_config,
                         A2dpCodecConfig* a2dp_config) {
  btav_a2dp_codec_config_t current_codec = a2dp_config->getCodecConfig();
  if (current_codec.codec_type != BTAV_A2DP_CODEC_INDEX_SOURCE_LDAC) {
    return false;
  }
  tBT_A2DP_OFFLOAD a2dp_offload;
  a2dp_config->getCodecSpecificConfig(&a2dp_offload);
  codec_config->codecType = CodecType::LDAC;
  LdacConfiguration ldac_config = {};
  ldac_config.sampleRateHz = A2dpCodecToHalSampleRate(current_codec);
  if (ldac_config.sampleRateHz <= 0) {
    LOG(ERROR) << __func__
               << ": Unknown LDAC sample_rate=" << current_codec.sample_rate;
    return false;
  }
  switch (a2dp_offload.codec_info[7]) {
    case A2DP_LDAC_CHANNEL_MODE_STEREO:
      ldac_config.channelMode = LdacChannelMode::STEREO;
      break;
    case A2DP_LDAC_CHANNEL_MODE_DUAL:
      ldac_config.channelMode = LdacChannelMode::DUAL;
      break;
    case A2DP_LDAC_CHANNEL_MODE_MONO:
      ldac_config.channelMode = LdacChannelMode::MONO;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown LDAC channel_mode="
                 << a2dp_offload.codec_info[7];
      ldac_config.channelMode = LdacChannelMode::UNKNOWN;
      return false;
  }
  switch (a2dp_offload.codec_info[6]) {
    case A2DP_LDAC_QUALITY_HIGH:
      ldac_config.qualityIndex = LdacQualityIndex::HIGH;
      break;
    case A2DP_LDAC_QUALITY_MID:
      ldac_config.qualityIndex = LdacQualityIndex::MID;
      break;
    case A2DP_LDAC_QUALITY_LOW:
      ldac_config.qualityIndex = LdacQualityIndex::LOW;
      break;
    case A2DP_LDAC_QUALITY_ABR_OFFLOAD:
      ldac_config.qualityIndex = LdacQualityIndex::ABR;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown LDAC QualityIndex="
                 << a2dp_offload.codec_info[6];
      return false;
  }
  ldac_config.bitsPerSample = A2dpCodecToHalBitsPerSample(current_codec);
  if (ldac_config.bitsPerSample <= 0) {
    LOG(ERROR) << __func__ << ": Unknown LDAC bits_per_sample="
               << current_codec.bits_per_sample;
    return false;
  }
  codec_config->config.set<CodecConfiguration::CodecSpecific::ldacConfig>(
      ldac_config);
  return true;
}

bool A2dpAptxAdaptiveToHalConfig(CodecConfiguration* codec_config,
                         A2dpCodecConfig* a2dp_config) {
  btav_a2dp_codec_config_t current_codec = a2dp_config->getCodecConfig();
  if (current_codec.codec_type != BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_ADAPTIVE) {
    return false;
  }
  tBT_A2DP_OFFLOAD a2dp_offload;
  uint8_t p_codec_info[AVDT_CODEC_SIZE];
  memset(p_codec_info, 0, AVDT_CODEC_SIZE);
  if (!a2dp_config->copyOutOtaCodecConfig(p_codec_info))
  {
    LOG(ERROR) << "No valid codec config";
    return false;
  }
  tA2DP_APTX_ADAPTIVE_CIE adaptive_cie;
  a2dp_config->getCodecSpecificConfig(&a2dp_offload);

  codec_config->codecType = CodecType::APTX_ADAPTIVE;
  AptxAdaptiveConfiguration aptxAdaptiveConfig = {};
  aptxAdaptiveConfig.sampleRateHz = A2dpCodecToHalSampleRate(current_codec);
  if (aptxAdaptiveConfig.sampleRateHz <= 0) {
    LOG(ERROR) << __func__ << ": Unknown AptxAdaptive sample_rate="
               << current_codec.sample_rate;
    return false;
  }

  LOG(ERROR) << __func__ << ": done with sample rate";
  aptxAdaptiveConfig.bitsPerSample =
      A2dpCodecToHalBitsPerSample(current_codec);
  if (aptxAdaptiveConfig.bitsPerSample <= 0) {
    LOG(ERROR) << __func__ << ": Unknown aptX adaptive bits_per_sample="
               << current_codec.bits_per_sample;
    return false;
  }
  if(!A2DP_GetAptxAdaptiveCIE(p_codec_info, &adaptive_cie)) { //phani
    LOG(ERROR) << __func__ << ": Unable to get Aptx Adaptive CIE";
    return false;
  }

  aptxAdaptiveConfig.channelMode =  AptxAdaptiveCodecToHalChannelMode(current_codec);
  if (aptxAdaptiveConfig.channelMode >=
             AptxAdaptiveChannelMode::UNKNOWN) {
    LOG(ERROR) << __func__ << ": Unknown aptX adaptive channel_mode=";
    return false;
  }
  aptxAdaptiveConfig.aptxMode = static_cast<AptxMode>
                        (btif_av_get_aptx_mode_info());
  aptxAdaptiveConfig.sinkBufferingMs = { 20, 50, 20, 50, 20, 50 };
  aptxAdaptiveConfig.ttp =
  {
    static_cast<int8_t> (adaptive_cie.aptx_data.ttp_ll_0 - 128),
    static_cast<int8_t> (adaptive_cie.aptx_data.ttp_ll_1 - 128),
    static_cast<int8_t> (adaptive_cie.aptx_data.ttp_hq_0 - 128),
    static_cast<int8_t> (adaptive_cie.aptx_data.ttp_hq_1 - 128),
    static_cast<int8_t> (adaptive_cie.aptx_data.ttp_tws_0 - 128),
    static_cast<int8_t> (adaptive_cie.aptx_data.ttp_tws_1 - 128)
  };

  if (btif_av_current_device_is_tws()) {
    aptxAdaptiveConfig.inputMode = (AptxAdaptiveInputMode)1;
  } else {
    aptxAdaptiveConfig.inputMode = (AptxAdaptiveInputMode)0;
  }

  aptxAdaptiveConfig.inputFadeDurationMs = 0xff;

  aptxAdaptiveConfig.aptxAdaptiveConfigStream = {
    adaptive_cie.aptx_data.cap_ext_ver_num,
    static_cast<uint8_t> (adaptive_cie.aptx_data.aptx_adaptive_sup_features & 0x000000FF),
    (uint8_t) ((adaptive_cie.aptx_data.aptx_adaptive_sup_features & 0x0000FF00) >> 8),
    (uint8_t) ((adaptive_cie.aptx_data.aptx_adaptive_sup_features & 0x00FF0000) >> 16),
    (uint8_t) ((adaptive_cie.aptx_data.aptx_adaptive_sup_features & 0xFF000000) >> 24),
    adaptive_cie.aptx_data.first_setup_pref,
    adaptive_cie.aptx_data.second_setup_pref,
    adaptive_cie.aptx_data.third_setup_pref,
    adaptive_cie.aptx_data.fourth_setup_pref,
    adaptive_cie.aptx_data.eoc0,
    adaptive_cie.aptx_data.eoc1
  };

  codec_config->config.set<CodecConfiguration::CodecSpecific::aptxAdaptiveConfig>(
     aptxAdaptiveConfig);
  return true;
}

// Savitech Patch - START (non-Offload only)
bool A2dpLhdcv5ToHalConfig(CodecConfiguration* codec_config,
                           A2dpCodecConfig* a2dp_config) {
  return true;
}

bool UpdateOffloadingCapabilities(
    const std::vector<btav_a2dp_codec_config_t>& framework_preference) {
  audio_hal_capabilities =
      BluetoothAudioSinkClientInterface::GetAudioCapabilities(
          SessionType::A2DP_HARDWARE_OFFLOAD_ENCODING_DATAPATH);
  std::unordered_set<CodecType> codec_type_set;
  for (auto preference : framework_preference) {
    switch (preference.codec_type) {
      case BTAV_A2DP_CODEC_INDEX_SOURCE_SBC:
        codec_type_set.insert(CodecType::SBC);
        break;
      case BTAV_A2DP_CODEC_INDEX_SOURCE_AAC:
        codec_type_set.insert(CodecType::AAC);
        break;
      case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX:
        codec_type_set.insert(CodecType::APTX);
        break;
      case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_HD:
        codec_type_set.insert(CodecType::APTX_HD);
        break;
      case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_ADAPTIVE:
        codec_type_set.insert(CodecType::APTX_ADAPTIVE);
        break;
      case BTAV_A2DP_CODEC_INDEX_SOURCE_LDAC:
        codec_type_set.insert(CodecType::LDAC);
        break;
      case BTAV_A2DP_CODEC_INDEX_SINK_SBC:
        [[fallthrough]];
      case BTAV_A2DP_CODEC_INDEX_SINK_AAC:
        [[fallthrough]];
      case BTAV_A2DP_CODEC_INDEX_SINK_LDAC:
        LOG(WARNING) << __func__
                     << ": Ignore sink codec_type=" << preference.codec_type;
        break;
      case BTAV_A2DP_CODEC_INDEX_MAX:
        [[fallthrough]];
      default:
        LOG(ERROR) << __func__
                   << ": Unknown codec_type=" << preference.codec_type;
        break;
    }
  }
  offloading_preference.clear();
  for (auto capability : audio_hal_capabilities) {
    auto codec_type =
        capability.get<AudioCapabilities::a2dpCapabilities>().codecType;
    if (codec_type_set.find(codec_type) != codec_type_set.end()) {
      LOG(INFO) << __func__
                << ": enabled offloading capability=" << capability.toString();
      offloading_preference.push_back(capability);
    } else {
      LOG(INFO) << __func__
                << ": disabled offloading capability=" << capability.toString();
    }
  }
  // TODO: Bluetooth SoC and runtime property
  return true;
}

/***
 * Check whether this codec is supported by the audio HAL and is allowed to
 * use by prefernece of framework / Bluetooth SoC / runtime property.
 ***/
bool IsCodecOffloadingEnabled(const CodecConfiguration& codec_config) {
  for (auto preference : offloading_preference) {
    if (codec_config.codecType !=
        preference.get<AudioCapabilities::a2dpCapabilities>().codecType) {
      continue;
    }
    auto codec_capability =
        preference.get<AudioCapabilities::a2dpCapabilities>();
    switch (codec_capability.codecType) {
      case CodecType::SBC: {
        auto sbc_capability =
            codec_capability.capabilities
                .get<CodecCapabilities::Capabilities::sbcCapabilities>();
        auto sbc_config =
            codec_config.config
                .get<CodecConfiguration::CodecSpecific::sbcConfig>();
        return sbc_offloading_capability_match(sbc_capability, sbc_config);
      }
      case CodecType::AAC: {
        auto aac_capability =
            codec_capability.capabilities
                .get<CodecCapabilities::Capabilities::aacCapabilities>();
        auto aac_config =
            codec_config.config
                .get<CodecConfiguration::CodecSpecific::aacConfig>();
        return aac_offloading_capability_match(aac_capability, aac_config);
      }
      case CodecType::APTX:
        [[fallthrough]];
      case CodecType::APTX_HD: {
        auto aptx_capability =
            codec_capability.capabilities
                .get<CodecCapabilities::Capabilities::aptxCapabilities>();
        auto aptx_config =
            codec_config.config
                .get<CodecConfiguration::CodecSpecific::aptxConfig>();
        return aptx_offloading_capability_match(aptx_capability, aptx_config);
      }
      case CodecType::LDAC: {
        auto ldac_capability =
            codec_capability.capabilities
                .get<CodecCapabilities::Capabilities::ldacCapabilities>();
        auto ldac_config =
            codec_config.config
                .get<CodecConfiguration::CodecSpecific::ldacConfig>();
        return ldac_offloading_capability_match(ldac_capability, ldac_config);
      }
      case CodecType::APTX_ADAPTIVE: {
        auto aptxAdaptive_capability =
            codec_capability.capabilities
                .get<CodecCapabilities::Capabilities::aptxAdaptiveCapabilities>();
        auto aptxAdaptive_config =
            codec_config.config
                .get<CodecConfiguration::CodecSpecific::aptxAdaptiveConfig>();
        return true;
      }
      case CodecType::UNKNOWN:
        [[fallthrough]];
      default:
        LOG(ERROR) << __func__ << ": Unknown codecType="
                   << toString(codec_capability.codecType);
        return false;
    }
  }
  LOG(INFO) << __func__ << ": software codec=" << codec_config.toString();
  return false;
}

}  // namespace codec
}  // namespace aidl
}  // namespace audio
}  // namespace bluetooth
