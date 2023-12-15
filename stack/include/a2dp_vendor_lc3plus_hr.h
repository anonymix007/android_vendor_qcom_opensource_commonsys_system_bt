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

//
// A2DP Codec API for LC3PLUS_HR
//

#ifndef A2DP_VENDOR_LC3PLUS_HR_H
#define A2DP_VENDOR_LC3PLUS_HR_H

#include "a2dp_codec_api.h"
#include "a2dp_vendor_lc3plus_hr_constants.h"
#include "avdt_api.h"

class A2dpCodecConfigLC3plusHR : public A2dpCodecConfig {
 public:
  A2dpCodecConfigLC3plusHR(btav_a2dp_codec_priority_t codec_priority);
  virtual ~A2dpCodecConfigLC3plusHR();

  bool init() override;
  period_ms_t encoderIntervalMs() const override;
  bool setCodecConfig(const uint8_t* p_peer_codec_info, bool is_capability,
                      uint8_t* p_result_codec_config) override;

 private:
  bool useRtpHeaderMarkerBit() const override;
  bool updateEncoderUserConfig(
      const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params,
      bool* p_restart_input, bool* p_restart_output,
      bool* p_config_updated) override;
  void debug_codec_dump(int fd) override;
};

// Checks whether the codec capabilities contain a valid A2DP LC3plus HR Source
// codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid LC3plus HR
// codec, otherwise false.
bool A2DP_IsVendorSourceCodecValidLC3plusHR(const uint8_t* p_codec_info);

// Checks whether the codec capabilities contain a valid peer A2DP LC3plus HR Sink
// codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid LC3plusHR
// codec, otherwise false.
bool A2DP_IsVendorPeerSinkCodecValidLC3plusHR(const uint8_t* p_codec_info);

// Checks whether the A2DP data packets should contain RTP header.
// |content_protection_enabled| is true if Content Protection is
// enabled. |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP data packets should contain RTP header, otherwise
// false.
bool A2DP_VendorUsesRtpHeaderLC3plusHR(bool content_protection_enabled,
                                  const uint8_t* p_codec_info);

// Gets the A2DP LC3plus HR codec name for a given |p_codec_info|.
const char* A2DP_VendorCodecNameLC3plusHR(const uint8_t* p_codec_info);

// Checks whether two A2DP LC3plus HR codecs |p_codec_info_a| and |p_codec_info_b|
// have the same type.
// Returns true if the two codecs have the same type, otherwise false.
bool A2DP_VendorCodecTypeEqualsLC3plusHR(const uint8_t* p_codec_info_a,
                                    const uint8_t* p_codec_info_b);

// Checks whether two A2DP LC3plus HR codecs |p_codec_info_a| and |p_codec_info_b|
// are exactly the same.
// Returns true if the two codecs are exactly the same, otherwise false.
// If the codec type is not LC3plusHR, the return value is false.
bool A2DP_VendorCodecEqualsLC3plusHR(const uint8_t* p_codec_info_a,
                                const uint8_t* p_codec_info_b);

// Gets the track sample rate value for the A2DP LC3plus HR codec.
// |p_codec_info| is a pointer to the LC3plusHR codec_info to decode.
// Returns the track sample rate on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetTrackSampleRateLC3plusHR(const uint8_t* p_codec_info);

// Gets the track bitrate value for the A2DP LC3plus HR codec.
// |p_codec_info| is a pointer to the LC3plusHR codec_info to decode.
// Returns the track sample rate on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetBitRateLC3plusHR(const uint8_t* p_codec_info);

// Gets the channel count for the A2DP LC3plus HR codec.
// |p_codec_info| is a pointer to the LC3plusHR codec_info to decode.
// Returns the channel count on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetTrackChannelCountLC3plusHR(const uint8_t* p_codec_info);

int A2DP_VendorGetTrackBitsPerSampleLC3plusHR(const uint8_t* p_codec_info);

// Gets the channel mode code for the A2DP LC3plus HR codec.
// The actual value is codec-specific - see |A2DP_LC3plusHR_CHANNEL_MODE_*|.
// |p_codec_info| is a pointer to the LC3plusHR codec_info to decode.
// Returns the channel mode code on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetChannelModeCodeLC3plusHR(const uint8_t* p_codec_info);

// Gets the frame ms for the A2DP LC3plus HR codec.
// |p_codec_info| is a pointer to the LC3plus HR codec_info to decode.
// Returns the channel mode code on success, or -1 if |p_codec_info|
// contains invalid codec information.
float A2DP_VendorGetFrameMsLC3plusHR(const uint8_t* p_codec_info);

// Gets the A2DP LC3plus HR audio data timestamp from an audio packet.
// |p_codec_info| contains the codec information.
// |p_data| contains the audio data.
// The timestamp is stored in |p_timestamp|.
// Returns true on success, otherwise false.
bool A2DP_VendorGetPacketTimestampLC3plusHR(const uint8_t* p_codec_info,
                                       const uint8_t* p_data,
                                       uint32_t* p_timestamp);

// Builds A2DP LC3plus HR codec header for audio data.
// |p_codec_info| contains the codec information.
// |p_buf| contains the audio data.
// |frames_per_packet| is the number of frames in this packet.
// Returns true on success, otherwise false.
bool A2DP_VendorBuildCodecHeaderLC3plusHR(const uint8_t* p_codec_info, BT_HDR* p_buf,
                                     uint16_t frames_per_packet);

// Decodes and displays A2DP LC3plus HR codec info when using |LOG_DEBUG|.
// |p_codec_info| is a pointer to the LC3plusHR codec_info to decode and display.
// Returns true if the codec information is valid, otherwise false.
bool A2DP_VendorDumpCodecInfoLC3plusHR(const uint8_t* p_codec_info);

// Gets the A2DP LC3plus HR encoder interface that can be used to encode and prepare
// A2DP packets for transmission - see |tA2DP_ENCODER_INTERFACE|.
// |p_codec_info| contains the codec information.
// Returns the A2DP LC3plus HR encoder interface if the |p_codec_info| is valid and
// supported, otherwise NULL.
const tA2DP_ENCODER_INTERFACE* A2DP_VendorGetEncoderInterfaceLC3plusHR(
    const uint8_t* p_codec_info);

// Adjusts the A2DP LC3plus HR codec, based on local support and Bluetooth
// specification.
// |p_codec_info| contains the codec information to adjust.
// Returns true if |p_codec_info| is valid and supported, otherwise false.
bool A2DP_VendorAdjustCodecLC3plusHR(uint8_t* p_codec_info);

// Gets the A2DP LC3plus HR Source codec index for a given |p_codec_info|.
// Returns the corresponding |btav_a2dp_codec_index_t| on success,
// otherwise |BTAV_A2DP_CODEC_INDEX_MAX|.
btav_a2dp_codec_index_t A2DP_VendorSourceCodecIndexLC3plusHR(
    const uint8_t* p_codec_info);

// Gets the A2DP LC3plus HR Source codec name.
const char* A2DP_VendorCodecIndexStrLC3plusHR(void);

// Initializes A2DP LC3plus HR Source codec information into |tAVDT_CFG|
// configuration entry pointed by |p_cfg|.
bool A2DP_VendorInitCodecConfigLC3plusHR(tAVDT_CFG* p_cfg);

// Checks peer initiated setconfig with DUT supported config
// and returns proper status.
tA2DP_STATUS A2DP_VendorIsCodecConfigMatchLC3plusHR(const uint8_t* p_codec_info);

#endif  // A2DP_VENDOR_LC3plusHR_H
