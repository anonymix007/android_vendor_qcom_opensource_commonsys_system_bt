/*
 * Copyright (C) 2016 The Android Open Source Project
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
// A2DP Codec API for LHDC
//

#ifndef A2DP_VENDOR_LHDCV2_H
#define A2DP_VENDOR_LHDCV2_H

#include "a2dp_codec_api.h"
#include "a2dp_vendor_lhdc_constants.h"
#include "avdt_api.h"


class A2dpCodecConfigLhdcV2 : public A2dpCodecConfig {
 public:
  bool copySinkCapability(uint8_t * codec_info);
  A2dpCodecConfigLhdcV2(btav_a2dp_codec_priority_t codec_priority);
  virtual ~A2dpCodecConfigLhdcV2();

  bool init() override;
  uint64_t encoderIntervalMs() const override;
  int getEffectiveMtu() const;
  bool setCodecConfig(const uint8_t* p_peer_codec_info, bool is_capability,
                      uint8_t* p_result_codec_config) override;
  bool setPeerCodecCapabilities(
      const uint8_t* p_peer_codec_capabilities);


 private:
  bool useRtpHeaderMarkerBit() const override;
  bool updateEncoderUserConfig(
      const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params,
      bool* p_restart_input, bool* p_restart_output,
      bool* p_config_updated) override;
  void debug_codec_dump(int fd) override;
};

bool A2DP_VendorGetLowLatencyEnabledLhdcV2();
// Checks whether the codec capabilities contain a valid A2DP LHDC Source
// codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid LHDC
// codec, otherwise false.
bool A2DP_IsVendorSourceCodecValidLhdcV2(const uint8_t* p_codec_info);

// Checks whether the codec capabilities contain a valid peer A2DP LHDC Sink
// codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid LHDC
// codec, otherwise false.
bool A2DP_IsVendorPeerSinkCodecValidLhdcV2(const uint8_t* p_codec_info);

// Checks whether the A2DP data packets should contain RTP header.
// |content_protection_enabled| is true if Content Protection is
// enabled. |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP data packets should contain RTP header, otherwise
// false.
bool A2DP_VendorUsesRtpHeaderLhdcV2(bool content_protection_enabled,
                                  const uint8_t* p_codec_info);

// Gets the A2DP LHDC codec name for a given |p_codec_info|.
const char* A2DP_VendorCodecNameLhdcV2(const uint8_t* p_codec_info);

// Checks whether two A2DP LHDC codecs |p_codec_info_a| and |p_codec_info_b|
// have the same type.
// Returns true if the two codecs have the same type, otherwise false.
bool A2DP_VendorCodecTypeEqualsLhdcV2(const uint8_t* p_codec_info_a,
                                    const uint8_t* p_codec_info_b);

// Checks whether two A2DP LHDC codecs |p_codec_info_a| and |p_codec_info_b|
// are exactly the same.
// Returns true if the two codecs are exactly the same, otherwise false.
// If the codec type is not LHDC, the return value is false.
bool A2DP_VendorCodecEqualsLhdcV2(const uint8_t* p_codec_info_a,
                                const uint8_t* p_codec_info_b);

// Gets the track sample rate value for the A2DP LHDC codec.
// |p_codec_info| is a pointer to the LHDC codec_info to decode.
// Returns the track sample rate on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetTrackSampleRateLhdcV2(const uint8_t* p_codec_info);

// Gets the bits per audio sample for the A2DP LHDC codec.
// |p_codec_info| is a pointer to the LHDC codec_info to decode.
// Returns the bits per audio sample on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetTrackBitsPerSampleLhdcV2(const uint8_t* p_codec_info);

// Gets the channel count for the A2DP LHDC codec.
// |p_codec_info| is a pointer to the LHDC codec_info to decode.
// Returns the channel count on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetTrackChannelCountLhdcV2(const uint8_t* p_codec_info);

// Gets the channel mode code for the A2DP LHDC codec.
// The actual value is codec-specific - see |A2DP_LHDC_CHANNEL_MODE_*|.
// |p_codec_info| is a pointer to the LHDC codec_info to decode.
// Returns the channel mode code on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetChannelModeCodeLhdcV2(const uint8_t* p_codec_info);

// Gets the A2DP LHDC audio data timestamp from an audio packet.
// |p_codec_info| contains the codec information.
// |p_data| contains the audio data.
// The timestamp is stored in |p_timestamp|.
// Returns true on success, otherwise false.
bool A2DP_VendorGetPacketTimestampLhdcV2(const uint8_t* p_codec_info,
                                       const uint8_t* p_data,
                                       uint32_t* p_timestamp);

// Builds A2DP LHDC codec header for audio data.
// |p_codec_info| contains the codec information.
// |p_buf| contains the audio data.
// |frames_per_packet| is the number of frames in this packet.
// Returns true on success, otherwise false.
bool A2DP_VendorBuildCodecHeaderLhdcV2(const uint8_t* p_codec_info, BT_HDR* p_buf,
                                     uint16_t frames_per_packet);

// Decodes A2DP LHDC codec info into a human readable string.
// |p_codec_info| is a pointer to the LHDC codec_info to decode.
// Returns a string describing the codec information.
std::string A2DP_VendorCodecInfoStringLhdcV2(const uint8_t* p_codec_info);

// New feature to check codec info is supported Channel Separation.
int8_t A2DP_VendorGetChannelSplitModeLhdcV2(const uint8_t* p_codec_info);

bool A2DP_VendorGetLowLatencyStateLhdcV2(const uint8_t* p_codec_info);
int16_t A2DP_VendorGetMaxDatarateLhdcV2(const uint8_t* p_codec_info);
uint8_t A2DP_VendorGetVersionLhdcV2(const uint8_t* p_codec_info);

// Decodes and displays LHDC codec info (for debugging).
// |p_codec_info| is a pointer to the LHDC codec_info to decode and display.
void A2DP_VendorDumpCodecInfoLhdcV2(const uint8_t* p_codec_info);

// Gets the A2DP LHDC encoder interface that can be used to encode and prepare
// A2DP packets for transmission - see |tA2DP_ENCODER_INTERFACE|.
// |p_codec_info| contains the codec information.
// Returns the A2DP LHDC encoder interface if the |p_codec_info| is valid and
// supported, otherwise NULL.
const tA2DP_ENCODER_INTERFACE* A2DP_VendorGetEncoderInterfaceLhdcV2(
    const uint8_t* p_codec_info);

// Adjusts the A2DP LHDC codec, based on local support and Bluetooth
// specification.
// |p_codec_info| contains the codec information to adjust.
// Returns true if |p_codec_info| is valid and supported, otherwise false.
bool A2DP_VendorAdjustCodecLhdcV2(uint8_t* p_codec_info);

// Gets the A2DP LHDC Source codec index for a given |p_codec_info|.
// Returns the corresponding |btav_a2dp_codec_index_t| on success,
// otherwise |BTAV_A2DP_CODEC_INDEX_MAX|.
btav_a2dp_codec_index_t A2DP_VendorSourceCodecIndexLhdcV2(
    const uint8_t* p_codec_info);

// Gets the A2DP LHDC Source codec name.
const char* A2DP_VendorCodecIndexStrLhdcV2(void);

// Initializes A2DP LHDC Source codec information into |tAVDT_CFG|
// configuration entry pointed by |p_cfg|.

bool A2DP_VendorInitCodecConfigLhdcV2(tAVDT_CFG* p_cfg);
// Gets the track bitrate value for the A2DP LHDCV2 codec.
// |p_codec_info| is a pointer to the LHDC codec_info to decode.
// Returns the track bit rate on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetBitRateLhdcV2(const uint8_t* p_codec_info);

#endif  // A2DP_VENDOR_LHDCV2_H
