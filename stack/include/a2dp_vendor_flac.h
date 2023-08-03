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
// A2DP Codec API for FLAC
//

#ifndef A2DP_VENDOR_FLAC_H
#define A2DP_VENDOR_FLAC_H

#include "a2dp_codec_api.h"
#include "a2dp_vendor_flac_constants.h"
#include "avdt_api.h"

class A2dpCodecConfigFlac : public A2dpCodecConfig {
 public:
  A2dpCodecConfigFlac(btav_a2dp_codec_priority_t codec_priority);
  virtual ~A2dpCodecConfigFlac();

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

// Checks whether the codec capabilities contain a valid A2DP Flac Source
// codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid Flac
// codec, otherwise false.
bool A2DP_IsVendorSourceCodecValidFlac(const uint8_t* p_codec_info);

// Checks whether the codec capabilities contain a valid peer A2DP Flac Sink
// codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid Flac
// codec, otherwise false.
bool A2DP_IsVendorPeerSinkCodecValidFlac(const uint8_t* p_codec_info);

// Checks whether the A2DP data packets should contain RTP header.
// |content_protection_enabled| is true if Content Protection is
// enabled. |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP data packets should contain RTP header, otherwise
// false.
bool A2DP_VendorUsesRtpHeaderFlac(bool content_protection_enabled,
                                  const uint8_t* p_codec_info);

// Gets the A2DP Flac codec name for a given |p_codec_info|.
const char* A2DP_VendorCodecNameFlac(const uint8_t* p_codec_info);

// Checks whether two A2DP Flac codecs |p_codec_info_a| and |p_codec_info_b|
// have the same type.
// Returns true if the two codecs have the same type, otherwise false.
bool A2DP_VendorCodecTypeEqualsFlac(const uint8_t* p_codec_info_a,
                                    const uint8_t* p_codec_info_b);

// Checks whether two A2DP Flac codecs |p_codec_info_a| and |p_codec_info_b|
// are exactly the same.
// Returns true if the two codecs are exactly the same, otherwise false.
// If the codec type is not Flac, the return value is false.
bool A2DP_VendorCodecEqualsFlac(const uint8_t* p_codec_info_a,
                                const uint8_t* p_codec_info_b);

// Gets the track sample rate value for the A2DP Flac codec.
// |p_codec_info| is a pointer to the Flac codec_info to decode.
// Returns the track sample rate on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetTrackSampleRateFlac(const uint8_t* p_codec_info);

// Gets the track bitrate value for the A2DP Flac codec.
// |p_codec_info| is a pointer to the Flac codec_info to decode.
// Returns the track sample rate on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetBitRateFlac(const uint8_t* p_codec_info);

// Gets the channel count for the A2DP Flac codec.
// |p_codec_info| is a pointer to the Flac codec_info to decode.
// Returns the channel count on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetTrackChannelCountFlac(const uint8_t* p_codec_info);

int A2DP_VendorGetTrackBitsPerSampleFlac(const uint8_t* p_codec_info);

// Gets the channel mode code for the A2DP Flac codec.
// The actual value is codec-specific - see |A2DP_Flac_CHANNEL_MODE_*|.
// |p_codec_info| is a pointer to the Flac codec_info to decode.
// Returns the channel mode code on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_VendorGetChannelModeCodeFlac(const uint8_t* p_codec_info);

// Gets the A2DP Flac audio data timestamp from an audio packet.
// |p_codec_info| contains the codec information.
// |p_data| contains the audio data.
// The timestamp is stored in |p_timestamp|.
// Returns true on success, otherwise false.
bool A2DP_VendorGetPacketTimestampFlac(const uint8_t* p_codec_info,
                                       const uint8_t* p_data,
                                       uint32_t* p_timestamp);

// Builds A2DP Flac codec header for audio data.
// |p_codec_info| contains the codec information.
// |p_buf| contains the audio data.
// |frames_per_packet| is the number of frames in this packet.
// Returns true on success, otherwise false.
bool A2DP_VendorBuildCodecHeaderFlac(const uint8_t* p_codec_info, BT_HDR* p_buf,
                                     uint16_t frames_per_packet);

// Decodes and displays A2DP Flac codec info when using |LOG_DEBUG|.
// |p_codec_info| is a pointer to the Flac codec_info to decode and display.
// Returns true if the codec information is valid, otherwise false.
bool A2DP_VendorDumpCodecInfoFlac(const uint8_t* p_codec_info);

// Gets the A2DP Flac encoder interface that can be used to encode and prepare
// A2DP packets for transmission - see |tA2DP_ENCODER_INTERFACE|.
// |p_codec_info| contains the codec information.
// Returns the A2DP Flac encoder interface if the |p_codec_info| is valid and
// supported, otherwise NULL.
const tA2DP_ENCODER_INTERFACE* A2DP_VendorGetEncoderInterfaceFlac(
    const uint8_t* p_codec_info);

// Adjusts the A2DP Flac codec, based on local support and Bluetooth
// specification.
// |p_codec_info| contains the codec information to adjust.
// Returns true if |p_codec_info| is valid and supported, otherwise false.
bool A2DP_VendorAdjustCodecFlac(uint8_t* p_codec_info);

// Gets the A2DP Flac Source codec index for a given |p_codec_info|.
// Returns the corresponding |btav_a2dp_codec_index_t| on success,
// otherwise |BTAV_A2DP_CODEC_INDEX_MAX|.
btav_a2dp_codec_index_t A2DP_VendorSourceCodecIndexFlac(
    const uint8_t* p_codec_info);

// Gets the A2DP Flac Source codec name.
const char* A2DP_VendorCodecIndexStrFlac(void);

// Initializes A2DP Flac Source codec information into |tAVDT_CFG|
// configuration entry pointed by |p_cfg|.
bool A2DP_VendorInitCodecConfigFlac(tAVDT_CFG* p_cfg);

// Checks peer initiated setconfig with DUT supported config
// and returns proper status.
tA2DP_STATUS A2DP_VendorIsCodecConfigMatchFlac(const uint8_t* p_codec_info);

#endif  // A2DP_VENDOR_Flac_H
