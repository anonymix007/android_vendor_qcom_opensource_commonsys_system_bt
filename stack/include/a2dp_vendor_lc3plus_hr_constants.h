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
// A2DP constants for LC3PLUS_HR codec
//

#ifndef A2DP_VENDOR_LC3PLUS_HR_CONSTANTS_H
#define A2DP_VENDOR_LC3PLUS_HR_CONSTANTS_H

// Length of the LC3PLUS_HR Media Payload header
#define A2DP_LC3PLUS_HR_MPL_HDR_LEN 1

// LC3PLUS_HR Media Payload Header
#define A2DP_LC3PLUS_HR_HDR_F_MSK 0x80
#define A2DP_LC3PLUS_HR_HDR_S_MSK 0x40
#define A2DP_LC3PLUS_HR_HDR_L_MSK 0x20
#define A2DP_LC3PLUS_HR_HDR_NUM_MSK 0x0F

// LC3PLUS_HR codec specific settings
#define A2DP_LC3PLUS_HR_CODEC_LEN 12
// [Octet 0-3] Vendor ID
#define A2DP_LC3PLUS_HR_VENDOR_ID 0x000008A9
// [Octet 4-5] Vendor Specific Codec ID
#define A2DP_LC3PLUS_HR_CODEC_ID 0x0001


// [Octet 6], Frame Durations
#define A2DP_LC3PLUS_HR_FRAME_DURATION_MASK   0xF0
#define A2DP_LC3PLUS_HR_FRAME_DURATION_100_MS 0x40
#define A2DP_LC3PLUS_HR_FRAME_DURATION_050_MS 0x20
#define A2DP_LC3PLUS_HR_FRAME_DURATION_025_MS 0x10

// [Octet 7], Channel Mode
#define A2DP_LC3PLUS_HR_CHANNEL_MODE_MASK    0xC0
#define A2DP_LC3PLUS_HR_CHANNEL_MODE_MONO    0x80
#define A2DP_LC3PLUS_HR_CHANNEL_MODE_STEREO  0x40

// [Octet 8], Sampling Rate (48K)
#define A2DP_LC3PLUS_HR_SAMPLING_RATE_48000   0x0100

// [Octet 9], Sampling Rate (96K)
#define A2DP_LC3PLUS_HR_SAMPLING_RATE_96000   0x0080

#define A2DP_LC3PLUS_HR_SAMPLING_RATE_MASK 0x0180


#endif  // A2DP_VENDOR_LC3PLUS_HR_CONSTANTS_H
