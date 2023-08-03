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
// A2DP constants for FLAC codec
//

#ifndef A2DP_VENDOR_FLAC_CONSTANTS_H
#define A2DP_VENDOR_FLAC_CONSTANTS_H

// Length of the FLAC Media Payload header
#define A2DP_FLAC_MPL_HDR_LEN 1

// FLAC Media Payload Header
#define A2DP_FLAC_HDR_F_MSK 0x80
#define A2DP_FLAC_HDR_S_MSK 0x40
#define A2DP_FLAC_HDR_L_MSK 0x20
#define A2DP_FLAC_HDR_NUM_MSK 0x0F

// FLAC codec specific settings
#define A2DP_FLAC_CODEC_LEN 13
// [Octet 0-3] Vendor ID
#define A2DP_FLAC_VENDOR_ID 0x000004A5
// [Octet 4-5] Vendor Specific Codec ID
#define A2DP_FLAC_CODEC_ID 0x0001


// [Octet 6], Sampling Frequency
#define A2DP_FLAC_SAMPLING_FREQ_MASK   0xB
// [Octet 7], Channel Mode
#define A2DP_FLAC_CHANNEL_MODE_MASK    0x3
// [Octet 8], Bits Per Sample
#define A2DP_FLAC_BITS_PER_SAMPLE_MASK 0x3


#define A2DP_FLAC_STEREO_MONO_MASK 0xF
#define A2DP_FLAC_STEREO           0x2
#define A2DP_FLAC_DEFAULT          A2DP_FLAC_STEREO
#define A2DP_FLAC_MONO             0x1



#define A2DP_FLAC_DEFAULT_BLOCK_SIZE  128
#endif  // A2DP_VENDOR_FLAC_CONSTANTS_H
