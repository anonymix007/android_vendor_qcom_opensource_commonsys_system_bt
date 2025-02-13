/*
 * Copyright (c) 2017, The Linux Foundation. All rights reserved.
 * "Not a contribution"
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the
 * disclaimer below) provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

    * Neither the name of The Linux Foundation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE
 * GRANTED BY THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
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

/*
 * Changes from Qualcomm Innovation Center are provided under the following license:
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

/**
 * Vendor Specific A2DP Codecs Support
 */

#define LOG_TAG "a2dp_vendor"
#include <dlfcn.h>
#include "a2dp_vendor.h"
#include "a2dp_vendor_aptx.h"
#include "a2dp_vendor_aptx_hd.h"
#include "a2dp_vendor_ldac.h"
#include "bt_target.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "a2dp_vendor_aptx_tws.h"
#include "a2dp_vendor_aptx_adaptive.h"
#include "a2dp_vendor_aptx_adaptive_constants.h"
#include "a2dp_vendor_lhdcv3.h"
#include "a2dp_vendor_lhdcv3_dec.h"
#include "a2dp_vendor_lhdcv2.h"
#include "a2dp_vendor_lhdcv5.h"

bool A2DP_IsVendorSourceCodecValid(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_IsVendorSourceCodecValidAptx(p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_IsVendorSourceCodecValidAptxHd(p_codec_info);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_IsVendorSourceCodecValidAptxAdaptive(p_codec_info);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_IsVendorSourceCodecValidLdac(p_codec_info);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_IsVendorSourceCodecValidAptxTWS(p_codec_info);
  }
#endif
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_IsVendorSourceCodecValidLhdcV2(p_codec_info);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_IsVendorSourceCodecValidLhdcV3(p_codec_info);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_IsVendorSourceCodecValidLhdcV5(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>

  return false;
}

bool A2DP_IsVendorSinkCodecValid(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return false;
}

bool A2DP_IsVendorPeerSourceCodecValid(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.
  return false;
}

bool A2DP_IsVendorPeerSinkCodecValid(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_IsVendorPeerSinkCodecValidAptx(p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_IsVendorPeerSinkCodecValidAptxHd(p_codec_info);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_IsVendorPeerSinkCodecValidAptxAdaptive(p_codec_info);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_IsVendorPeerSinkCodecValidLdac(p_codec_info);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_IsVendorPeerSinkCodecValidAptxTWS(p_codec_info);
  }
#endif
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_IsVendorPeerSinkCodecValidLhdcV2(p_codec_info);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_IsVendorPeerSinkCodecValidLhdcV3(p_codec_info);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_IsVendorPeerSinkCodecValidLhdcV5(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>

  return false;
}

bool A2DP_IsVendorSinkCodecSupported(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return false;
}

bool A2DP_IsVendorPeerSourceCodecSupported(
    UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id> and peer codec capabilities
  // NOTE: Should be done only for local Sink codecs.

  return false;
}

tA2DP_STATUS A2DP_VendorBuildSrc2SinkConfig(
    UNUSED_ATTR const uint8_t* p_src_cap, UNUSED_ATTR uint8_t* p_pref_cfg) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return A2DP_NS_CODEC_TYPE;
}

uint32_t A2DP_VendorCodecGetVendorId(const uint8_t* p_codec_info) {
  const uint8_t* p = &p_codec_info[A2DP_VENDOR_CODEC_VENDOR_ID_START_IDX];

  uint32_t vendor_id = (p[0] & 0x000000ff) | ((p[1] << 8) & 0x0000ff00) |
                       ((p[2] << 16) & 0x00ff0000) |
                       ((p[3] << 24) & 0xff000000);

  return vendor_id;
}

uint16_t A2DP_VendorCodecGetCodecId(const uint8_t* p_codec_info) {
  const uint8_t* p = &p_codec_info[A2DP_VENDOR_CODEC_CODEC_ID_START_IDX];

  uint16_t codec_id = (p[0] & 0x00ff) | ((p[1] << 8) & 0xff00);

  return codec_id;
}

bool A2DP_VendorUsesRtpHeader(bool content_protection_enabled,
                              const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorUsesRtpHeaderAptx(content_protection_enabled,
                                        p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorUsesRtpHeaderAptxHd(content_protection_enabled,
                                          p_codec_info);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorUsesRtpHeaderAptxHd(content_protection_enabled,
                                          p_codec_info);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorUsesRtpHeaderLdac(content_protection_enabled,
                                        p_codec_info);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorUsesRtpHeaderAptxTWS(content_protection_enabled,
                                          p_codec_info);
  }
#endif
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorUsesRtpHeaderLhdcV2(content_protection_enabled,
                                          p_codec_info);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorUsesRtpHeaderLhdcV3(content_protection_enabled,
                                          p_codec_info);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorUsesRtpHeaderLhdcV5(content_protection_enabled,
                                          p_codec_info);
  }

  // Add checks based on <content_protection_enabled, vendor_id, codec_id>

  return true;
}

const char* A2DP_VendorCodecName(UNUSED_ATTR const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecNameAptx(p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecNameAptxHd(p_codec_info);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecNameAptxAdaptive(p_codec_info);
  }


  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorCodecNameLdac(p_codec_info);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecNameAptxTWS(p_codec_info);
  }
#endif
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorCodecNameLhdcV2(p_codec_info);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorCodecNameLhdcV3(p_codec_info);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorCodecNameLhdcV5(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>

  return "UNKNOWN VENDOR CODEC";
}

bool A2DP_VendorCodecTypeEquals(const uint8_t* p_codec_info_a,
                                const uint8_t* p_codec_info_b) {
  tA2DP_CODEC_TYPE codec_type_a = A2DP_GetCodecType(p_codec_info_a);
  tA2DP_CODEC_TYPE codec_type_b = A2DP_GetCodecType(p_codec_info_b);

  if ((codec_type_a != codec_type_b) ||
      (codec_type_a != A2DP_MEDIA_CT_NON_A2DP)) {
    return false;
  }

  uint32_t vendor_id_a = A2DP_VendorCodecGetVendorId(p_codec_info_a);
  uint16_t codec_id_a = A2DP_VendorCodecGetCodecId(p_codec_info_a);
  uint32_t vendor_id_b = A2DP_VendorCodecGetVendorId(p_codec_info_b);
  uint16_t codec_id_b = A2DP_VendorCodecGetCodecId(p_codec_info_b);

  if (vendor_id_a != vendor_id_b || codec_id_a != codec_id_b) return false;

  // Check for aptX
  if (vendor_id_a == A2DP_APTX_VENDOR_ID &&
      codec_id_a == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecTypeEqualsAptx(p_codec_info_a, p_codec_info_b);
  }

  // Check for aptX-HD
  if (vendor_id_a == A2DP_APTX_HD_VENDOR_ID &&
      codec_id_a == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecTypeEqualsAptxHd(p_codec_info_a, p_codec_info_b);
  }

  // Check for aptX-Adaptive
  if (vendor_id_a == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id_a == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecTypeEqualsAptxAdaptive(p_codec_info_a, p_codec_info_b);
  }

  // Check for LDAC
  if (vendor_id_a == A2DP_LDAC_VENDOR_ID && codec_id_a == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorCodecTypeEqualsLdac(p_codec_info_a, p_codec_info_b);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id_a == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id_a == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecTypeEqualsAptxTWS(p_codec_info_a, p_codec_info_b);
  }
#endif
  // Check for Savitech LHDCV2
  if (vendor_id_a == A2DP_LHDC_VENDOR_ID && codec_id_a == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorCodecTypeEqualsLhdcV2(p_codec_info_a, p_codec_info_b);
  }

  // Check for Savitech LHDCV3
  if (vendor_id_a == A2DP_LHDC_VENDOR_ID && codec_id_a == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorCodecTypeEqualsLhdcV3(p_codec_info_a, p_codec_info_b);
  }

  // Check for Savitech LHDCV5
  if (vendor_id_a == A2DP_LHDC_VENDOR_ID && codec_id_a == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorCodecTypeEqualsLhdcV5(p_codec_info_a, p_codec_info_b);
  }

  // OPTIONAL: Add extra vendor-specific checks based on the
  // vendor-specific data stored in "p_codec_info_a" and "p_codec_info_b".

  return true;
}

bool A2DP_VendorCodecEquals(const uint8_t* p_codec_info_a,
                            const uint8_t* p_codec_info_b) {
  tA2DP_CODEC_TYPE codec_type_a = A2DP_GetCodecType(p_codec_info_a);
  tA2DP_CODEC_TYPE codec_type_b = A2DP_GetCodecType(p_codec_info_b);

  if ((codec_type_a != codec_type_b) ||
      (codec_type_a != A2DP_MEDIA_CT_NON_A2DP)) {
    return false;
  }

  uint32_t vendor_id_a = A2DP_VendorCodecGetVendorId(p_codec_info_a);
  uint16_t codec_id_a = A2DP_VendorCodecGetCodecId(p_codec_info_a);
  uint32_t vendor_id_b = A2DP_VendorCodecGetVendorId(p_codec_info_b);
  uint16_t codec_id_b = A2DP_VendorCodecGetCodecId(p_codec_info_b);

  if ((vendor_id_a != vendor_id_b) || (codec_id_a != codec_id_b)) return false;

  // Check for aptX
  if (vendor_id_a == A2DP_APTX_VENDOR_ID &&
      codec_id_a == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecEqualsAptx(p_codec_info_a, p_codec_info_b);
  }

  // Check for aptX-HD
  if (vendor_id_a == A2DP_APTX_HD_VENDOR_ID &&
      codec_id_a == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecEqualsAptxHd(p_codec_info_a, p_codec_info_b);
  }

  // Check for aptX-Adaptive
  if (vendor_id_a == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id_a == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecEqualsAptxAdaptive(p_codec_info_a, p_codec_info_b);
  }

  // Check for LDAC
  if (vendor_id_a == A2DP_LDAC_VENDOR_ID && codec_id_a == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorCodecEqualsLdac(p_codec_info_a, p_codec_info_b);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id_a == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id_a == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecEqualsAptxTWS(p_codec_info_a, p_codec_info_b);
  }
#endif
  // Check for Savitech LHDCV2
  if (vendor_id_a == A2DP_LHDC_VENDOR_ID && codec_id_a == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorCodecEqualsLhdcV2(p_codec_info_a, p_codec_info_b);
  }

  // Check for Savitech LHDCV3
  if (vendor_id_a == A2DP_LHDC_VENDOR_ID && codec_id_a == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorCodecEqualsLhdcV3(p_codec_info_a, p_codec_info_b);
  }

  // Check for Savitech LHDCV5
  if (vendor_id_a == A2DP_LHDC_VENDOR_ID && codec_id_a == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorCodecEqualsLhdcV5(p_codec_info_a, p_codec_info_b);
  }
  // Add extra vendor-specific checks based on the
  // vendor-specific data stored in "p_codec_info_a" and "p_codec_info_b".

  return false;
}

int A2DP_VendorGetBitRate(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);
  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorGetBitRateLdac(p_codec_info);
  }
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorGetBitRateLhdcV2(p_codec_info);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorGetBitRateLhdcV3(p_codec_info);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorGetBitRateLhdcV5(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>

  return -1;
}

int A2DP_VendorGetTrackSampleRate(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetTrackSampleRateAptx(p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetTrackSampleRateAptxHd(p_codec_info);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetTrackSampleRateAptxAdaptive(p_codec_info);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorGetTrackSampleRateLdac(p_codec_info);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetTrackSampleRateAptxTWS(p_codec_info);
  }
#endif
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorGetTrackSampleRateLhdcV2(p_codec_info);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorGetTrackSampleRateLhdcV3(p_codec_info);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorGetTrackSampleRateLhdcV5(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>

  return -1;
}

int A2DP_VendorGetTrackChannelCount(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetTrackChannelCountAptx(p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetTrackChannelCountAptxHd(p_codec_info);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetTrackChannelCountAptxAdaptive(p_codec_info);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorGetTrackChannelCountLdac(p_codec_info);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetTrackChannelCountAptxTWS(p_codec_info);
  }
#endif

  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorGetTrackChannelCountLhdcV2(p_codec_info);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorGetTrackChannelCountLhdcV3(p_codec_info);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorGetTrackChannelCountLhdcV5(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>

  return -1;
}

int A2DP_VendorGetSinkTrackChannelType(
    UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return -1;
}

int A2DP_VendorGetSinkFramesCountToProcess(
    UNUSED_ATTR uint64_t time_interval_ms,
    UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return -1;
}

bool A2DP_VendorGetPacketTimestamp(const uint8_t* p_codec_info,
                                   const uint8_t* p_data,
                                   uint32_t* p_timestamp) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetPacketTimestampAptx(p_codec_info, p_data, p_timestamp);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetPacketTimestampAptxHd(p_codec_info, p_data,
                                               p_timestamp);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetPacketTimestampAptxAdaptive(p_codec_info, p_data,
                                               p_timestamp);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorGetPacketTimestampLdac(p_codec_info, p_data, p_timestamp);
  }
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorGetPacketTimestampLhdcV2(p_codec_info, p_data, p_timestamp);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorGetPacketTimestampLhdcV3(p_codec_info, p_data, p_timestamp);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorGetPacketTimestampLhdcV5(p_codec_info, p_data, p_timestamp);
  }

  // Add checks based on <vendor_id, codec_id>

  return false;
}

bool A2DP_VendorBuildCodecHeader(const uint8_t* p_codec_info, BT_HDR* p_buf,
                                 uint16_t frames_per_packet) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorBuildCodecHeaderAptx(p_codec_info, p_buf,
                                           frames_per_packet);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorBuildCodecHeaderAptxHd(p_codec_info, p_buf,
                                             frames_per_packet);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorBuildCodecHeaderAptxAdaptive(p_codec_info, p_buf,
                                             frames_per_packet);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorBuildCodecHeaderLdac(p_codec_info, p_buf,
                                           frames_per_packet);
  }

  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorBuildCodecHeaderLhdcV2(p_codec_info, p_buf,
                                               frames_per_packet);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorBuildCodecHeaderLhdcV3(p_codec_info, p_buf,
                                               frames_per_packet);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorBuildCodecHeaderLhdcV5(p_codec_info, p_buf,
                                               frames_per_packet);
  }

  // Add checks based on <vendor_id, codec_id>

  return false;
}

const tA2DP_ENCODER_INTERFACE* A2DP_VendorGetEncoderInterface(
    const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetEncoderInterfaceAptx(p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetEncoderInterfaceAptxHd(p_codec_info);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetEncoderInterfaceAptxAdaptive(p_codec_info);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorGetEncoderInterfaceLdac(p_codec_info);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorGetEncoderInterfaceAptxTWS(p_codec_info);
  }
#endif
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorGetEncoderInterfaceLhdcV2(p_codec_info);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorGetEncoderInterfaceLhdcV3(p_codec_info);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorGetEncoderInterfaceLhdcV5(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>

  return NULL;
}

bool A2DP_VendorAdjustCodec(uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorAdjustCodecAptx(p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorAdjustCodecAptxHd(p_codec_info);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorAdjustCodecAptxAdaptive(p_codec_info);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorAdjustCodecLdac(p_codec_info);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorAdjustCodecAptxTWS(p_codec_info);
  }
#endif
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorAdjustCodecLhdcV2(p_codec_info);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorAdjustCodecLhdcV3(p_codec_info);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorAdjustCodecLhdcV5(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>

  return false;
}

btav_a2dp_codec_index_t A2DP_VendorSourceCodecIndex(
    const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

   LOG_INFO(LOG_TAG,"A2DP_VendorSourceCodecIndex: vendor_id = %d, codec_id = %d", vendor_id, codec_id);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorSourceCodecIndexAptx(p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorSourceCodecIndexAptxHd(p_codec_info);
  }

  // Check for aptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorSourceCodecIndexAptxAdaptive(p_codec_info);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    return A2DP_VendorSourceCodecIndexLdac(p_codec_info);
  }

  // Check for aptX-TWS
#if (TWS_ENABLED == TRUE)
  if (vendor_id == A2DP_APTX_TWS_VENDOR_ID &&
      codec_id == A2DP_APTX_TWS_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorSourceCodecIndexAptxTWS(p_codec_info);
  }
#endif

  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    return A2DP_VendorSourceCodecIndexLhdcV2(p_codec_info);
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    return A2DP_VendorSourceCodecIndexLhdcV3(p_codec_info);
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    return A2DP_VendorSourceCodecIndexLhdcV5(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>

  return BTAV_A2DP_CODEC_INDEX_MAX;
}

const char* A2DP_VendorCodecIndexStr(btav_a2dp_codec_index_t codec_index) {
  // Add checks based on codec_index
  switch (codec_index) {
    case BTAV_A2DP_CODEC_INDEX_SOURCE_SBC:
    case BTAV_A2DP_CODEC_INDEX_SINK_SBC:
    case BTAV_A2DP_CODEC_INDEX_SOURCE_AAC:
	case BTAV_A2DP_CODEC_INDEX_SINK_AAC:
      break;  // These are not vendor-specific codecs
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX:
      return A2DP_VendorCodecIndexStrAptx();
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_HD:
      return A2DP_VendorCodecIndexStrAptxHd();
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_ADAPTIVE:
      return A2DP_VendorCodecIndexStrAptxAdaptive();
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LDAC:
      return A2DP_VendorCodecIndexStrLdac();
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_TWS:
      return A2DP_VendorCodecIndexStrAptxTWS();
    // Savitech Patch - START
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LHDCV2:
      return A2DP_VendorCodecIndexStrLhdcV2();
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LHDCV3:
      return A2DP_VendorCodecIndexStrLhdcV3();
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LHDCV5:
      return A2DP_VendorCodecIndexStrLhdcV5();
    // Savitech Patch - END
    // Add a switch statement for each vendor-specific codec
    case BTAV_A2DP_CODEC_INDEX_MAX:
    default:
      break;
  }

  return "UNKNOWN CODEC INDEX";
}

bool A2DP_VendorInitCodecConfig(btav_a2dp_codec_index_t codec_index,
                                tAVDT_CFG* p_cfg) {
  // Add checks based on codec_index
  switch (codec_index) {
    case BTAV_A2DP_CODEC_INDEX_SOURCE_SBC:
    case BTAV_A2DP_CODEC_INDEX_SINK_SBC:
    case BTAV_A2DP_CODEC_INDEX_SOURCE_AAC:
	case BTAV_A2DP_CODEC_INDEX_SINK_AAC:
      break;  // These are not vendor-specific codecs
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX:
      return A2DP_VendorInitCodecConfigAptx(p_cfg);
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_HD:
      return A2DP_VendorInitCodecConfigAptxHd(p_cfg);
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_ADAPTIVE:
      return A2DP_VendorInitCodecConfigAptxAdaptive(p_cfg);
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LDAC:
      return A2DP_VendorInitCodecConfigLdac(p_cfg);
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_TWS:
      return A2DP_VendorInitCodecConfigAptxTWS(p_cfg);
    // Savitech Patch - START
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LHDCV2:
      return A2DP_VendorInitCodecConfigLhdcV2(p_cfg);
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LHDCV3:
      return A2DP_VendorInitCodecConfigLhdcV3(p_cfg);
    case BTAV_A2DP_CODEC_INDEX_SOURCE_LHDCV5:
      return A2DP_VendorInitCodecConfigLhdcV5(p_cfg);
    // Savitech Patch - END
    // Add a switch statement for each vendor-specific codec
    case BTAV_A2DP_CODEC_INDEX_MAX:
    default:
      break;
  }

  return false;
}

bool A2DP_VendorDumpCodecInfo(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorDumpCodecInfoAptx(p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorDumpCodecInfoAptxHd(p_codec_info);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {

    return A2DP_VendorDumpCodecInfoLdac(p_codec_info);
  }
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    LOG_DEBUG(LOG_TAG, "LHDC : %s", A2DP_VendorCodecInfoStringLhdcV2(p_codec_info).c_str());
    return true;
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    LOG_DEBUG(LOG_TAG, "LHDC : %s", A2DP_VendorCodecInfoStringLhdcV3(p_codec_info).c_str());
    return true;
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    LOG_DEBUG(LOG_TAG, "LHDC : %s", A2DP_VendorCodecInfoStringLhdcV5(p_codec_info).c_str());
    return true;
  }

  // Add checks based on <vendor_id, codec_id>

  return false;
}

tA2DP_STATUS A2DP_VendorIsCodecConfigMatch(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    LOG_DEBUG(LOG_TAG, "%s: checking for Aptx codecConfig match", __func__);
    return A2DP_VendorIsCodecConfigMatchAptx(p_codec_info);
  }

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    LOG_DEBUG(LOG_TAG, "%s: checking for Aptx-HD codecConfig match", __func__);
    return A2DP_VendorIsCodecConfigMatchAptxHd(p_codec_info);
  }

  // Check for LDAC
  if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
    LOG_DEBUG(LOG_TAG, "%s: checking for Ldac codecConfig match", __func__);
    return A2DP_VendorIsCodecConfigMatchLdac(p_codec_info);
  }
  // Check for Savitech LHDCV2
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV2_CODEC_ID) {
    LOG_DEBUG(LOG_TAG, "LHDC : %s", A2DP_VendorCodecInfoStringLhdcV2(p_codec_info).c_str());
    return true;
  }

  // Check for Savitech LHDCV3
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV3_CODEC_ID) {
    LOG_DEBUG(LOG_TAG, "LHDC : %s", A2DP_VendorCodecInfoStringLhdcV3(p_codec_info).c_str());
    return true;
  }

  // Check for Savitech LHDCV5
  if (vendor_id == A2DP_LHDC_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
    LOG_DEBUG(LOG_TAG, "LHDC : %s", A2DP_VendorCodecInfoStringLhdcV5(p_codec_info).c_str());
    return true;
  }

  // Check for AptX-Adaptive
  if (vendor_id == A2DP_APTX_ADAPTIVE_VENDOR_ID &&
      codec_id == A2DP_APTX_ADAPTIVE_CODEC_ID_BLUETOOTH) {
    LOG_DEBUG(LOG_TAG, "%s: checking for Aptx-Adaptive codecConfig match", __func__);
    return A2DP_VendorIsCodecConfigMatchAptxAdaptive(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>

  return false;
}

void* A2DP_VendorCodecLoadExternalLib(const std::string& lib_name,
                                      const std::string& friendly_name) {
  void* lib_handle = dlopen(lib_name.c_str(), RTLD_NOW);
  if (lib_handle == NULL) {
    LOG(ERROR) << __func__
               << ": Failed to load codec library: " << friendly_name
               << ". Err: [" << dlerror() << "]";
    return nullptr;
  }
  LOG(INFO) << __func__ << ": Codec library loaded: " << friendly_name;
  return lib_handle;
}
