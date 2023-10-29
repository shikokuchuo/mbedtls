/**
 * \file aesce.h
 *
 * \brief Support hardware AES acceleration on Armv8-A processors with
 *        the Armv8-A Cryptographic Extension in AArch64 execution state.
 *
 * \warning These functions are only for internal use by other library
 *          functions; you must not call them directly.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#ifndef MBEDTLS_AESCE_H
#define MBEDTLS_AESCE_H

#include "mbedtls/build_info.h"

#include "mbedtls/aes.h"


#if defined(MBEDTLS_AESCE_C) && defined(MBEDTLS_ARCH_IS_ARM64)

#define MBEDTLS_AESCE_HAVE_CODE

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__linux__) && !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)

extern signed char mbedtls_aesce_has_support_result;

int mbedtls_aesce_has_support_impl(void);

#define MBEDTLS_AESCE_HAS_SUPPORT() (mbedtls_aesce_has_support_result == -1 ? \
                                     mbedtls_aesce_has_support_impl() : \
                                     mbedtls_aesce_has_support_result)

#else /* defined(__linux__) && !defined(MBEDTLS_AES_USE_HARDWARE_ONLY) */

#define MBEDTLS_AESCE_HAS_SUPPORT() 1

#endif /* defined(__linux__) && !defined(MBEDTLS_AES_USE_HARDWARE_ONLY) */

int mbedtls_aesce_crypt_ecb(mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16]);

void mbedtls_aesce_gcm_mult(unsigned char c[16],
                            const unsigned char a[16],
                            const unsigned char b[16]);

void mbedtls_aesce_inverse_key(unsigned char *invkey,
                               const unsigned char *fwdkey,
                               int nr);

int mbedtls_aesce_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             size_t bits);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_AESCE_C && MBEDTLS_ARCH_IS_ARM64 */

#endif /* MBEDTLS_AESCE_H */
