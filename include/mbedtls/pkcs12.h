/**
 * \file pkcs12.h
 *
 * \brief PKCS#12 Personal Information Exchange Syntax
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
#ifndef MBEDTLS_PKCS12_H
#define MBEDTLS_PKCS12_H

#include "mbedtls/build_info.h"

#include "mbedtls/md.h"
#include "mbedtls/cipher.h"
#include "mbedtls/asn1.h"

#include <stddef.h>

#define MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA                 -0x1F80

#define MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE            -0x1F00

#define MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT             -0x1E80

#define MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH              -0x1E00

#define MBEDTLS_PKCS12_DERIVE_KEY       1
#define MBEDTLS_PKCS12_DERIVE_IV        2
#define MBEDTLS_PKCS12_DERIVE_MAC_KEY   3

#define MBEDTLS_PKCS12_PBE_DECRYPT      0
#define MBEDTLS_PKCS12_PBE_ENCRYPT      1

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_ASN1_PARSE_C)

int mbedtls_pkcs12_pbe(mbedtls_asn1_buf *pbe_params, int mode,
                       mbedtls_cipher_type_t cipher_type, mbedtls_md_type_t md_type,
                       const unsigned char *pwd,  size_t pwdlen,
                       const unsigned char *input, size_t len,
                       unsigned char *output);

#endif /* MBEDTLS_ASN1_PARSE_C */

int mbedtls_pkcs12_derivation(unsigned char *data, size_t datalen,
                              const unsigned char *pwd, size_t pwdlen,
                              const unsigned char *salt, size_t saltlen,
                              mbedtls_md_type_t mbedtls_md, int id, int iterations);

#ifdef __cplusplus
}
#endif

#endif /* pkcs12.h */
