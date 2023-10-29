/**
 * \file cipher_wrap.h
 *
 * \brief Cipher wrappers.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
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
#ifndef MBEDTLS_CIPHER_WRAP_H
#define MBEDTLS_CIPHER_WRAP_H

#include "mbedtls/build_info.h"

#include "mbedtls/cipher.h"

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#ifdef __cplusplus
extern "C" {
#endif

struct mbedtls_cipher_base_t {
    mbedtls_cipher_id_t cipher;

    int (*ecb_func)(void *ctx, mbedtls_operation_t mode,
                    const unsigned char *input, unsigned char *output);

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    int (*cbc_func)(void *ctx, mbedtls_operation_t mode, size_t length,
                    unsigned char *iv, const unsigned char *input,
                    unsigned char *output);
#endif

#if defined(MBEDTLS_CIPHER_MODE_CFB)
    int (*cfb_func)(void *ctx, mbedtls_operation_t mode, size_t length, size_t *iv_off,
                    unsigned char *iv, const unsigned char *input,
                    unsigned char *output);
#endif

#if defined(MBEDTLS_CIPHER_MODE_OFB)
    int (*ofb_func)(void *ctx, size_t length, size_t *iv_off,
                    unsigned char *iv,
                    const unsigned char *input,
                    unsigned char *output);
#endif

#if defined(MBEDTLS_CIPHER_MODE_CTR)
    int (*ctr_func)(void *ctx, size_t length, size_t *nc_off,
                    unsigned char *nonce_counter, unsigned char *stream_block,
                    const unsigned char *input, unsigned char *output);
#endif

#if defined(MBEDTLS_CIPHER_MODE_XTS)
    int (*xts_func)(void *ctx, mbedtls_operation_t mode, size_t length,
                    const unsigned char data_unit[16],
                    const unsigned char *input, unsigned char *output);
#endif

#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    int (*stream_func)(void *ctx, size_t length,
                       const unsigned char *input, unsigned char *output);
#endif

    int (*setkey_enc_func)(void *ctx, const unsigned char *key,
                           unsigned int key_bitlen);

    int (*setkey_dec_func)(void *ctx, const unsigned char *key,
                           unsigned int key_bitlen);

    void * (*ctx_alloc_func)(void);

    void (*ctx_free_func)(void *ctx);

};

typedef struct {
    mbedtls_cipher_type_t type;
    const mbedtls_cipher_info_t *info;
} mbedtls_cipher_definition_t;

#if defined(MBEDTLS_USE_PSA_CRYPTO)
typedef enum {
    MBEDTLS_CIPHER_PSA_KEY_UNSET = 0,
    MBEDTLS_CIPHER_PSA_KEY_OWNED,
    MBEDTLS_CIPHER_PSA_KEY_NOT_OWNED,
} mbedtls_cipher_psa_key_ownership;

typedef struct {
    psa_algorithm_t alg;
    mbedtls_svc_key_id_t slot;
    mbedtls_cipher_psa_key_ownership slot_state;
} mbedtls_cipher_context_psa;
#endif /* MBEDTLS_USE_PSA_CRYPTO */

extern const mbedtls_cipher_definition_t mbedtls_cipher_definitions[];

extern int mbedtls_cipher_supported[];

extern const mbedtls_cipher_base_t *mbedtls_cipher_base_lookup_table[];

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CIPHER_WRAP_H */
