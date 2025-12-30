/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_INVASIVE_H
#define PSA_CRYPTO_INVASIVE_H

#include "psa/build_info.h"

#include "psa/crypto.h"
#include "common.h"

#include "mbedtls/entropy.h"

#if !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

psa_status_t mbedtls_psa_crypto_configure_entropy_sources(
    void (* entropy_init)(mbedtls_entropy_context *ctx),
    void (* entropy_free)(mbedtls_entropy_context *ctx));
#endif

#if defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_PSA_CRYPTO_C)
psa_status_t psa_mac_key_can_do(
    psa_algorithm_t algorithm,
    psa_key_type_t key_type);

psa_status_t psa_crypto_copy_input(const uint8_t *input, size_t input_len,
                                   uint8_t *input_copy, size_t input_copy_len);

psa_status_t psa_crypto_copy_output(const uint8_t *output_copy, size_t output_copy_len,
                                    uint8_t *output, size_t output_len);

extern void (*psa_input_pre_copy_hook)(const uint8_t *input, size_t input_len);
extern void (*psa_input_post_copy_hook)(const uint8_t *input, size_t input_len);
extern void (*psa_output_pre_copy_hook)(const uint8_t *output, size_t output_len);
extern void (*psa_output_post_copy_hook)(const uint8_t *output, size_t output_len);

#endif

#endif
