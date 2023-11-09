/**
 * \file ccm.h
 *
 * \brief This file provides an API for the CCM authenticated encryption
 *        mode for block ciphers.
 *
 * CCM combines Counter mode encryption with CBC-MAC authentication
 * for 128-bit block ciphers.
 *
 * Input to CCM includes the following elements:
 * <ul><li>Payload - data that is both authenticated and encrypted.</li>
 * <li>Associated data (Adata) - data that is authenticated but not
 * encrypted, For example, a header.</li>
 * <li>Nonce - A unique value that is assigned to the payload and the
 * associated data.</li></ul>
 *
 * Definition of CCM:
 * http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
 * RFC 3610 "Counter with CBC-MAC (CCM)"
 *
 * Related:
 * RFC 5116 "An Interface and Algorithms for Authenticated Encryption"
 *
 * Definition of CCM*:
 * IEEE 802.15.4 - IEEE Standard for Local and metropolitan area networks
 * Integer representation is fixed most-significant-octet-first order and
 * the representation of octets is most-significant-bit-first order. This is
 * consistent with RFC 3610.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_CCM_H
#define MBEDTLS_CCM_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/cipher.h"

#define MBEDTLS_CCM_DECRYPT       0
#define MBEDTLS_CCM_ENCRYPT       1
#define MBEDTLS_CCM_STAR_DECRYPT  2
#define MBEDTLS_CCM_STAR_ENCRYPT  3

#define MBEDTLS_ERR_CCM_BAD_INPUT       -0x000D
#define MBEDTLS_ERR_CCM_AUTH_FAILED     -0x000F

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_ccm_context {
    unsigned char MBEDTLS_PRIVATE(y)[16];
    unsigned char MBEDTLS_PRIVATE(ctr)[16];
    size_t MBEDTLS_PRIVATE(plaintext_len);
    size_t MBEDTLS_PRIVATE(add_len);
    size_t MBEDTLS_PRIVATE(tag_len);
    size_t MBEDTLS_PRIVATE(processed);
    unsigned int MBEDTLS_PRIVATE(q);
    unsigned int MBEDTLS_PRIVATE(mode);
    mbedtls_cipher_context_t MBEDTLS_PRIVATE(cipher_ctx);
    int MBEDTLS_PRIVATE(state);
}
mbedtls_ccm_context;

void mbedtls_ccm_init(mbedtls_ccm_context *ctx);

int mbedtls_ccm_setkey(mbedtls_ccm_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits);

void mbedtls_ccm_free(mbedtls_ccm_context *ctx);

int mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context *ctx, size_t length,
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *ad, size_t ad_len,
                                const unsigned char *input, unsigned char *output,
                                unsigned char *tag, size_t tag_len);

int mbedtls_ccm_star_encrypt_and_tag(mbedtls_ccm_context *ctx, size_t length,
                                     const unsigned char *iv, size_t iv_len,
                                     const unsigned char *ad, size_t ad_len,
                                     const unsigned char *input, unsigned char *output,
                                     unsigned char *tag, size_t tag_len);

int mbedtls_ccm_auth_decrypt(mbedtls_ccm_context *ctx, size_t length,
                             const unsigned char *iv, size_t iv_len,
                             const unsigned char *ad, size_t ad_len,
                             const unsigned char *input, unsigned char *output,
                             const unsigned char *tag, size_t tag_len);

int mbedtls_ccm_star_auth_decrypt(mbedtls_ccm_context *ctx, size_t length,
                                  const unsigned char *iv, size_t iv_len,
                                  const unsigned char *ad, size_t ad_len,
                                  const unsigned char *input, unsigned char *output,
                                  const unsigned char *tag, size_t tag_len);

int mbedtls_ccm_starts(mbedtls_ccm_context *ctx,
                       int mode,
                       const unsigned char *iv,
                       size_t iv_len);

int mbedtls_ccm_set_lengths(mbedtls_ccm_context *ctx,
                            size_t total_ad_len,
                            size_t plaintext_len,
                            size_t tag_len);

int mbedtls_ccm_update_ad(mbedtls_ccm_context *ctx,
                          const unsigned char *ad,
                          size_t ad_len);

int mbedtls_ccm_update(mbedtls_ccm_context *ctx,
                       const unsigned char *input, size_t input_len,
                       unsigned char *output, size_t output_size,
                       size_t *output_len);

int mbedtls_ccm_finish(mbedtls_ccm_context *ctx,
                       unsigned char *tag, size_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CCM_H */
