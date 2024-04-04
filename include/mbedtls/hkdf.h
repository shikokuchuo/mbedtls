/**
 * \file hkdf.h
 *
 * \brief   This file contains the HKDF interface.
 *
 *          The HMAC-based Extract-and-Expand Key Derivation Function (HKDF) is
 *          specified by RFC 5869.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_HKDF_H
#define MBEDTLS_HKDF_H

#include "mbedtls/build_info.h"

#include "mbedtls/md.h"

#define MBEDTLS_ERR_HKDF_BAD_INPUT_DATA  -0x5F80

#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
                 size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                 const unsigned char *info, size_t info_len,
                 unsigned char *okm, size_t okm_len);

int mbedtls_hkdf_extract(const mbedtls_md_info_t *md,
                         const unsigned char *salt, size_t salt_len,
                         const unsigned char *ikm, size_t ikm_len,
                         unsigned char *prk);

int mbedtls_hkdf_expand(const mbedtls_md_info_t *md, const unsigned char *prk,
                        size_t prk_len, const unsigned char *info,
                        size_t info_len, unsigned char *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* hkdf.h */
