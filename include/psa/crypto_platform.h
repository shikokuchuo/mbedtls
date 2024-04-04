/**
 * \file psa/crypto_platform.h
 *
 * \brief PSA cryptography module: Mbed TLS platform definitions
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains platform-dependent type definitions.
 *
 * In implementations with isolation between the application and the
 * cryptography module, implementers should take care to ensure that
 * the definitions that are exposed to applications match what the
 * module implements.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_PLATFORM_H
#define PSA_CRYPTO_PLATFORM_H
#include "mbedtls/private_access.h"

#include "psa/build_info.h"

#include <stdint.h>

#if defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)

typedef int32_t mbedtls_key_owner_id_t;

static inline int mbedtls_key_owner_id_equal(mbedtls_key_owner_id_t id1,
                                             mbedtls_key_owner_id_t id2)
{
    return id1 == id2;
}

#endif /* MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER */

#if defined(MBEDTLS_PSA_CRYPTO_SPM)
#define PSA_CRYPTO_SECURE 1
#include "crypto_spe.h"
#endif // MBEDTLS_PSA_CRYPTO_SPM

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

typedef struct {
    uintptr_t MBEDTLS_PRIVATE(opaque)[2];
} mbedtls_psa_external_random_context_t;
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

#if defined(MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(MBEDTLS_PSA_CRYPTO_C)

typedef uint32_t mbedtls_psa_client_handle_t;
#endif

#endif /* PSA_CRYPTO_PLATFORM_H */
