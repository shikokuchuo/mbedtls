/**
 * \file pkwrite.h
 *
 * \brief Internal defines shared by the PK write module
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_PK_WRITE_H
#define MBEDTLS_PK_WRITE_H

#include "mbedtls/build_info.h"

#include "mbedtls/pk.h"

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_RSA_C)

#define MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES    (38 + 2 * MBEDTLS_MPI_MAX_SIZE)

#define MBEDTLS_MPI_MAX_SIZE_2  (MBEDTLS_MPI_MAX_SIZE / 2 + \
                                 MBEDTLS_MPI_MAX_SIZE % 2)
#define MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES    (47 + 3 * MBEDTLS_MPI_MAX_SIZE \
                                             + 5 * MBEDTLS_MPI_MAX_SIZE_2)

#else /* MBEDTLS_RSA_C */

#define MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES   0
#define MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES   0

#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#define MBEDTLS_PK_MAX_ECC_BYTES   (PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS) > \
                                    MBEDTLS_ECP_MAX_BYTES ? \
                                    PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS) : \
                                    MBEDTLS_ECP_MAX_BYTES)
#else /* MBEDTLS_USE_PSA_CRYPTO */
#define MBEDTLS_PK_MAX_ECC_BYTES   MBEDTLS_ECP_MAX_BYTES
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#define MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES    (30 + 2 * MBEDTLS_PK_MAX_ECC_BYTES)

#define MBEDTLS_PK_ECP_PRV_DER_MAX_BYTES    (29 + 3 * MBEDTLS_PK_MAX_ECC_BYTES)

#else /* MBEDTLS_PK_HAVE_ECC_KEYS */

#define MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES   0
#define MBEDTLS_PK_ECP_PRV_DER_MAX_BYTES   0

#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */
#endif /* MBEDTLS_PK_WRITE_H */
