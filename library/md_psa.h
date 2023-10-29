/**
 * Translation between MD and PSA identifiers (algorithms, errors).
 *
 *  Note: this internal module will go away when everything becomes based on
 *  PSA Crypto; it is a helper for the transition period.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_MD_PSA_H
#define MBEDTLS_MD_PSA_H

#include "common.h"

#include "mbedtls/md.h"
#include "psa/crypto.h"

static inline psa_algorithm_t mbedtls_md_psa_alg_from_type(mbedtls_md_type_t md_type)
{
    return PSA_ALG_CATEGORY_HASH | (psa_algorithm_t) md_type;
}

static inline mbedtls_md_type_t mbedtls_md_type_from_psa_alg(psa_algorithm_t psa_alg)
{
    return (mbedtls_md_type_t) (psa_alg & PSA_ALG_HASH_MASK);
}

int mbedtls_md_error_from_psa(psa_status_t status);

#endif /* MBEDTLS_MD_PSA_H */
