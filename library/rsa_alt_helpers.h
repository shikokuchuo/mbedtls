/**
 * \file rsa_alt_helpers.h
 *
 * \brief Context-independent RSA helper functions
 *
 *  This module declares some RSA-related helper functions useful when
 *  implementing the RSA interface. These functions are provided in a separate
 *  compilation unit in order to make it easy for designers of alternative RSA
 *  implementations to use them in their own code, as it is conceived that the
 *  functionality they provide will be necessary for most complete
 *  implementations.
 *
 *  End-users of Mbed TLS who are not providing their own alternative RSA
 *  implementations should not use these functions directly, and should instead
 *  use only the functions declared in rsa.h.
 *
 *  The interface provided by this module will be maintained through LTS (Long
 *  Term Support) branches of Mbed TLS, but may otherwise be subject to change,
 *  and must be considered an internal interface of the library.
 *
 *  There are two classes of helper functions:
 *
 *  (1) Parameter-generating helpers. These are:
 *      - mbedtls_rsa_deduce_primes
 *      - mbedtls_rsa_deduce_private_exponent
 *      - mbedtls_rsa_deduce_crt
 *       Each of these functions takes a set of core RSA parameters and
 *       generates some other, or CRT related parameters.
 *
 *  (2) Parameter-checking helpers. These are:
 *      - mbedtls_rsa_validate_params
 *      - mbedtls_rsa_validate_crt
 *      They take a set of core or CRT related RSA parameters and check their
 *      validity.
 *
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 */

#ifndef MBEDTLS_RSA_INTERNAL_H
#define MBEDTLS_RSA_INTERNAL_H

#include "mbedtls/build_info.h"

#include "mbedtls/bignum.h"

#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_rsa_deduce_primes(mbedtls_mpi const *N, mbedtls_mpi const *E,
                              mbedtls_mpi const *D,
                              mbedtls_mpi *P, mbedtls_mpi *Q);

int mbedtls_rsa_deduce_private_exponent(mbedtls_mpi const *P,
                                        mbedtls_mpi const *Q,
                                        mbedtls_mpi const *E,
                                        mbedtls_mpi *D);

int mbedtls_rsa_deduce_crt(const mbedtls_mpi *P, const mbedtls_mpi *Q,
                           const mbedtls_mpi *D, mbedtls_mpi *DP,
                           mbedtls_mpi *DQ, mbedtls_mpi *QP);

int mbedtls_rsa_validate_params(const mbedtls_mpi *N, const mbedtls_mpi *P,
                                const mbedtls_mpi *Q, const mbedtls_mpi *D,
                                const mbedtls_mpi *E,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng);

int mbedtls_rsa_validate_crt(const mbedtls_mpi *P,  const mbedtls_mpi *Q,
                             const mbedtls_mpi *D,  const mbedtls_mpi *DP,
                             const mbedtls_mpi *DQ, const mbedtls_mpi *QP);

#ifdef __cplusplus
}
#endif

#endif /* rsa_alt_helpers.h */
