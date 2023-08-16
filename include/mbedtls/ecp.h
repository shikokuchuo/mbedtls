/**
 * \file ecp.h
 *
 * \brief This file provides an API for Elliptic Curves over GF(P) (ECP).
 *
 * The use of ECP in cryptography and TLS is defined in
 * <em>Standards for Efficient Cryptography Group (SECG): SEC1
 * Elliptic Curve Cryptography</em> and
 * <em>RFC-4492: Elliptic Curve Cryptography (ECC) Cipher Suites
 * for Transport Layer Security (TLS)</em>.
 *
 * <em>RFC-2409: The Internet Key Exchange (IKE)</em> defines ECP
 * group types.
 *
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

#ifndef MBEDTLS_ECP_H
#define MBEDTLS_ECP_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/bignum.h"

#define MBEDTLS_ERR_ECP_BAD_INPUT_DATA                    -0x4F80

#define MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL                  -0x4F00

#define MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE               -0x4E80

#define MBEDTLS_ERR_ECP_VERIFY_FAILED                     -0x4E00

#define MBEDTLS_ERR_ECP_ALLOC_FAILED                      -0x4D80

#define MBEDTLS_ERR_ECP_RANDOM_FAILED                     -0x4D00

#define MBEDTLS_ERR_ECP_INVALID_KEY                       -0x4C80

#define MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH                  -0x4C00

#define MBEDTLS_ERR_ECP_IN_PROGRESS                       -0x4B00

#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_BP256R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_BP384R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_BP512R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
#define MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) || \
    defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
#define MBEDTLS_ECP_MONTGOMERY_ENABLED
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MBEDTLS_ECP_DP_NONE = 0,       /*!< Curve not defined. */
    MBEDTLS_ECP_DP_SECP192R1,      /*!< Domain parameters for the 192-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP224R1,      /*!< Domain parameters for the 224-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP256R1,      /*!< Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP384R1,      /*!< Domain parameters for the 384-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP521R1,      /*!< Domain parameters for the 521-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_BP256R1,        /*!< Domain parameters for 256-bit Brainpool curve. */
    MBEDTLS_ECP_DP_BP384R1,        /*!< Domain parameters for 384-bit Brainpool curve. */
    MBEDTLS_ECP_DP_BP512R1,        /*!< Domain parameters for 512-bit Brainpool curve. */
    MBEDTLS_ECP_DP_CURVE25519,     /*!< Domain parameters for Curve25519. */
    MBEDTLS_ECP_DP_SECP192K1,      /*!< Domain parameters for 192-bit "Koblitz" curve. */
    MBEDTLS_ECP_DP_SECP224K1,      /*!< Domain parameters for 224-bit "Koblitz" curve. */
    MBEDTLS_ECP_DP_SECP256K1,      /*!< Domain parameters for 256-bit "Koblitz" curve. */
    MBEDTLS_ECP_DP_CURVE448,       /*!< Domain parameters for Curve448. */
} mbedtls_ecp_group_id;

#define MBEDTLS_ECP_DP_MAX     14

typedef enum {
    MBEDTLS_ECP_TYPE_NONE = 0,
    MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS,    /* y^2 = x^3 + a x + b      */
    MBEDTLS_ECP_TYPE_MONTGOMERY,           /* y^2 = x^3 + a x^2 + x    */
} mbedtls_ecp_curve_type;

typedef enum {
    MBEDTLS_ECP_MOD_NONE = 0,
    MBEDTLS_ECP_MOD_COORDINATE,
    MBEDTLS_ECP_MOD_SCALAR
} mbedtls_ecp_modulus_type;

typedef struct mbedtls_ecp_curve_info {
    mbedtls_ecp_group_id grp_id;    /*!< An internal identifier. */
    uint16_t tls_id;                /*!< The TLS NamedCurve identifier. */
    uint16_t bit_size;              /*!< The curve size in bits. */
    const char *name;               /*!< A human-friendly name. */
} mbedtls_ecp_curve_info;

typedef struct mbedtls_ecp_point {
    mbedtls_mpi MBEDTLS_PRIVATE(X);          /*!< The X coordinate of the ECP point. */
    mbedtls_mpi MBEDTLS_PRIVATE(Y);          /*!< The Y coordinate of the ECP point. */
    mbedtls_mpi MBEDTLS_PRIVATE(Z);          /*!< The Z coordinate of the ECP point. */
}
mbedtls_ecp_point;

#if !defined(MBEDTLS_ECP_ALT)

typedef struct mbedtls_ecp_group {
    mbedtls_ecp_group_id id;    /*!< An internal group identifier. */
    mbedtls_mpi P;              /*!< The prime modulus of the base field. */
    mbedtls_mpi A;              /*!< For Short Weierstrass: \p A in the equation. For
                                     Montgomery curves: <code>(A + 2) / 4</code>. */
    mbedtls_mpi B;              /*!< For Short Weierstrass: \p B in the equation.
                                     For Montgomery curves: unused. */
    mbedtls_ecp_point G;        /*!< The generator of the subgroup used. */
    mbedtls_mpi N;              /*!< The order of \p G. */
    size_t pbits;               /*!< The number of bits in \p P.*/
    size_t nbits;               /*!< For Short Weierstrass: The number of bits in \p P.
                                     For Montgomery curves: the number of bits in the
                                     private keys. */
    /* End of public fields */

    unsigned int MBEDTLS_PRIVATE(h);             /*!< \internal 1 if the constants are static. */
    int(*MBEDTLS_PRIVATE(modp))(mbedtls_mpi *);  /*!< The function for fast pseudo-reduction
                                                    mod \p P (see above).*/
    int(*MBEDTLS_PRIVATE(t_pre))(mbedtls_ecp_point *, void *);   /*!< Unused. */
    int(*MBEDTLS_PRIVATE(t_post))(mbedtls_ecp_point *, void *);  /*!< Unused. */
    void *MBEDTLS_PRIVATE(t_data);               /*!< Unused. */
    mbedtls_ecp_point *MBEDTLS_PRIVATE(T);       /*!< Pre-computed points for ecp_mul_comb(). */
    size_t MBEDTLS_PRIVATE(T_size);              /*!< The number of dynamic allocated pre-computed points. */
}
mbedtls_ecp_group;

#if !defined(MBEDTLS_ECP_WINDOW_SIZE)

#define MBEDTLS_ECP_WINDOW_SIZE    4   /**< The maximum window size used. */
#endif /* MBEDTLS_ECP_WINDOW_SIZE */

#if !defined(MBEDTLS_ECP_FIXED_POINT_OPTIM)

#define MBEDTLS_ECP_FIXED_POINT_OPTIM  1   /**< Enable fixed-point speed-up. */
#endif /* MBEDTLS_ECP_FIXED_POINT_OPTIM */

#else  /* MBEDTLS_ECP_ALT */
#include "ecp_alt.h"
#endif /* MBEDTLS_ECP_ALT */

#if !defined(MBEDTLS_ECP_C)

#define MBEDTLS_ECP_MAX_BITS 1
#elif defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 521
#elif defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 512
#elif defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 448
#elif defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 384
#elif defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 384
#elif defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 256
#elif defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 256
#elif defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 256
#elif defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 255
#elif defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 225 // n is slightly above 2^224
#elif defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 224
#elif defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 192
#elif defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 192
#else
#error "Missing definition of MBEDTLS_ECP_MAX_BITS"
#endif

#define MBEDTLS_ECP_MAX_BYTES    ((MBEDTLS_ECP_MAX_BITS + 7) / 8)
#define MBEDTLS_ECP_MAX_PT_LEN   (2 * MBEDTLS_ECP_MAX_BYTES + 1)

#if defined(MBEDTLS_ECP_RESTARTABLE)

typedef struct mbedtls_ecp_restart_mul mbedtls_ecp_restart_mul_ctx;

typedef struct mbedtls_ecp_restart_muladd mbedtls_ecp_restart_muladd_ctx;

typedef struct {
    unsigned MBEDTLS_PRIVATE(ops_done);                  /*!<  current ops count             */
    unsigned MBEDTLS_PRIVATE(depth);                     /*!<  call depth (0 = top-level)    */
    mbedtls_ecp_restart_mul_ctx *MBEDTLS_PRIVATE(rsm);   /*!<  ecp_mul_comb() sub-context    */
    mbedtls_ecp_restart_muladd_ctx *MBEDTLS_PRIVATE(ma); /*!<  ecp_muladd() sub-context      */
} mbedtls_ecp_restart_ctx;

#define MBEDTLS_ECP_OPS_CHK   3 /*!< basic ops count for ecp_check_pubkey()  */
#define MBEDTLS_ECP_OPS_DBL   8 /*!< basic ops count for ecp_double_jac()    */
#define MBEDTLS_ECP_OPS_ADD  11 /*!< basic ops count for see ecp_add_mixed() */
#define MBEDTLS_ECP_OPS_INV 120 /*!< empirical equivalent for mpi_mod_inv()  */

int mbedtls_ecp_check_budget(const mbedtls_ecp_group *grp,
                             mbedtls_ecp_restart_ctx *rs_ctx,
                             unsigned ops);

#define MBEDTLS_ECP_BUDGET(ops)   \
    MBEDTLS_MPI_CHK(mbedtls_ecp_check_budget(grp, rs_ctx, \
                                             (unsigned) (ops)));

#else /* MBEDTLS_ECP_RESTARTABLE */

#define MBEDTLS_ECP_BUDGET(ops)     /* no-op; for compatibility */

typedef void mbedtls_ecp_restart_ctx;

#endif /* MBEDTLS_ECP_RESTARTABLE */

typedef struct mbedtls_ecp_keypair {
    mbedtls_ecp_group MBEDTLS_PRIVATE(grp);      /*!<  Elliptic curve and base point     */
    mbedtls_mpi MBEDTLS_PRIVATE(d);              /*!<  our secret value                  */
    mbedtls_ecp_point MBEDTLS_PRIVATE(Q);        /*!<  our public value                  */
}
mbedtls_ecp_keypair;

#define MBEDTLS_ECP_PF_UNCOMPRESSED    0

#define MBEDTLS_ECP_PF_COMPRESSED      1

#define MBEDTLS_ECP_TLS_NAMED_CURVE    3   /**< The named_curve of ECCurveType. */

#if defined(MBEDTLS_ECP_RESTARTABLE)

void mbedtls_ecp_set_max_ops(unsigned max_ops);

int mbedtls_ecp_restart_is_enabled(void);
#endif /* MBEDTLS_ECP_RESTARTABLE */

mbedtls_ecp_curve_type mbedtls_ecp_get_type(const mbedtls_ecp_group *grp);

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_list(void);

const mbedtls_ecp_group_id *mbedtls_ecp_grp_id_list(void);

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_grp_id(mbedtls_ecp_group_id grp_id);

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_tls_id(uint16_t tls_id);

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_name(const char *name);

void mbedtls_ecp_point_init(mbedtls_ecp_point *pt);

void mbedtls_ecp_group_init(mbedtls_ecp_group *grp);

void mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *key);

void mbedtls_ecp_point_free(mbedtls_ecp_point *pt);

void mbedtls_ecp_group_free(mbedtls_ecp_group *grp);

void mbedtls_ecp_keypair_free(mbedtls_ecp_keypair *key);

#if defined(MBEDTLS_ECP_RESTARTABLE)

void mbedtls_ecp_restart_init(mbedtls_ecp_restart_ctx *ctx);

void mbedtls_ecp_restart_free(mbedtls_ecp_restart_ctx *ctx);
#endif /* MBEDTLS_ECP_RESTARTABLE */

int mbedtls_ecp_copy(mbedtls_ecp_point *P, const mbedtls_ecp_point *Q);

int mbedtls_ecp_group_copy(mbedtls_ecp_group *dst,
                           const mbedtls_ecp_group *src);

int mbedtls_ecp_set_zero(mbedtls_ecp_point *pt);

int mbedtls_ecp_is_zero(mbedtls_ecp_point *pt);

int mbedtls_ecp_point_cmp(const mbedtls_ecp_point *P,
                          const mbedtls_ecp_point *Q);

int mbedtls_ecp_point_read_string(mbedtls_ecp_point *P, int radix,
                                  const char *x, const char *y);

int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp,
                                   const mbedtls_ecp_point *P,
                                   int format, size_t *olen,
                                   unsigned char *buf, size_t buflen);

int mbedtls_ecp_point_read_binary(const mbedtls_ecp_group *grp,
                                  mbedtls_ecp_point *P,
                                  const unsigned char *buf, size_t ilen);

int mbedtls_ecp_tls_read_point(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *pt,
                               const unsigned char **buf, size_t len);

int mbedtls_ecp_tls_write_point(const mbedtls_ecp_group *grp,
                                const mbedtls_ecp_point *pt,
                                int format, size_t *olen,
                                unsigned char *buf, size_t blen);

int mbedtls_ecp_group_load(mbedtls_ecp_group *grp, mbedtls_ecp_group_id id);

int mbedtls_ecp_tls_read_group(mbedtls_ecp_group *grp,
                               const unsigned char **buf, size_t len);

int mbedtls_ecp_tls_read_group_id(mbedtls_ecp_group_id *grp,
                                  const unsigned char **buf,
                                  size_t len);

int mbedtls_ecp_tls_write_group(const mbedtls_ecp_group *grp,
                                size_t *olen,
                                unsigned char *buf, size_t blen);

int mbedtls_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int mbedtls_ecp_mul_restartable(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                                const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                mbedtls_ecp_restart_ctx *rs_ctx);

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

int mbedtls_ecp_muladd(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                       const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                       const mbedtls_mpi *n, const mbedtls_ecp_point *Q);

int mbedtls_ecp_muladd_restartable(
    mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
    const mbedtls_mpi *n, const mbedtls_ecp_point *Q,
    mbedtls_ecp_restart_ctx *rs_ctx);
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

int mbedtls_ecp_check_pubkey(const mbedtls_ecp_group *grp,
                             const mbedtls_ecp_point *pt);

int mbedtls_ecp_check_privkey(const mbedtls_ecp_group *grp,
                              const mbedtls_mpi *d);

int mbedtls_ecp_gen_privkey(const mbedtls_ecp_group *grp,
                            mbedtls_mpi *d,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng);

int mbedtls_ecp_gen_keypair_base(mbedtls_ecp_group *grp,
                                 const mbedtls_ecp_point *G,
                                 mbedtls_mpi *d, mbedtls_ecp_point *Q,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng);

int mbedtls_ecp_gen_keypair(mbedtls_ecp_group *grp, mbedtls_mpi *d,
                            mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng);

int mbedtls_ecp_gen_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

int mbedtls_ecp_read_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                         const unsigned char *buf, size_t buflen);

int mbedtls_ecp_write_key(mbedtls_ecp_keypair *key,
                          unsigned char *buf, size_t buflen);

int mbedtls_ecp_check_pub_priv(
    const mbedtls_ecp_keypair *pub, const mbedtls_ecp_keypair *prv,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int mbedtls_ecp_export(const mbedtls_ecp_keypair *key, mbedtls_ecp_group *grp,
                       mbedtls_mpi *d, mbedtls_ecp_point *Q);

#if defined(MBEDTLS_SELF_TEST)

int mbedtls_ecp_self_test(int verbose);

#endif /* MBEDTLS_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* ecp.h */
