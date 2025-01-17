/**
 * \file psa/crypto_compat.h
 *
 * \brief PSA cryptography module: Backward compatibility aliases
 *
 * This header declares alternative names for macro and functions.
 * New application code should not use these names.
 * These names may be removed in a future version of Mbed TLS.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef PSA_CRYPTO_COMPAT_H
#define PSA_CRYPTO_COMPAT_H 
#ifdef __cplusplus
extern "C" {
#endif
typedef mbedtls_svc_key_id_t psa_key_handle_t;
#define PSA_KEY_HANDLE_INIT MBEDTLS_SVC_KEY_ID_INIT
static inline int psa_key_handle_is_null(psa_key_handle_t handle)
{
    return mbedtls_svc_key_id_is_null(handle);
}
psa_status_t psa_open_key(mbedtls_svc_key_id_t key,
                          psa_key_handle_t *handle);
psa_status_t psa_close_key(psa_key_handle_t handle);
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#define PSA_DH_FAMILY_CUSTOM \
    ((psa_dh_family_t) MBEDTLS_DEPRECATED_NUMERIC_CONSTANT(0x7e))
static inline psa_status_t MBEDTLS_DEPRECATED psa_set_key_domain_parameters(
    psa_key_attributes_t *attributes,
    psa_key_type_t type, const uint8_t *data, size_t data_length)
{
    (void) data;
    if (data_length != 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    psa_set_key_type(attributes, type);
    return PSA_SUCCESS;
}
static inline psa_status_t MBEDTLS_DEPRECATED psa_get_key_domain_parameters(
    const psa_key_attributes_t *attributes,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    (void) attributes;
    (void) data;
    (void) data_size;
    *data_length = 0;
    return PSA_SUCCESS;
}
#define PSA_KEY_DOMAIN_PARAMETERS_SIZE(key_type,key_bits) \
    MBEDTLS_DEPRECATED_NUMERIC_CONSTANT(1u)
#endif
#ifdef __cplusplus
}
#endif
#endif
