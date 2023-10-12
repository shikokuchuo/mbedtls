/*
 *  Declaration of context structures for use with the PSA driver wrapper
 *  interface. This file contains the context structures for 'primitive'
 *  operations, i.e. those operations which do not rely on other contexts.
 *
 *  Warning: This file will be auto-generated in the future.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * \note This header and its content are not part of the Mbed TLS API and
 * applications must not depend on it. Its main purpose is to define the
 * multi-part state objects of the PSA drivers included in the cryptographic
 * library. The definitions of these objects are then used by crypto_struct.h
 * to define the implementation-defined types of PSA multi-part state objects.
 */
/*  Copyright The Mbed TLS Contributors
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

#ifndef PSA_CRYPTO_DRIVER_CONTEXTS_PRIMITIVES_H
#define PSA_CRYPTO_DRIVER_CONTEXTS_PRIMITIVES_H

#include "psa/crypto_driver_common.h"

#include "psa/crypto_builtin_primitives.h"

typedef union {
    unsigned dummy;
    mbedtls_psa_hash_operation_t mbedtls_ctx;
#if defined(PSA_CRYPTO_DRIVER_TEST)
    mbedtls_transparent_test_driver_hash_operation_t test_driver_ctx;
#endif
} psa_driver_hash_context_t;

typedef union {
    unsigned dummy;
    mbedtls_psa_cipher_operation_t mbedtls_ctx;
#if defined(PSA_CRYPTO_DRIVER_TEST)
    mbedtls_transparent_test_driver_cipher_operation_t transparent_test_driver_ctx;
    mbedtls_opaque_test_driver_cipher_operation_t opaque_test_driver_ctx;
#endif
} psa_driver_cipher_context_t;

#endif /* PSA_CRYPTO_DRIVER_CONTEXTS_PRIMITIVES_H */
/* End of automatically generated file. */
