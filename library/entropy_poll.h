/**
 * \file entropy_poll.h
 *
 * \brief Platform-specific and custom entropy polling functions
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
#ifndef MBEDTLS_ENTROPY_POLL_H
#define MBEDTLS_ENTROPY_POLL_H

#include "mbedtls/build_info.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ENTROPY_MIN_PLATFORM     32
#if !defined(MBEDTLS_ENTROPY_MIN_HARDWARE)
#define MBEDTLS_ENTROPY_MIN_HARDWARE     32
#endif

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)

int mbedtls_platform_entropy_poll(void *data,
                                  unsigned char *output, size_t len, size_t *olen);
#endif

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)

int mbedtls_hardware_poll(void *data,
                          unsigned char *output, size_t len, size_t *olen);
#endif

#if defined(MBEDTLS_ENTROPY_NV_SEED)

int mbedtls_nv_seed_poll(void *data,
                         unsigned char *output, size_t len, size_t *olen);
#endif

#ifdef __cplusplus
}
#endif

#endif /* entropy_poll.h */
