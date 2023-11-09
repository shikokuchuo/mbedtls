/**
 * \file platform_util.h
 *
 * \brief Common and shared functions used by multiple modules in the Mbed TLS
 *        library.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PLATFORM_UTIL_H
#define MBEDTLS_PLATFORM_UTIL_H

#include "mbedtls/build_info.h"

#include <stddef.h>
#if defined(MBEDTLS_HAVE_TIME_DATE)
#include "mbedtls/platform_time.h"
#include <time.h>
#endif /* MBEDTLS_HAVE_TIME_DATE */

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_INTERNAL_VALIDATE_RET(cond, ret)  do { } while (0)
#define MBEDTLS_INTERNAL_VALIDATE(cond)           do { } while (0)

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_DEPRECATED __attribute__((deprecated))
MBEDTLS_DEPRECATED typedef char const *mbedtls_deprecated_string_constant_t;
#define MBEDTLS_DEPRECATED_STRING_CONSTANT(VAL)       \
    ((mbedtls_deprecated_string_constant_t) (VAL))
MBEDTLS_DEPRECATED typedef int mbedtls_deprecated_numeric_constant_t;
#define MBEDTLS_DEPRECATED_NUMERIC_CONSTANT(VAL)       \
    ((mbedtls_deprecated_numeric_constant_t) (VAL))
#else /* MBEDTLS_DEPRECATED_WARNING */
#define MBEDTLS_DEPRECATED
#define MBEDTLS_DEPRECATED_STRING_CONSTANT(VAL) VAL
#define MBEDTLS_DEPRECATED_NUMERIC_CONSTANT(VAL) VAL
#endif /* MBEDTLS_DEPRECATED_WARNING */
#endif /* MBEDTLS_DEPRECATED_REMOVED */

#if !defined(MBEDTLS_CHECK_RETURN)
#if defined(__GNUC__)
#define MBEDTLS_CHECK_RETURN __attribute__((__warn_unused_result__))
#elif defined(_MSC_VER) && _MSC_VER >= 1700
#include <sal.h>
#define MBEDTLS_CHECK_RETURN _Check_return_
#else
#define MBEDTLS_CHECK_RETURN
#endif
#endif

#define MBEDTLS_CHECK_RETURN_CRITICAL MBEDTLS_CHECK_RETURN

#if defined(MBEDTLS_CHECK_RETURN_WARNING)
#define MBEDTLS_CHECK_RETURN_TYPICAL MBEDTLS_CHECK_RETURN
#else
#define MBEDTLS_CHECK_RETURN_TYPICAL
#endif

#define MBEDTLS_CHECK_RETURN_OPTIONAL

#if !defined(MBEDTLS_IGNORE_RETURN)

#define MBEDTLS_IGNORE_RETURN(result) ((void) !(result))
#endif

#if !defined(MBEDTLS_TEST_DEFINES_ZEROIZE)

void mbedtls_platform_zeroize(void *buf, size_t len);
#endif

#if defined(MBEDTLS_HAVE_TIME_DATE)

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt,
                                     struct tm *tm_buf);
#endif /* MBEDTLS_HAVE_TIME_DATE */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PLATFORM_UTIL_H */
