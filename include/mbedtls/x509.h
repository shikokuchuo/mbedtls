/**
 * \file x509.h
 *
 * \brief X.509 generic defines and structures
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
#ifndef MBEDTLS_X509_H
#define MBEDTLS_X509_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/asn1.h"
#include "mbedtls/pk.h"

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif

#if !defined(MBEDTLS_X509_MAX_INTERMEDIATE_CA)

#define MBEDTLS_X509_MAX_INTERMEDIATE_CA   8
#endif

#define MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE              -0x2080

#define MBEDTLS_ERR_X509_UNKNOWN_OID                      -0x2100

#define MBEDTLS_ERR_X509_INVALID_FORMAT                   -0x2180

#define MBEDTLS_ERR_X509_INVALID_VERSION                  -0x2200

#define MBEDTLS_ERR_X509_INVALID_SERIAL                   -0x2280

#define MBEDTLS_ERR_X509_INVALID_ALG                      -0x2300

#define MBEDTLS_ERR_X509_INVALID_NAME                     -0x2380

#define MBEDTLS_ERR_X509_INVALID_DATE                     -0x2400

#define MBEDTLS_ERR_X509_INVALID_SIGNATURE                -0x2480

#define MBEDTLS_ERR_X509_INVALID_EXTENSIONS               -0x2500

#define MBEDTLS_ERR_X509_UNKNOWN_VERSION                  -0x2580

#define MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG                  -0x2600

#define MBEDTLS_ERR_X509_SIG_MISMATCH                     -0x2680

#define MBEDTLS_ERR_X509_CERT_VERIFY_FAILED               -0x2700

#define MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT              -0x2780

#define MBEDTLS_ERR_X509_BAD_INPUT_DATA                   -0x2800

#define MBEDTLS_ERR_X509_ALLOC_FAILED                     -0x2880

#define MBEDTLS_ERR_X509_FILE_IO_ERROR                    -0x2900

#define MBEDTLS_ERR_X509_BUFFER_TOO_SMALL                 -0x2980

#define MBEDTLS_ERR_X509_FATAL_ERROR                      -0x3000

#define MBEDTLS_X509_BADCERT_EXPIRED             0x01
#define MBEDTLS_X509_BADCERT_REVOKED             0x02
#define MBEDTLS_X509_BADCERT_CN_MISMATCH         0x04
#define MBEDTLS_X509_BADCERT_NOT_TRUSTED         0x08
#define MBEDTLS_X509_BADCRL_NOT_TRUSTED          0x10
#define MBEDTLS_X509_BADCRL_EXPIRED              0x20
#define MBEDTLS_X509_BADCERT_MISSING             0x40
#define MBEDTLS_X509_BADCERT_SKIP_VERIFY         0x80
#define MBEDTLS_X509_BADCERT_OTHER             0x0100
#define MBEDTLS_X509_BADCERT_FUTURE            0x0200
#define MBEDTLS_X509_BADCRL_FUTURE             0x0400
#define MBEDTLS_X509_BADCERT_KEY_USAGE         0x0800
#define MBEDTLS_X509_BADCERT_EXT_KEY_USAGE     0x1000
#define MBEDTLS_X509_BADCERT_NS_CERT_TYPE      0x2000
#define MBEDTLS_X509_BADCERT_BAD_MD            0x4000
#define MBEDTLS_X509_BADCERT_BAD_PK            0x8000
#define MBEDTLS_X509_BADCERT_BAD_KEY         0x010000
#define MBEDTLS_X509_BADCRL_BAD_MD           0x020000
#define MBEDTLS_X509_BADCRL_BAD_PK           0x040000
#define MBEDTLS_X509_BADCRL_BAD_KEY          0x080000

#define MBEDTLS_X509_SAN_OTHER_NAME                      0
#define MBEDTLS_X509_SAN_RFC822_NAME                     1
#define MBEDTLS_X509_SAN_DNS_NAME                        2
#define MBEDTLS_X509_SAN_X400_ADDRESS_NAME               3
#define MBEDTLS_X509_SAN_DIRECTORY_NAME                  4
#define MBEDTLS_X509_SAN_EDI_PARTY_NAME                  5
#define MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER     6
#define MBEDTLS_X509_SAN_IP_ADDRESS                      7
#define MBEDTLS_X509_SAN_REGISTERED_ID                   8

#define MBEDTLS_X509_KU_DIGITAL_SIGNATURE            (0x80)
#define MBEDTLS_X509_KU_NON_REPUDIATION              (0x40)
#define MBEDTLS_X509_KU_KEY_ENCIPHERMENT             (0x20)
#define MBEDTLS_X509_KU_DATA_ENCIPHERMENT            (0x10)
#define MBEDTLS_X509_KU_KEY_AGREEMENT                (0x08)
#define MBEDTLS_X509_KU_KEY_CERT_SIGN                (0x04)
#define MBEDTLS_X509_KU_CRL_SIGN                     (0x02)
#define MBEDTLS_X509_KU_ENCIPHER_ONLY                (0x01)
#define MBEDTLS_X509_KU_DECIPHER_ONLY              (0x8000)

#define MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT         (0x80)
#define MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER         (0x40)
#define MBEDTLS_X509_NS_CERT_TYPE_EMAIL              (0x20)
#define MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING     (0x10)
#define MBEDTLS_X509_NS_CERT_TYPE_RESERVED           (0x08)
#define MBEDTLS_X509_NS_CERT_TYPE_SSL_CA             (0x04)
#define MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA           (0x02)
#define MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA  (0x01)

#define MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
#define MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER   MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER
#define MBEDTLS_X509_EXT_KEY_USAGE                MBEDTLS_OID_X509_EXT_KEY_USAGE
#define MBEDTLS_X509_EXT_CERTIFICATE_POLICIES     MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES
#define MBEDTLS_X509_EXT_POLICY_MAPPINGS          MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS
#define MBEDTLS_X509_EXT_SUBJECT_ALT_NAME         MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME
#define MBEDTLS_X509_EXT_ISSUER_ALT_NAME          MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME
#define MBEDTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS  MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS
#define MBEDTLS_X509_EXT_BASIC_CONSTRAINTS        MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS
#define MBEDTLS_X509_EXT_NAME_CONSTRAINTS         MBEDTLS_OID_X509_EXT_NAME_CONSTRAINTS
#define MBEDTLS_X509_EXT_POLICY_CONSTRAINTS       MBEDTLS_OID_X509_EXT_POLICY_CONSTRAINTS
#define MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE       MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE
#define MBEDTLS_X509_EXT_CRL_DISTRIBUTION_POINTS  MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS
#define MBEDTLS_X509_EXT_INIHIBIT_ANYPOLICY       MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY
#define MBEDTLS_X509_EXT_FRESHEST_CRL             MBEDTLS_OID_X509_EXT_FRESHEST_CRL
#define MBEDTLS_X509_EXT_NS_CERT_TYPE             MBEDTLS_OID_X509_EXT_NS_CERT_TYPE

#define MBEDTLS_X509_FORMAT_DER                 1
#define MBEDTLS_X509_FORMAT_PEM                 2

#define MBEDTLS_X509_MAX_DN_NAME_SIZE         256

#ifdef __cplusplus
extern "C" {
#endif

typedef mbedtls_asn1_buf mbedtls_x509_buf;

typedef mbedtls_asn1_bitstring mbedtls_x509_bitstring;

typedef mbedtls_asn1_named_data mbedtls_x509_name;

typedef mbedtls_asn1_sequence mbedtls_x509_sequence;

typedef struct mbedtls_x509_time {
    int year, mon, day;
    int hour, min, sec;
}
mbedtls_x509_time;

typedef struct mbedtls_x509_san_other_name {
    mbedtls_x509_buf type_id;
    union {
        struct {
            mbedtls_x509_buf oid;
            mbedtls_x509_buf val;
        }
        hardware_module_name;
    }
    value;
}
mbedtls_x509_san_other_name;

typedef struct mbedtls_x509_subject_alternative_name {
    int type;
    union {
        mbedtls_x509_san_other_name other_name;
        mbedtls_x509_buf   unstructured_name;
    }
    san;
}
mbedtls_x509_subject_alternative_name;

int mbedtls_x509_dn_gets(char *buf, size_t size, const mbedtls_x509_name *dn);

static inline mbedtls_x509_name *mbedtls_x509_dn_get_next(
    mbedtls_x509_name *dn)
{
    while (dn->MBEDTLS_PRIVATE(next_merged) && dn->next != NULL) {
        dn = dn->next;
    }
    return dn->next;
}

int mbedtls_x509_serial_gets(char *buf, size_t size, const mbedtls_x509_buf *serial);

int mbedtls_x509_time_is_past(const mbedtls_x509_time *to);

int mbedtls_x509_time_is_future(const mbedtls_x509_time *from);

int mbedtls_x509_parse_subject_alt_name(const mbedtls_x509_buf *san_buf,
                                        mbedtls_x509_subject_alternative_name *san);

int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_name *cur);
int mbedtls_x509_get_alg_null(unsigned char **p, const unsigned char *end,
                              mbedtls_x509_buf *alg);
int mbedtls_x509_get_alg(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *alg, mbedtls_x509_buf *params);
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
int mbedtls_x509_get_rsassa_pss_params(const mbedtls_x509_buf *params,
                                       mbedtls_md_type_t *md_alg, mbedtls_md_type_t *mgf_md,
                                       int *salt_len);
#endif
int mbedtls_x509_get_sig(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig);
int mbedtls_x509_get_sig_alg(const mbedtls_x509_buf *sig_oid, const mbedtls_x509_buf *sig_params,
                             mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                             void **sig_opts);
int mbedtls_x509_get_time(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_time *t);
int mbedtls_x509_get_serial(unsigned char **p, const unsigned char *end,
                            mbedtls_x509_buf *serial);
int mbedtls_x509_get_ext(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *ext, int tag);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
int mbedtls_x509_sig_alg_gets(char *buf, size_t size, const mbedtls_x509_buf *sig_oid,
                              mbedtls_pk_type_t pk_alg, mbedtls_md_type_t md_alg,
                              const void *sig_opts);
#endif
int mbedtls_x509_key_size_helper(char *buf, size_t buf_size, const char *name);
int mbedtls_x509_string_to_names(mbedtls_asn1_named_data **head, const char *name);
int mbedtls_x509_set_extension(mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                               int critical, const unsigned char *val,
                               size_t val_len);
int mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start,
                                  mbedtls_asn1_named_data *first);
int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first);
int mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size);
int mbedtls_x509_get_ns_cert_type(unsigned char **p,
                                  const unsigned char *end,
                                  unsigned char *ns_cert_type);
int mbedtls_x509_get_key_usage(unsigned char **p,
                               const unsigned char *end,
                               unsigned int *key_usage);
int mbedtls_x509_get_subject_alt_name(unsigned char **p,
                                      const unsigned char *end,
                                      mbedtls_x509_sequence *subject_alt_name);
int mbedtls_x509_info_subject_alt_name(char **buf, size_t *size,
                                       const mbedtls_x509_sequence
                                       *subject_alt_name,
                                       const char *prefix);
int mbedtls_x509_info_cert_type(char **buf, size_t *size,
                                unsigned char ns_cert_type);
int mbedtls_x509_info_key_usage(char **buf, size_t *size,
                                unsigned int key_usage);

#define MBEDTLS_X509_SAFE_SNPRINTF                          \
    do {                                                    \
        if (ret < 0 || (size_t) ret >= n)                  \
        return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;    \
                                                          \
        n -= (size_t) ret;                                  \
        p += (size_t) ret;                                  \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* x509.h */
