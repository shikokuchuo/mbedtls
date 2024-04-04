/**
 * \file oid.h
 *
 * \brief Object Identifier (OID) database
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_OID_H
#define MBEDTLS_OID_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/asn1.h"
#include "mbedtls/pk.h"

#include <stddef.h>

#if defined(MBEDTLS_CIPHER_C)
#include "mbedtls/cipher.h"
#endif

#include "mbedtls/md.h"

#define MBEDTLS_ERR_OID_NOT_FOUND                         -0x002E
#define MBEDTLS_ERR_OID_BUF_TOO_SMALL                     -0x000B

#define MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER    (1 << 0)
#define MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER      (1 << 1)
#define MBEDTLS_OID_X509_EXT_KEY_USAGE                   (1 << 2)
#define MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES        (1 << 3)
#define MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS             (1 << 4)
#define MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME            (1 << 5)
#define MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME             (1 << 6)
#define MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS     (1 << 7)
#define MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS           (1 << 8)
#define MBEDTLS_OID_X509_EXT_NAME_CONSTRAINTS            (1 << 9)
#define MBEDTLS_OID_X509_EXT_POLICY_CONSTRAINTS          (1 << 10)
#define MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE          (1 << 11)
#define MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS     (1 << 12)
#define MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY          (1 << 13)
#define MBEDTLS_OID_X509_EXT_FRESHEST_CRL                (1 << 14)
#define MBEDTLS_OID_X509_EXT_NS_CERT_TYPE                (1 << 16)

#define MBEDTLS_OID_MAX_COMPONENTS              128

#define MBEDTLS_OID_ISO_MEMBER_BODIES           "\x2a"
#define MBEDTLS_OID_ISO_IDENTIFIED_ORG          "\x2b"
#define MBEDTLS_OID_ISO_CCITT_DS                "\x55"
#define MBEDTLS_OID_ISO_ITU_COUNTRY             "\x60"

#define MBEDTLS_OID_COUNTRY_US                  "\x86\x48"
#define MBEDTLS_OID_ORG_RSA_DATA_SECURITY       "\x86\xf7\x0d"
#define MBEDTLS_OID_RSA_COMPANY                 MBEDTLS_OID_ISO_MEMBER_BODIES MBEDTLS_OID_COUNTRY_US \
        MBEDTLS_OID_ORG_RSA_DATA_SECURITY
#define MBEDTLS_OID_ORG_ANSI_X9_62              "\xce\x3d"
#define MBEDTLS_OID_ANSI_X9_62                  MBEDTLS_OID_ISO_MEMBER_BODIES MBEDTLS_OID_COUNTRY_US \
        MBEDTLS_OID_ORG_ANSI_X9_62

#define MBEDTLS_OID_ORG_DOD                     "\x06"
#define MBEDTLS_OID_ORG_OIW                     "\x0e"
#define MBEDTLS_OID_OIW_SECSIG                  MBEDTLS_OID_ORG_OIW "\x03"
#define MBEDTLS_OID_OIW_SECSIG_ALG              MBEDTLS_OID_OIW_SECSIG "\x02"
#define MBEDTLS_OID_OIW_SECSIG_SHA1             MBEDTLS_OID_OIW_SECSIG_ALG "\x1a"
#define MBEDTLS_OID_ORG_THAWTE                  "\x65"
#define MBEDTLS_OID_THAWTE                      MBEDTLS_OID_ISO_IDENTIFIED_ORG \
        MBEDTLS_OID_ORG_THAWTE
#define MBEDTLS_OID_ORG_CERTICOM                "\x81\x04"
#define MBEDTLS_OID_CERTICOM                    MBEDTLS_OID_ISO_IDENTIFIED_ORG \
        MBEDTLS_OID_ORG_CERTICOM
#define MBEDTLS_OID_ORG_TELETRUST               "\x24"
#define MBEDTLS_OID_TELETRUST                   MBEDTLS_OID_ISO_IDENTIFIED_ORG \
        MBEDTLS_OID_ORG_TELETRUST

#define MBEDTLS_OID_ORGANIZATION                "\x01"
#define MBEDTLS_OID_ISO_ITU_US_ORG              MBEDTLS_OID_ISO_ITU_COUNTRY MBEDTLS_OID_COUNTRY_US \
        MBEDTLS_OID_ORGANIZATION

#define MBEDTLS_OID_ORG_GOV                     "\x65"
#define MBEDTLS_OID_GOV                         MBEDTLS_OID_ISO_ITU_US_ORG MBEDTLS_OID_ORG_GOV

#define MBEDTLS_OID_ORG_NETSCAPE                "\x86\xF8\x42"
#define MBEDTLS_OID_NETSCAPE                    MBEDTLS_OID_ISO_ITU_US_ORG MBEDTLS_OID_ORG_NETSCAPE

#define MBEDTLS_OID_ID_CE                       MBEDTLS_OID_ISO_CCITT_DS "\x1D"

#define MBEDTLS_OID_NIST_ALG                    MBEDTLS_OID_GOV "\x03\x04"

#define MBEDTLS_OID_INTERNET                    MBEDTLS_OID_ISO_IDENTIFIED_ORG MBEDTLS_OID_ORG_DOD \
    "\x01"
#define MBEDTLS_OID_PKIX                        MBEDTLS_OID_INTERNET "\x05\x05\x07"

#define MBEDTLS_OID_AT                          MBEDTLS_OID_ISO_CCITT_DS "\x04"
#define MBEDTLS_OID_AT_CN                       MBEDTLS_OID_AT "\x03"
#define MBEDTLS_OID_AT_SUR_NAME                 MBEDTLS_OID_AT "\x04"
#define MBEDTLS_OID_AT_SERIAL_NUMBER            MBEDTLS_OID_AT "\x05"
#define MBEDTLS_OID_AT_COUNTRY                  MBEDTLS_OID_AT "\x06"
#define MBEDTLS_OID_AT_LOCALITY                 MBEDTLS_OID_AT "\x07"
#define MBEDTLS_OID_AT_STATE                    MBEDTLS_OID_AT "\x08"
#define MBEDTLS_OID_AT_ORGANIZATION             MBEDTLS_OID_AT "\x0A"
#define MBEDTLS_OID_AT_ORG_UNIT                 MBEDTLS_OID_AT "\x0B"
#define MBEDTLS_OID_AT_TITLE                    MBEDTLS_OID_AT "\x0C"
#define MBEDTLS_OID_AT_POSTAL_ADDRESS           MBEDTLS_OID_AT "\x10"
#define MBEDTLS_OID_AT_POSTAL_CODE              MBEDTLS_OID_AT "\x11"
#define MBEDTLS_OID_AT_GIVEN_NAME               MBEDTLS_OID_AT "\x2A"
#define MBEDTLS_OID_AT_INITIALS                 MBEDTLS_OID_AT "\x2B"
#define MBEDTLS_OID_AT_GENERATION_QUALIFIER     MBEDTLS_OID_AT "\x2C"
#define MBEDTLS_OID_AT_UNIQUE_IDENTIFIER        MBEDTLS_OID_AT "\x2D"
#define MBEDTLS_OID_AT_DN_QUALIFIER             MBEDTLS_OID_AT "\x2E"
#define MBEDTLS_OID_AT_PSEUDONYM                MBEDTLS_OID_AT "\x41"

#define MBEDTLS_OID_UID                         "\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x01"
#define MBEDTLS_OID_DOMAIN_COMPONENT            "\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x19"

#define MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER    MBEDTLS_OID_ID_CE "\x23"
#define MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER      MBEDTLS_OID_ID_CE "\x0E"
#define MBEDTLS_OID_KEY_USAGE                   MBEDTLS_OID_ID_CE "\x0F"
#define MBEDTLS_OID_CERTIFICATE_POLICIES        MBEDTLS_OID_ID_CE "\x20"
#define MBEDTLS_OID_POLICY_MAPPINGS             MBEDTLS_OID_ID_CE "\x21"
#define MBEDTLS_OID_SUBJECT_ALT_NAME            MBEDTLS_OID_ID_CE "\x11"
#define MBEDTLS_OID_ISSUER_ALT_NAME             MBEDTLS_OID_ID_CE "\x12"
#define MBEDTLS_OID_SUBJECT_DIRECTORY_ATTRS     MBEDTLS_OID_ID_CE "\x09"
#define MBEDTLS_OID_BASIC_CONSTRAINTS           MBEDTLS_OID_ID_CE "\x13"
#define MBEDTLS_OID_NAME_CONSTRAINTS            MBEDTLS_OID_ID_CE "\x1E"
#define MBEDTLS_OID_POLICY_CONSTRAINTS          MBEDTLS_OID_ID_CE "\x24"
#define MBEDTLS_OID_EXTENDED_KEY_USAGE          MBEDTLS_OID_ID_CE "\x25"
#define MBEDTLS_OID_CRL_DISTRIBUTION_POINTS     MBEDTLS_OID_ID_CE "\x1F"
#define MBEDTLS_OID_INIHIBIT_ANYPOLICY          MBEDTLS_OID_ID_CE "\x36"
#define MBEDTLS_OID_FRESHEST_CRL                MBEDTLS_OID_ID_CE "\x2E"

#define MBEDTLS_OID_ANY_POLICY              MBEDTLS_OID_CERTIFICATE_POLICIES "\x00"

#define MBEDTLS_OID_NS_CERT                 MBEDTLS_OID_NETSCAPE "\x01"
#define MBEDTLS_OID_NS_CERT_TYPE            MBEDTLS_OID_NS_CERT  "\x01"
#define MBEDTLS_OID_NS_BASE_URL             MBEDTLS_OID_NS_CERT  "\x02"
#define MBEDTLS_OID_NS_REVOCATION_URL       MBEDTLS_OID_NS_CERT  "\x03"
#define MBEDTLS_OID_NS_CA_REVOCATION_URL    MBEDTLS_OID_NS_CERT  "\x04"
#define MBEDTLS_OID_NS_RENEWAL_URL          MBEDTLS_OID_NS_CERT  "\x07"
#define MBEDTLS_OID_NS_CA_POLICY_URL        MBEDTLS_OID_NS_CERT  "\x08"
#define MBEDTLS_OID_NS_SSL_SERVER_NAME      MBEDTLS_OID_NS_CERT  "\x0C"
#define MBEDTLS_OID_NS_COMMENT              MBEDTLS_OID_NS_CERT  "\x0D"
#define MBEDTLS_OID_NS_DATA_TYPE            MBEDTLS_OID_NETSCAPE "\x02"
#define MBEDTLS_OID_NS_CERT_SEQUENCE        MBEDTLS_OID_NS_DATA_TYPE "\x05"

#define MBEDTLS_OID_PRIVATE_KEY_USAGE_PERIOD    MBEDTLS_OID_ID_CE "\x10"
#define MBEDTLS_OID_CRL_NUMBER                  MBEDTLS_OID_ID_CE "\x14"

#define MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE      MBEDTLS_OID_EXTENDED_KEY_USAGE "\x00"

#define MBEDTLS_OID_KP                          MBEDTLS_OID_PKIX "\x03"
#define MBEDTLS_OID_SERVER_AUTH                 MBEDTLS_OID_KP "\x01"
#define MBEDTLS_OID_CLIENT_AUTH                 MBEDTLS_OID_KP "\x02"
#define MBEDTLS_OID_CODE_SIGNING                MBEDTLS_OID_KP "\x03"
#define MBEDTLS_OID_EMAIL_PROTECTION            MBEDTLS_OID_KP "\x04"
#define MBEDTLS_OID_TIME_STAMPING               MBEDTLS_OID_KP "\x08"
#define MBEDTLS_OID_OCSP_SIGNING                MBEDTLS_OID_KP "\x09"

#define MBEDTLS_OID_WISUN_FAN                   MBEDTLS_OID_INTERNET "\x04\x01\x82\xe4\x25\x01"

#define MBEDTLS_OID_ON                          MBEDTLS_OID_PKIX "\x08"
#define MBEDTLS_OID_ON_HW_MODULE_NAME           MBEDTLS_OID_ON "\x04"

#define MBEDTLS_OID_PKCS                MBEDTLS_OID_RSA_COMPANY "\x01"
#define MBEDTLS_OID_PKCS1               MBEDTLS_OID_PKCS "\x01"
#define MBEDTLS_OID_PKCS5               MBEDTLS_OID_PKCS "\x05"
#define MBEDTLS_OID_PKCS7               MBEDTLS_OID_PKCS "\x07"
#define MBEDTLS_OID_PKCS9               MBEDTLS_OID_PKCS "\x09"
#define MBEDTLS_OID_PKCS12              MBEDTLS_OID_PKCS "\x0c"

#define MBEDTLS_OID_PKCS1_RSA           MBEDTLS_OID_PKCS1 "\x01"
#define MBEDTLS_OID_PKCS1_MD5           MBEDTLS_OID_PKCS1 "\x04"
#define MBEDTLS_OID_PKCS1_SHA1          MBEDTLS_OID_PKCS1 "\x05"
#define MBEDTLS_OID_PKCS1_SHA224        MBEDTLS_OID_PKCS1 "\x0e"
#define MBEDTLS_OID_PKCS1_SHA256        MBEDTLS_OID_PKCS1 "\x0b"
#define MBEDTLS_OID_PKCS1_SHA384        MBEDTLS_OID_PKCS1 "\x0c"
#define MBEDTLS_OID_PKCS1_SHA512        MBEDTLS_OID_PKCS1 "\x0d"

#define MBEDTLS_OID_RSA_SHA_OBS         "\x2B\x0E\x03\x02\x1D"

#define MBEDTLS_OID_PKCS9_EMAIL         MBEDTLS_OID_PKCS9 "\x01"

#define MBEDTLS_OID_RSASSA_PSS          MBEDTLS_OID_PKCS1 "\x0a"
#define MBEDTLS_OID_MGF1                MBEDTLS_OID_PKCS1 "\x08"

#define MBEDTLS_OID_DIGEST_ALG_MD5              MBEDTLS_OID_RSA_COMPANY "\x02\x05"
#define MBEDTLS_OID_DIGEST_ALG_SHA1             MBEDTLS_OID_ISO_IDENTIFIED_ORG \
        MBEDTLS_OID_OIW_SECSIG_SHA1
#define MBEDTLS_OID_DIGEST_ALG_SHA224           MBEDTLS_OID_NIST_ALG "\x02\x04"
#define MBEDTLS_OID_DIGEST_ALG_SHA256           MBEDTLS_OID_NIST_ALG "\x02\x01"

#define MBEDTLS_OID_DIGEST_ALG_SHA384           MBEDTLS_OID_NIST_ALG "\x02\x02"

#define MBEDTLS_OID_DIGEST_ALG_SHA512           MBEDTLS_OID_NIST_ALG "\x02\x03"

#define MBEDTLS_OID_DIGEST_ALG_RIPEMD160        MBEDTLS_OID_TELETRUST "\x03\x02\x01"

#define MBEDTLS_OID_DIGEST_ALG_SHA3_224         MBEDTLS_OID_NIST_ALG "\x02\x07"

#define MBEDTLS_OID_DIGEST_ALG_SHA3_256         MBEDTLS_OID_NIST_ALG "\x02\x08"

#define MBEDTLS_OID_DIGEST_ALG_SHA3_384         MBEDTLS_OID_NIST_ALG "\x02\x09"

#define MBEDTLS_OID_DIGEST_ALG_SHA3_512         MBEDTLS_OID_NIST_ALG "\x02\x0a"


#define MBEDTLS_OID_HMAC_SHA1                   MBEDTLS_OID_RSA_COMPANY "\x02\x07"

#define MBEDTLS_OID_HMAC_SHA224                 MBEDTLS_OID_RSA_COMPANY "\x02\x08"

#define MBEDTLS_OID_HMAC_SHA256                 MBEDTLS_OID_RSA_COMPANY "\x02\x09"

#define MBEDTLS_OID_HMAC_SHA384                 MBEDTLS_OID_RSA_COMPANY "\x02\x0A"

#define MBEDTLS_OID_HMAC_SHA512                 MBEDTLS_OID_RSA_COMPANY "\x02\x0B"

#define MBEDTLS_OID_HMAC_SHA3_224               MBEDTLS_OID_NIST_ALG "\x02\x0d"

#define MBEDTLS_OID_HMAC_SHA3_256               MBEDTLS_OID_NIST_ALG "\x02\x0e"

#define MBEDTLS_OID_HMAC_SHA3_384               MBEDTLS_OID_NIST_ALG "\x02\x0f"

#define MBEDTLS_OID_HMAC_SHA3_512               MBEDTLS_OID_NIST_ALG "\x02\x10"

#define MBEDTLS_OID_HMAC_RIPEMD160              MBEDTLS_OID_INTERNET "\x05\x05\x08\x01\x04"

#define MBEDTLS_OID_DES_CBC                     MBEDTLS_OID_ISO_IDENTIFIED_ORG \
        MBEDTLS_OID_OIW_SECSIG_ALG "\x07"
#define MBEDTLS_OID_DES_EDE3_CBC                MBEDTLS_OID_RSA_COMPANY "\x03\x07"
#define MBEDTLS_OID_AES                         MBEDTLS_OID_NIST_ALG "\x01"
#define MBEDTLS_OID_AES_128_CBC                 MBEDTLS_OID_AES "\x02"
#define MBEDTLS_OID_AES_192_CBC                 MBEDTLS_OID_AES "\x16"
#define MBEDTLS_OID_AES_256_CBC                 MBEDTLS_OID_AES "\x2a"

#define MBEDTLS_OID_AES128_KW                   MBEDTLS_OID_AES "\x05"
#define MBEDTLS_OID_AES128_KWP                  MBEDTLS_OID_AES "\x08"
#define MBEDTLS_OID_AES192_KW                   MBEDTLS_OID_AES "\x19"
#define MBEDTLS_OID_AES192_KWP                  MBEDTLS_OID_AES "\x1c"
#define MBEDTLS_OID_AES256_KW                   MBEDTLS_OID_AES "\x2d"
#define MBEDTLS_OID_AES256_KWP                  MBEDTLS_OID_AES "\x30"

#define MBEDTLS_OID_PKCS5_PBKDF2                MBEDTLS_OID_PKCS5 "\x0c"
#define MBEDTLS_OID_PKCS5_PBES2                 MBEDTLS_OID_PKCS5 "\x0d"
#define MBEDTLS_OID_PKCS5_PBMAC1                MBEDTLS_OID_PKCS5 "\x0e"

#define MBEDTLS_OID_PKCS5_PBE_MD5_DES_CBC       MBEDTLS_OID_PKCS5 "\x03"
#define MBEDTLS_OID_PKCS5_PBE_MD5_RC2_CBC       MBEDTLS_OID_PKCS5 "\x06"
#define MBEDTLS_OID_PKCS5_PBE_SHA1_DES_CBC      MBEDTLS_OID_PKCS5 "\x0a"
#define MBEDTLS_OID_PKCS5_PBE_SHA1_RC2_CBC      MBEDTLS_OID_PKCS5 "\x0b"

#define MBEDTLS_OID_PKCS7_DATA                        MBEDTLS_OID_PKCS7 "\x01"
#define MBEDTLS_OID_PKCS7_SIGNED_DATA                 MBEDTLS_OID_PKCS7 "\x02"
#define MBEDTLS_OID_PKCS7_ENVELOPED_DATA              MBEDTLS_OID_PKCS7 "\x03"
#define MBEDTLS_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA   MBEDTLS_OID_PKCS7 "\x04"
#define MBEDTLS_OID_PKCS7_DIGESTED_DATA               MBEDTLS_OID_PKCS7 "\x05"
#define MBEDTLS_OID_PKCS7_ENCRYPTED_DATA              MBEDTLS_OID_PKCS7 "\x06"

#define MBEDTLS_OID_PKCS9_CSR_EXT_REQ           MBEDTLS_OID_PKCS9 "\x0e"

#define MBEDTLS_OID_PKCS12_PBE                      MBEDTLS_OID_PKCS12 "\x01"

#define MBEDTLS_OID_PKCS12_PBE_SHA1_DES3_EDE_CBC    MBEDTLS_OID_PKCS12_PBE "\x03"
#define MBEDTLS_OID_PKCS12_PBE_SHA1_DES2_EDE_CBC    MBEDTLS_OID_PKCS12_PBE "\x04"
#define MBEDTLS_OID_PKCS12_PBE_SHA1_RC2_128_CBC     MBEDTLS_OID_PKCS12_PBE "\x05"
#define MBEDTLS_OID_PKCS12_PBE_SHA1_RC2_40_CBC      MBEDTLS_OID_PKCS12_PBE "\x06"

#define MBEDTLS_OID_EC_ALG_UNRESTRICTED         MBEDTLS_OID_ANSI_X9_62 "\x02\01"

#define MBEDTLS_OID_EC_ALG_ECDH                 MBEDTLS_OID_CERTICOM "\x01\x0c"

#define MBEDTLS_OID_EC_GRP_SECP192R1        MBEDTLS_OID_ANSI_X9_62 "\x03\x01\x01"

#define MBEDTLS_OID_EC_GRP_SECP224R1        MBEDTLS_OID_CERTICOM "\x00\x21"

#define MBEDTLS_OID_EC_GRP_SECP256R1        MBEDTLS_OID_ANSI_X9_62 "\x03\x01\x07"

#define MBEDTLS_OID_EC_GRP_SECP384R1        MBEDTLS_OID_CERTICOM "\x00\x22"

#define MBEDTLS_OID_EC_GRP_SECP521R1        MBEDTLS_OID_CERTICOM "\x00\x23"

#define MBEDTLS_OID_EC_GRP_SECP192K1        MBEDTLS_OID_CERTICOM "\x00\x1f"

#define MBEDTLS_OID_EC_GRP_SECP224K1        MBEDTLS_OID_CERTICOM "\x00\x20"

#define MBEDTLS_OID_EC_GRP_SECP256K1        MBEDTLS_OID_CERTICOM "\x00\x0a"

#define MBEDTLS_OID_EC_BRAINPOOL_V1         MBEDTLS_OID_TELETRUST "\x03\x03\x02\x08\x01\x01"

#define MBEDTLS_OID_EC_GRP_BP256R1          MBEDTLS_OID_EC_BRAINPOOL_V1 "\x07"

#define MBEDTLS_OID_EC_GRP_BP384R1          MBEDTLS_OID_EC_BRAINPOOL_V1 "\x0B"

#define MBEDTLS_OID_EC_GRP_BP512R1          MBEDTLS_OID_EC_BRAINPOOL_V1 "\x0D"

#define MBEDTLS_OID_ANSI_X9_62_FIELD_TYPE   MBEDTLS_OID_ANSI_X9_62 "\x01"
#define MBEDTLS_OID_ANSI_X9_62_PRIME_FIELD  MBEDTLS_OID_ANSI_X9_62_FIELD_TYPE "\x01"

#define MBEDTLS_OID_ANSI_X9_62_SIG          MBEDTLS_OID_ANSI_X9_62 "\x04"
#define MBEDTLS_OID_ANSI_X9_62_SIG_SHA2     MBEDTLS_OID_ANSI_X9_62_SIG "\x03"

#define MBEDTLS_OID_ECDSA_SHA1              MBEDTLS_OID_ANSI_X9_62_SIG "\x01"

#define MBEDTLS_OID_ECDSA_SHA224            MBEDTLS_OID_ANSI_X9_62_SIG_SHA2 "\x01"

#define MBEDTLS_OID_ECDSA_SHA256            MBEDTLS_OID_ANSI_X9_62_SIG_SHA2 "\x02"

#define MBEDTLS_OID_ECDSA_SHA384            MBEDTLS_OID_ANSI_X9_62_SIG_SHA2 "\x03"

#define MBEDTLS_OID_ECDSA_SHA512            MBEDTLS_OID_ANSI_X9_62_SIG_SHA2 "\x04"

#define MBEDTLS_OID_X25519                  MBEDTLS_OID_THAWTE "\x6e"
#define MBEDTLS_OID_X448                    MBEDTLS_OID_THAWTE "\x6f"
#define MBEDTLS_OID_ED25519                 MBEDTLS_OID_THAWTE "\x70"
#define MBEDTLS_OID_ED448                   MBEDTLS_OID_THAWTE "\x71"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_oid_descriptor_t {
    const char *MBEDTLS_PRIVATE(asn1);
    size_t MBEDTLS_PRIVATE(asn1_len);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    const char *MBEDTLS_PRIVATE(name);
    const char *MBEDTLS_PRIVATE(description);
#endif
} mbedtls_oid_descriptor_t;

int mbedtls_oid_get_numeric_string(char *buf, size_t size, const mbedtls_asn1_buf *oid);

int mbedtls_oid_from_numeric_string(mbedtls_asn1_buf *oid, const char *oid_str, size_t size);

int mbedtls_oid_get_x509_ext_type(const mbedtls_asn1_buf *oid, int *ext_type);

int mbedtls_oid_get_attr_short_name(const mbedtls_asn1_buf *oid, const char **short_name);

int mbedtls_oid_get_pk_alg(const mbedtls_asn1_buf *oid, mbedtls_pk_type_t *pk_alg);

int mbedtls_oid_get_oid_by_pk_alg(mbedtls_pk_type_t pk_alg,
                                  const char **oid, size_t *olen);

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)

int mbedtls_oid_get_ec_grp(const mbedtls_asn1_buf *oid, mbedtls_ecp_group_id *grp_id);

int mbedtls_oid_get_oid_by_ec_grp(mbedtls_ecp_group_id grp_id,
                                  const char **oid, size_t *olen);

int mbedtls_oid_get_ec_grp_algid(const mbedtls_asn1_buf *oid, mbedtls_ecp_group_id *grp_id);

int mbedtls_oid_get_oid_by_ec_grp_algid(mbedtls_ecp_group_id grp_id,
                                        const char **oid, size_t *olen);
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

int mbedtls_oid_get_sig_alg(const mbedtls_asn1_buf *oid,
                            mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg);

int mbedtls_oid_get_sig_alg_desc(const mbedtls_asn1_buf *oid, const char **desc);

int mbedtls_oid_get_oid_by_sig_alg(mbedtls_pk_type_t pk_alg, mbedtls_md_type_t md_alg,
                                   const char **oid, size_t *olen);

int mbedtls_oid_get_md_hmac(const mbedtls_asn1_buf *oid, mbedtls_md_type_t *md_hmac);

int mbedtls_oid_get_md_alg(const mbedtls_asn1_buf *oid, mbedtls_md_type_t *md_alg);

#if !defined(MBEDTLS_X509_REMOVE_INFO)

int mbedtls_oid_get_extended_key_usage(const mbedtls_asn1_buf *oid, const char **desc);
#endif

int mbedtls_oid_get_certificate_policies(const mbedtls_asn1_buf *oid, const char **desc);

int mbedtls_oid_get_oid_by_md(mbedtls_md_type_t md_alg, const char **oid, size_t *olen);

#if defined(MBEDTLS_CIPHER_C)

int mbedtls_oid_get_cipher_alg(const mbedtls_asn1_buf *oid, mbedtls_cipher_type_t *cipher_alg);

#if defined(MBEDTLS_PKCS12_C)

int mbedtls_oid_get_pkcs12_pbe_alg(const mbedtls_asn1_buf *oid, mbedtls_md_type_t *md_alg,
                                   mbedtls_cipher_type_t *cipher_alg);
#endif /* MBEDTLS_PKCS12_C */
#endif /* MBEDTLS_CIPHER_C */

#ifdef __cplusplus
}
#endif

#endif /* oid.h */
