/**
 * \file net_sockets.h
 *
 * \brief   Network sockets abstraction layer to integrate Mbed TLS into a
 *          BSD-style sockets API.
 *
 *          The network sockets module provides an example integration of the
 *          Mbed TLS library into a BSD sockets implementation. The module is
 *          intended to be an example of how Mbed TLS can be integrated into a
 *          networking stack, as well as to be Mbed TLS's network integration
 *          for its supported platforms.
 *
 *          The module is intended only to be used with the Mbed TLS library and
 *          is not intended to be used by third party application software
 *          directly.
 *
 *          The supported platforms are as follows:
 *              * Microsoft Windows and Windows CE
 *              * POSIX/Unix platforms including Linux, OS X
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
#ifndef MBEDTLS_NET_SOCKETS_H
#define MBEDTLS_NET_SOCKETS_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/ssl.h"

#include <stddef.h>
#include <stdint.h>

/** Failed to open a socket. */
#define MBEDTLS_ERR_NET_SOCKET_FAILED                     -0x0042
/** The connection to the given server / port failed. */
#define MBEDTLS_ERR_NET_CONNECT_FAILED                    -0x0044
/** Binding of the socket failed. */
#define MBEDTLS_ERR_NET_BIND_FAILED                       -0x0046
/** Could not listen on the socket. */
#define MBEDTLS_ERR_NET_LISTEN_FAILED                     -0x0048
/** Could not accept the incoming connection. */
#define MBEDTLS_ERR_NET_ACCEPT_FAILED                     -0x004A
/** Reading information from the socket failed. */
#define MBEDTLS_ERR_NET_RECV_FAILED                       -0x004C
/** Sending information through the socket failed. */
#define MBEDTLS_ERR_NET_SEND_FAILED                       -0x004E
/** Connection was reset by peer. */
#define MBEDTLS_ERR_NET_CONN_RESET                        -0x0050
/** Failed to get an IP address for the given hostname. */
#define MBEDTLS_ERR_NET_UNKNOWN_HOST                      -0x0052
/** Buffer is too small to hold the data. */
#define MBEDTLS_ERR_NET_BUFFER_TOO_SMALL                  -0x0043
/** The context is invalid, eg because it was free()ed. */
#define MBEDTLS_ERR_NET_INVALID_CONTEXT                   -0x0045
/** Polling the net context failed. */
#define MBEDTLS_ERR_NET_POLL_FAILED                       -0x0047
/** Input invalid. */
#define MBEDTLS_ERR_NET_BAD_INPUT_DATA                    -0x0049

#define MBEDTLS_NET_LISTEN_BACKLOG         10 /**< The backlog that listen() should use. */

#define MBEDTLS_NET_PROTO_TCP 0 /**< The TCP transport protocol */
#define MBEDTLS_NET_PROTO_UDP 1 /**< The UDP transport protocol */

#define MBEDTLS_NET_POLL_READ  1 /**< Used in \c mbedtls_net_poll to check for pending data  */
#define MBEDTLS_NET_POLL_WRITE 2 /**< Used in \c mbedtls_net_poll to check if write possible */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_net_context {
    int fd;
}
mbedtls_net_context;

void mbedtls_net_init(mbedtls_net_context *ctx);

int mbedtls_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto);

int mbedtls_net_bind(mbedtls_net_context *ctx, const char *bind_ip, const char *port, int proto);

int mbedtls_net_accept(mbedtls_net_context *bind_ctx,
                       mbedtls_net_context *client_ctx,
                       void *client_ip, size_t buf_size, size_t *ip_len);

int mbedtls_net_poll(mbedtls_net_context *ctx, uint32_t rw, uint32_t timeout);

int mbedtls_net_set_block(mbedtls_net_context *ctx);

int mbedtls_net_set_nonblock(mbedtls_net_context *ctx);

void mbedtls_net_usleep(unsigned long usec);

int mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len);

int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len);

int mbedtls_net_recv_timeout(void *ctx, unsigned char *buf, size_t len,
                             uint32_t timeout);

void mbedtls_net_close(mbedtls_net_context *ctx);

void mbedtls_net_free(mbedtls_net_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* net_sockets.h */
