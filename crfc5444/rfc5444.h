/*
 * Copyright 2020 Jean Pierre Dudey. See the LICENSE-MIT and
 * LICENSE-APACHE files at the top-level directory of this
 * distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */


#ifndef RUST_RFC5444_H
#define RUST_RFC5444_H

/* Generated with cbindgen:0.14.2 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/**
 * @brief   Supported RFC 5444 version.
 */
#define RFC5444_VERSION 0

/**
 * @brief   Packet header
 */
typedef struct {
    /**
     * Version
     */
    uint8_t version;
    /**
     * Has a seq_num?
     */
    bool has_seq_num;
    /**
     * Sequence number
     */
    uint16_t seq_num;
    /**
     * Has a TLV block?
     */
    bool has_tlv_block;
} rfc5444_pkt_header_t;

/**
 * @brief   Represents an slice of a buffer
 */
typedef struct {
    /**
     * Pointer to buffer
     */
    const uint8_t *buf;
    /**
     * Buffer size
     */
    uintptr_t buf_len;
} rfc5444_buf_t;

/**
 * @brief   Packet messages
 */
typedef struct {
    /**
     * Buffer containing the packet messages
     */
    rfc5444_buf_t buf;
} rfc5444_messages_t;

/**
 * @brief   Representation of an RFC 5444 packet.
 */
typedef struct {
    /**
     * Packet header
     */
    rfc5444_pkt_header_t hdr;
    /**
     * Packet messages
     */
    rfc5444_messages_t messages;
} rfc5444_packet_t;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief   Read a single RFC 5444 packet.
 *
 * @pre `(buf != NULL) && (pkt != NULL)`
 *
 * @param[in]  buf     The buffer with the packet data to parse/read.
 * @param[in]  buf_len `buf` length in bytes.
 * @param[out] pkt     The parsed packet.
 *
 * @return 0 on successful parse.
 * @return -EOF on unexpected end of file.
 * @return -EINVAL on invalid packet.
 */
int rfc5444_read_packet(const uint8_t *buf,
                        size_t buf_len,
                        rfc5444_packet_t *pkt);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* RUST_RFC5444_H */
