// Copyright 2020 Jean Pierre Dudey. See the LICENSE-MIT and
// LICENSE-APACHE files at the top-level directory of this
// distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![no_std]

use core::mem::transmute;
use libc::{c_int, size_t};

/// @brief   Supported RFC 5444 version.
pub const RFC5444_VERSION: u8 = 0;

/// @brief   Represents an slice of a buffer
#[repr(C)]
pub struct rfc5444_buf_t {
    /// Pointer to buffer
    pub buf: *const u8,
    /// Buffer size
    pub buf_len: usize,
}

/// @brief   Representation of an RFC 5444 packet.
#[repr(C)]
pub struct rfc5444_packet_t {
    /// Packet header
    pub hdr: rfc5444_pkt_header_t,
    /// Packet messages
    pub messages: rfc5444_messages_t,
}

/// @brief   Packet header
#[repr(C)]
pub struct rfc5444_pkt_header_t {
    /// Version
    pub version: u8,
    /// Has a seq_num?
    pub has_seq_num: bool,
    /// Sequence number
    pub seq_num: u16,
    /// Has a TLV block?
    pub has_tlv_block: bool,
}

/// @brief   Packet messages
#[repr(C)]
pub struct rfc5444_messages_t {
    /// Buffer containing the packet messages
    pub buf: rfc5444_buf_t,
}

/// @brief   Read a single RFC 5444 packet.
///
/// @pre `(buf != NULL) && (pkt != NULL)`
///
/// @param[in]  buf     The buffer with the packet data to parse/read.
/// @param[in]  buf_len `buf` length in bytes.
/// @param[out] pkt     The parsed packet.
///
/// @return 0 on successful parse.
/// @return -EOF on unexpected end of file.
/// @return -EINVAL on invalid packet.
#[no_mangle]
pub extern "C" fn rfc5444_read_packet(
    buf: *const u8,
    buf_len: size_t,
    pkt: *mut rfc5444_packet_t,
) -> c_int {
    let buf = unsafe { core::slice::from_raw_parts(buf, usize::from(buf_len)) };

    match rfc5444::read_packet(buf) {
        Ok(p) => {
            let pkt = unsafe {
                transmute::<*mut rfc5444_packet_t, &mut rfc5444_packet_t>(pkt)
            };

            pkt.hdr.version = p.hdr.version;
            pkt.hdr.has_seq_num = false;
            if let Some(seq_num) = p.hdr.seq_num {
                pkt.hdr.has_seq_num = true;
                pkt.hdr.seq_num = seq_num;
            }

            pkt.messages.buf.buf = p.messages.as_bytes().as_ptr();
            pkt.messages.buf.buf_len = p.messages.as_bytes().len();
        }
        Err(e) => match e {
            rfc5444::Error::UnexpectedEof => return -libc::EOF,
            rfc5444::Error::PrefixTooLarge | rfc5444::Error::InvalidVersion => {
                return -libc::EINVAL;
            }
        },
    }

    0
}
