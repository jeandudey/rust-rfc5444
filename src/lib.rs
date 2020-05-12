// Copyright 2020 Jean Pierre Dudey. See the LICENSE-MIT and
// LICENSE-APACHE files at the top-level directory of this
// distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # `rust-rfc5444`
//!
//! <p align="center">
//!   <a href="https://tools.ietf.org/html/rfc5444">
//!     Generalized Mobile Ad Hoc Network (MANET) Packet/Message Format
//!   </a>
//!   <br>
//!   RFC 5444
//! </p>
//!
//! # Introduction
//!
//! This is a crate for parsing and creating RFC 5444 packets, it's mean to be
//! fully compatible with the implementation and support all of the use cases.
//!
//! Also this crate has as it's goal to be small and embedded-friendly, with
//! full `no_std` support. This library should be useful for low-latency
//! applications, and as such, use of the heap is prohibited (unless you use
//! `use_std`).
//!
//! Other goal is to be secure, that means, 0 crashes, good error handling, and
//! well tested/fuzzed code. Also this means that usage of `unsafe` is banned
//! even for dependencies.
//!
//! # Non goals
//!
//! This library doesn't aims to be a "server" of some sort, or to handle any
//! logic in the packets, that's up to you, here the hard part is done to leave
//! the other things more simple such as handling sequence numbers, we don't
//! touch sequence numbers, nor we increment/decrement hop count, hop limits,
//! etc.
//!
//! # Minimum Supported Rust Version
//!
//! As a minimum the goal is to support Debian oldoldstable [`rustc`][deb]
//! (1.34.2 right now). Newer `rustc` versions will be supported when Debian
//! updates their `rustc` for Debian oldoldstable.
//!
//! Breakage of MSRV will be done in the minor versions when on `<1`. When a
//! stable version is released, the major verison **will** be incremented to not
//! break dependant crates depending on the MSRV.
//!
//! [deb]: https://packages.debian.org/jessie/rust-doc
//!
//! # Features
//!
//! - `use_std`: (default) enables usage of `std`, disable it to be compatible
//! with `no_std`.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "use_std"), no_std)]

#[macro_use]
extern crate bitflags;

mod buf;
mod parser;

use crate::buf::Buf;
pub use parser::read_packet;

/// RFC 5444 error
#[derive(Debug)]
pub enum Error {
    /// Unexpected End-Of-File.
    UnexpectedEof,
    /// An address prefix is larger than `8 * address_length`.
    PrefixTooLarge,
    /// Invalid version
    InvalidVersion,
}

#[cfg(feature = "use_std")]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match *self {
            Error::UnexpectedEof => write!(f, "Unexpected EOF"),
            Error::PrefixTooLarge => write!(f, "Address prefix is too large"),
            Error::InvalidVersion => {
                write!(f, "Version is invalid, not supported")
            }
        }
    }
}

#[cfg(feature = "use_std")]
impl std::error::Error for Error {}

/// Supported version of RFC 5444.
pub const RFC5444_VERSION: u8 = 0;

/// Packet
#[derive(Debug)]
pub struct Packet<'a> {
    /// Packet header
    pub hdr: PktHeader<'a>,
    /// Messages
    pub messages: Messages<'a>,
}

/// Packet messages
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Messages<'a> {
    buf: Buf<'a>,
}

impl<'a> Messages<'a> {
    /// Iterator over each message
    pub fn iter(&self) -> MessageIter<'a> {
        MessageIter {
            buf: self.buf.clone(),
        }
    }
}

/// Iterator over messages
#[derive(Debug)]
pub struct MessageIter<'a> {
    buf: Buf<'a>,
}

impl<'a> Iterator for MessageIter<'a> {
    type Item = Result<Message<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_eof() {
            return None;
        }

        match parser::message(&mut self.buf) {
            Ok(a) => Some(Ok(a)),
            Err(e) => Some(Err(e)),
        }
    }
}

/// Address-TLVs
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AddressTlvs<'a> {
    address_length: usize,
    buf: Buf<'a>,
}

impl<'a> AddressTlvs<'a> {
    /// Iterator over Address-TLVs
    pub fn iter(&self) -> AddressTlvIter<'a> {
        AddressTlvIter {
            address_length: self.address_length,
            buf: self.buf.clone(),
        }
    }
}

/// Iterator over a TLV block
#[derive(Debug)]
pub struct AddressTlvIter<'a> {
    address_length: usize,
    /// `(<address-block><tlb-block>)*` buffer
    buf: Buf<'a>,
}

impl<'a> Iterator for AddressTlvIter<'a> {
    type Item = Result<(AddressBlock<'a>, TlvBlock<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_eof() {
            return None;
        }

        let address_block =
            parser::address_block(&mut self.buf, self.address_length);
        let address_block = match address_block {
            Ok(a) => a,
            Err(e) => return Some(Err(e)),
        };

        let tlv_block = parser::tlv_block(&mut self.buf);
        let tlv_block = match tlv_block {
            Ok(t) => t,
            Err(e) => return Some(Err(e)),
        };

        Some(Ok((address_block, tlv_block)))
    }
}

/// Message.
#[derive(Debug)]
pub struct Message<'a> {
    /// Message header.
    pub hdr: MsgHeader<'a>,
    /// TLV block
    pub tlv_block: TlvBlock<'a>,
    /// Address block/TLV block iterator
    pub address_tlv: AddressTlvs<'a>,
}

/// Message header.
#[derive(Debug)]
pub struct MsgHeader<'a> {
    /// Message type.
    pub r#type: u8,
    /// Adress size in bytes.
    pub address_length: usize,
    /// Total size in bytes of the `<message>` including `<msg-header>`
    size: usize,
    /// Originator address.
    pub orig_addr: Option<&'a [u8]>,
    /// Hop limit.
    pub hop_limit: Option<u8>,
    /// Hop count.
    pub hop_count: Option<u8>,
    /// Sequence number.
    pub seq_num: Option<u16>,
}

bitflags! {
    /// Message header flags.
    struct MsgHeaderFlags: u8 {
        const HAS_ORIG      = 0x80;
        const HAS_HOP_LIMIT = 0x40;
        const HAS_HOP_COUNT = 0x20;
        const HAS_SEQ_NUM   = 0x10;
        const RESERVED0     = 0x08;
        const RESERVED1     = 0x02;
        const RESERVED2     = 0x01;
    }
}

/// Packet header.
#[derive(Debug)]
pub struct PktHeader<'a> {
    /// RFC 5444 version
    pub version: u8,
    /// Sequence number
    pub seq_num: Option<u16>,
    /// TLV block
    pub tlv_block: Option<TlvBlock<'a>>,
}

bitflags! {
    struct PktHeaderFlags: u8 {
        const UNUSED0     = 0x80;
        const UNUSED1     = 0x40;
        const UNUSED2     = 0x20;
        const UNUSED3     = 0x10;
        const HAS_SEQ_NUM = 0x08;
        const HAS_TLV     = 0x04;
        const RESERVED0   = 0x02;
        const RESERVED1   = 0x01;
    }
}

/// Address block
#[derive(Debug)]
pub struct AddressBlock<'a> {
    /// Address count.
    pub num_addr: usize,
    /// <head>
    pub head: Option<&'a [u8]>,
    /// <tail>
    pub tail: Option<&'a [u8]>,
    /// <mid>
    pub mid: Option<&'a [u8]>,
    /// Prefix lengths
    pub prefix_lengths: Option<&'a [u8]>,
}

bitflags! {
    struct AddressBlockFlags: u8 {
        const HAS_HEAD          = 0x80;
        const HAS_FULL_TAIL     = 0x40;
        const HAS_ZERO_TAIL     = 0x20;
        const HAS_SINGLE_PRELEN = 0x10;
        const HAS_MULTI_PRELEN  = 0x08;
        const RESERVED0         = 0x04;
        const RESERVED1         = 0x02;
        const RESERVED2         = 0x01;
    }
}

/// TLV block
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TlvBlock<'a> {
    buf: Buf<'a>,
}

impl<'a> TlvBlock<'a> {
    /// Iterator over a TLV block entries
    pub fn iter(&self) -> TlvBlockIter<'a> {
        TlvBlockIter {
            buf: self.buf.clone(),
        }
    }
}

/// Iterator over a TLV block
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TlvBlockIter<'a> {
    /// Tlv block buffer
    buf: Buf<'a>,
}

impl<'a> Iterator for TlvBlockIter<'a> {
    type Item = Result<Tlv<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_eof() {
            return None;
        }

        match parser::tlv(&mut self.buf) {
            Ok(tlv) => {
                return Some(Ok(tlv));
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// A type-length-value
#[derive(Debug)]
pub struct Tlv<'a> {
    /// Type
    pub r#type: u8,
    /// Type extension
    pub type_ext: Option<u8>,
    /// Start index
    pub start_index: Option<u8>,
    /// Stop index
    pub stop_index: Option<u8>,
    /// Value
    pub value: Option<&'a [u8]>,
}

bitflags! {
    struct TlvFlags: u8 {
        const HAS_TYPE_EXT     = 0x80;
        const HAS_SINGLE_INDEX = 0x40;
        const HAS_MULTI_INDEX  = 0x20;
        const HAS_VALUE        = 0x10;
        const HAS_EXT_LEN      = 0x08;
        const IS_MULTI_VALUE   = 0x04;
        const RESERVED0        = 0x02;
        const RESERVED1        = 0x01;
    }
}
