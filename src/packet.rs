// Copyright 2020 Jean Pierre Dudey. See the LICENSE-MIT and
// LICENSE-APACHE files at the top-level directory of this
// distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Buf, Error, Messages, TlvBlock, RFC5444_VERSION};

/// Packet
#[derive(Debug)]
pub struct Packet<'a> {
    /// Packet header
    pub hdr: PktHeader<'a>,
    /// Messages
    pub messages: Messages<'a>,
}

impl<'a> Packet<'a> {
    /// Read an RFC 5444 packet
    pub fn read(buf: &'a [u8]) -> Result<Packet<'a>, Error> {
        let mut buf = Buf::new(buf);

        let hdr = PktHeader::read(&mut buf)?;

        let messages = Messages::from_buf(buf);

        Ok(Packet { hdr, messages })
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

impl<'a> PktHeader<'a> {
    /// Read a packet header
    fn read(buf: &mut Buf<'a>) -> Result<PktHeader<'a>, Error> {
        // Parse <version> and <pkt-flags>
        let (version, flags) = buf.get_u8().map(|b| {
            (
                (b & 0xf0) >> 4,
                PktHeaderFlags::from_bits(b & 0x0f).unwrap(),
            )
        })?;

        if version != RFC5444_VERSION {
            return Err(Error::InvalidVersion);
        }

        // Parse <pkt-seq-num>?
        let has_seq_num = flags.contains(PktHeaderFlags::HAS_SEQ_NUM);

        let seq_num = if has_seq_num {
            Some(buf.get_ne_u16()?)
        } else {
            None
        };

        // Parse <tlv-block>?
        let has_tlv = flags.contains(PktHeaderFlags::HAS_TLV);

        let block = if has_tlv {
            Some(TlvBlock::read(buf)?)
        } else {
            None
        };

        Ok(PktHeader {
            version,
            seq_num,
            tlv_block: block,
        })
    }
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
