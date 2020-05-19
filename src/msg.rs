// Copyright 2020 Jean Pierre Dudey. See the LICENSE-MIT and
// LICENSE-APACHE files at the top-level directory of this
// distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{AddressTlvs, Buf, Error, TlvBlock};

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

impl<'a> Message<'a> {
    /// Read a message
    pub fn read(buf: &mut Buf<'a>) -> Result<Message<'a>, Error> {
        let initial_offset = buf.pos();

        let hdr = MsgHeader::read(buf)?;
        let msg_tlv_block = TlvBlock::read(buf)?;

        let count = buf.pos() - initial_offset;
        let restant_bytes = hdr.size - count;

        let address_tlv = AddressTlvs {
            address_length: hdr.address_length,
            buf: Buf::new(buf.get_bytes(restant_bytes)?),
        };

        Ok(Message {
            hdr,
            tlv_block: msg_tlv_block,
            address_tlv,
        })
    }
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

impl<'a> MsgHeader<'a> {
    /// Read the message header
    pub fn read(buf: &mut Buf<'a>) -> Result<MsgHeader<'a>, Error> {
        // Parse <msg-type>
        let r#type = buf.get_u8()?;

        // Parse <msg-flags> <msg-addr-length>
        let (flags, address_length) = buf.get_u8().map(|b| {
            // TODO: verify these flags and masks
            let flags = MsgHeaderFlags::from_bits(b & 0xf0).unwrap();
            let len = usize::from(b & 0x0f) + 1;
            (flags, len)
        })?;

        // Parse <msg-size>
        let size = buf.get_ne_u16().map(usize::from)?;

        // Parse <msg-orig-addr>
        let has_orig = flags.contains(MsgHeaderFlags::HAS_ORIG);

        let orig_addr = if has_orig {
            Some(buf.get_bytes(address_length)?)
        } else {
            None
        };

        // Parse <msg-hop-limit>
        let has_hop_limit = flags.contains(MsgHeaderFlags::HAS_HOP_LIMIT);

        let hop_limit = if has_hop_limit {
            Some(buf.get_u8()?)
        } else {
            None
        };

        // Parse <msg-hop-count>
        let has_hop_count = flags.contains(MsgHeaderFlags::HAS_HOP_COUNT);

        let hop_count = if has_hop_count {
            Some(buf.get_u8()?)
        } else {
            None
        };

        // Parse <msg-seq-num>
        let has_seq_num = flags.contains(MsgHeaderFlags::HAS_SEQ_NUM);

        let seq_num = if has_seq_num {
            Some(buf.get_ne_u16()?)
        } else {
            None
        };

        Ok(MsgHeader {
            r#type,
            address_length,
            size,
            orig_addr,
            hop_limit,
            hop_count,
            seq_num,
        })
    }
}

/// Packet messages
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Messages<'a> {
    buf: Buf<'a>,
}

impl<'a> Messages<'a> {
    /// Read `Messages` from the given buffer.
    pub fn from_buf(buf: Buf<'a>) -> Messages<'a> {
        Messages { buf }
    }

    /// Get the bytes of all the messages
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf.buf
    }

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

        match Message::read(&mut self.buf) {
            Ok(a) => Some(Ok(a)),
            Err(e) => Some(Err(e)),
        }
    }
}
