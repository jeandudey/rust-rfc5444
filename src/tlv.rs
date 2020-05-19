// Copyright 2020 Jean Pierre Dudey. See the LICENSE-MIT and
// LICENSE-APACHE files at the top-level directory of this
// distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Buf, Error};

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

impl<'a> Tlv<'a> {
    /// Parse a `<tlv>`
    pub fn read(buf: &mut Buf<'a>) -> Result<Tlv<'a>, Error> {
        // Parse <tlv-type> and <tlv-flag>
        let r#type = buf.get_u8()?;
        let flags = buf.get_u8().map(TlvFlags::from_bits)?.unwrap();

        // Parse <tlv-type-ext> if exists
        let type_ext = if flags.contains(TlvFlags::HAS_TYPE_EXT) {
            Some(buf.get_u8()?)
        } else {
            None
        };

        // Parse (<index-start><index-end>?)?
        let has_single_idx = flags.contains(TlvFlags::HAS_SINGLE_INDEX);
        let has_multi_idx = flags.contains(TlvFlags::HAS_MULTI_INDEX);

        let mut start_index = None;
        let mut stop_index = None;
        match (has_single_idx, has_multi_idx) {
            // nothing
            (false, false) => (),
            // only <index-start>
            (true, false) => {
                start_index = Some(buf.get_u8()?);
            }
            // both <index-start>,<index-stop>
            (false, true) | (true, true) => {
                start_index = Some(buf.get_u8()?);
                stop_index = Some(buf.get_u8()?);
            }
        }

        // Parse <length><value>
        let has_value = flags.contains(TlvFlags::HAS_VALUE);
        let has_extlen = flags.contains(TlvFlags::HAS_EXT_LEN);

        let mut value = None;
        match (has_value, has_extlen) {
            // do nothing
            (false, false) | (false, true) => (),
            // <length> is 8 bits
            (true, false) => {
                let length = buf.get_u8().map(usize::from)?;
                if length > 0 {
                    value = Some(buf.get_bytes(length)?);
                }
            }
            // <length> is 16 bits
            (true, true) => {
                let length = buf.get_ne_u16().map(usize::from)?;
                if length > 0 {
                    value = Some(buf.get_bytes(length)?);
                }
            }
        }

        Ok(Tlv {
            r#type,
            type_ext,
            start_index,
            stop_index,
            value,
        })
    }
}

/// TLV block
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TlvBlock<'a> {
    buf: Buf<'a>,
}

impl<'a> TlvBlock<'a> {
    /// Parse a <tlv-block>
    pub fn read(buf: &mut Buf<'a>) -> Result<TlvBlock<'a>, Error> {
        let length = buf.get_ne_u16().map(usize::from)?;
        let block = buf.get_bytes(length).map(Buf::new)?;

        Ok(TlvBlock { buf: block })
    }

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

        match Tlv::read(&mut self.buf) {
            Ok(tlv) => Some(Ok(tlv)),
            Err(e) => Some(Err(e)),
        }
    }
}
