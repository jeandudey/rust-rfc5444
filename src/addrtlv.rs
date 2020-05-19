// Copyright 2020 Jean Pierre Dudey. See the LICENSE-MIT and
// LICENSE-APACHE files at the top-level directory of this
// distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Buf, Error, TlvBlock};

/// Address-TLVs
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AddressTlvs<'a> {
    pub(crate) address_length: usize,
    pub(crate) buf: Buf<'a>,
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
            AddressBlock::read(&mut self.buf, self.address_length);
        let address_block = match address_block {
            Ok(a) => a,
            Err(e) => return Some(Err(e)),
        };

        let tlv_block = TlvBlock::read(&mut self.buf);
        let tlv_block = match tlv_block {
            Ok(t) => t,
            Err(e) => return Some(Err(e)),
        };

        Some(Ok((address_block, tlv_block)))
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

impl<'a> AddressBlock<'a> {
    /// Read an AddressBlock
    pub fn read(
        buf: &mut Buf<'a>,
        address_length: usize,
    ) -> Result<AddressBlock<'a>, Error> {
        // Parse <num-addr> and <addr-flags>
        let num_addr = buf.get_u8().map(usize::from)?;
        let addr_flags = AddressBlockFlags::from_bits(buf.get_u8()?).unwrap();

        let mut head_length = 0;
        let mut head = None;
        let has_head = addr_flags.contains(AddressBlockFlags::HAS_HEAD);
        if has_head {
            head_length = buf.get_u8().map(usize::from)?;
            head = Some(buf.get_bytes(head_length)?);
        }

        // Parse (<tail-length><tail>?)?
        let mut tail_length = 0;
        let mut tail = None;
        let has_full_tail =
            addr_flags.contains(AddressBlockFlags::HAS_FULL_TAIL);
        let has_zero_tail =
            addr_flags.contains(AddressBlockFlags::HAS_ZERO_TAIL);
        match (has_full_tail, has_zero_tail) {
            // do nothing
            (false, false) | (true, true) => (),
            // parse <tail-length> and <tail> (if <tail-length> is not 0)
            (true, false) => {
                tail_length = buf.get_u8().map(usize::from)?;

                if tail_length != 0 {
                    tail = Some(buf.get_bytes(tail_length)?);
                }
            }
            // parse <tail-length>
            (false, true) => {
                tail_length = buf.get_u8().map(usize::from)?;
            }
        }

        // Parse <mid>*
        let mid_length = address_length - head_length - tail_length;
        let mid = if mid_length != 0 {
            Some(buf.get_bytes(mid_length * num_addr)?)
        } else {
            None
        };

        // Parse <prefix-length>*
        let has_single_prelen =
            addr_flags.contains(AddressBlockFlags::HAS_SINGLE_PRELEN);
        let has_multi_prelen =
            addr_flags.contains(AddressBlockFlags::HAS_MULTI_PRELEN);
        let prefix_length_fields = match (has_single_prelen, has_multi_prelen) {
            // no fields
            (false, false) | (true, true) => 0,
            // single field
            (true, false) => 1,
            // <num-addr> fields
            (false, true) => num_addr,
        };

        let prefix_lengths = if prefix_length_fields != 0 {
            let pfs = buf.get_bytes(prefix_length_fields)?;
            for pf in pfs {
                if usize::from(*pf) > (8 * address_length) {
                    return Err(Error::PrefixTooLarge);
                }
            }

            Some(pfs)
        } else {
            None
        };

        Ok(AddressBlock {
            num_addr,
            head,
            tail,
            mid,
            prefix_lengths,
        })
    }
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
