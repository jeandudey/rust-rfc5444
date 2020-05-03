use crate::{AddressBlock, AddressBlockFlags, Error, Tlv, TlvFlags};

#[inline(always)]
fn check_len(input: &[u8], len: usize) -> Result<(), Error> {
    if input.len() < len {
        return Err(Error::UnexpectedEof);
    }

    Ok(())
}

fn parse_u16<'a>(input: &'a [u8]) -> Result<(&'a [u8], usize), Error> {
    check_len(input, 2)?;

    let mut length_buf = [0u8; 2];
    let l = &input[..2];
    length_buf.copy_from_slice(l);
    let length = usize::from(u16::from_be_bytes(length_buf));

    Ok((&input[2..], length))
}

pub fn address_block<'a>(
    input: &'a [u8],
    address_length: usize,
) -> Result<(&'a [u8], AddressBlock), Error> {
    check_len(input, 2)?;

    // Parse <num-addr> and <addr-flags>
    let mut i = 0;
    let num_addr = usize::from(input[i]);
    let addr_flags = AddressBlockFlags::from_bits(input[i + 1]).unwrap();
    i += 2;

    let mut head_length = 0;
    let mut head = None;
    let has_head = addr_flags.contains(AddressBlockFlags::HAS_HEAD);
    if has_head {
        check_len(&input[i..], 1)?;
        head_length = usize::from(input[i]);
        i += 1;
        check_len(&input[i..], head_length)?;
        let h = &input[i..];
        head = Some(&h[..head_length]);
        i += head_length;
    }

    // Parse (<tail-length><tail>?)?
    let mut tail_length = 0;
    let mut tail = None;
    let has_full_tail = addr_flags.contains(AddressBlockFlags::HAS_FULL_TAIL);
    let has_zero_tail = addr_flags.contains(AddressBlockFlags::HAS_ZERO_TAIL);
    match (has_full_tail, has_zero_tail) {
        // do nothing
        (false, false) | (true, true) => (),
        // parse <tail-length> and <tail> (if <tail-length> is not 0)
        (true, false) => {
            tail_length = usize::from(input[i]);
            i += 1;

            if tail_length != 0 {
                let t = &input[i..];
                tail = Some(&t[..tail_length]);
                i += tail_length;
            }
        },
        // parse <tail-length>
        (false, true) => {
            tail_length = usize::from(input[i]);
            i += 1;
        },
    }

    // Parse <mid>*
    let mid_length = address_length - head_length - tail_length;
    let mut mid = None;
    if mid_length != 0 {
        let m = &input[i..];
        mid = Some(&m[..mid_length]);
        i += mid_length;
    }

    // Parse <prefix-length>*
    let has_single_prelen = addr_flags.contains(AddressBlockFlags::HAS_SINGLE_PRELEN);
    let has_multi_prelen = addr_flags.contains(AddressBlockFlags::HAS_MULTI_PRELEN);
    let mut prefix_length_fields = 0;
    match (has_single_prelen, has_multi_prelen) {
        // no fields
        (false, false) => prefix_length_fields = 0,
        // single field
        (true, false) => prefix_length_fields = 1,
        // <num-addr> fields
        (false, true) => prefix_length_fields = num_addr,
        // ignore both
        (true, true) => ()
    }

    let mut prefix_lengths = None;
    if prefix_length_fields != 0 {
        let pfs = &input[i..];
        prefix_lengths = Some(&pfs[..prefix_length_fields]);
        i += prefix_length_fields;

        for pf in prefix_lengths.unwrap() {
            if usize::from(*pf) > (8 * address_length) {
                return Err(Error::PrefixTooLarge);
            }
        }
    }

    let addr_block = AddressBlock {
        num_addr,
        head,
        tail,
        mid,
        prefix_lengths,
    };

    Ok((&input[i..], addr_block))
}

/// Iterator over a TLV block
pub struct TlvBlockIterator<'a> {
    /// Tlv block buffer
    buf: &'a [u8],
}

impl<'a> Iterator for TlvBlockIterator<'a> {
    type Item = Result<Tlv<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() == 0 {
            return None;
        }

        match tlv(self.buf) {
            Ok((buf, tlv)) => {
                self.buf = buf;
                return Some(Ok(tlv));
            },
            Err(e) => Some(Err(e)),
        }
    }
}

/// Parse a <tlv-block>
pub fn tlv_block<'a>(
    input: &'a [u8]
) -> Result<(&'a [u8], TlvBlockIterator<'a>), Error> {
    let (input, length) = parse_u16(input)?;
    check_len(input, length)?;

    let iter = TlvBlockIterator {
        buf: input,
    };

    Ok((&input[length..], iter))
}

/// Parse a `<tlv>`
pub fn tlv<'a>(input: &'a [u8]) -> Result<(&'a [u8], Tlv<'a>), Error> {
    let mut i = 0;

    check_len(input, 2)?;

    // Parse <tlv-type> and <tlv-flag>
    let r#type = input[i];
    let flags = TlvFlags::from_bits(input[i + 1]).unwrap();
    i += 2;

    // Parse <tlv-type-ext> if exists
    let mut type_ext = None;
    if flags.contains(TlvFlags::HAS_TYPE_EXT) {
        check_len(&input[i..], 1)?;
        type_ext = Some(input[i]);
        i += 1;
    }

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
            check_len(&input[i..], 1)?;
            start_index = Some(input[i]);
            i += 1;
        },
        // both <index-start>,<index-stop>
        (false, true) | (true, true) => {
            check_len(&input[i..], 2)?;
            start_index = Some(input[i]);
            stop_index = Some(input[i + 1]);
            i += 2;
        },
    }

    // Parse <length><value>
    let mut value = None;
    let has_value = flags.contains(TlvFlags::HAS_VALUE);
    let has_extlen = flags.contains(TlvFlags::HAS_EXT_LEN);
    match (has_value, has_extlen) {
        // do nothing
        (false, false) | (false, true) => (),
        // <length> is 8 bits
        (true, false) => {
            check_len(&input[i..], 1)?;
            let length = usize::from(input[i]);
            i += 1;

            if length > 0 {
                check_len(&input[i..], length)?;
                let v = &input[i..];
                let v = &v[..length];
                i += length;
                value = Some(v);
            }
        }
        // <length> is 16 bits
        (true, true) => {
            let (_, length) = parse_u16(&input[i..])?;
            i += 2;

            if length > 0 {
                check_len(&input[i..], length)?;
                let v = &input[i..];
                let v = &v[..length];
                i += length;
                value = Some(v);
            }
        }
    }

    let tlv = Tlv {
        r#type,
        type_ext,
        start_index,
        stop_index,
        value,
    };

    Ok((&input[i..], tlv))
}
