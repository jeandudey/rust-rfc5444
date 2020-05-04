use crate::{
    AddressBlock, AddressBlockFlags, AddressTlvIterator, Buf, Error, Message, MessageIterator,
    MsgHeader, MsgHeaderFlags, Packet, PktHeader, PktHeaderFlags, Tlv, TlvBlockIterator, TlvFlags,
    RFC5444_VERSION,
};

pub fn packet<'a>(buf: &'a [u8]) -> Result<Packet<'a>, Error> {
    let mut buf = Buf::new(buf);

    let hdr = pkt_header(&mut buf)?;

    let messages = MessageIterator { buf };

    Ok(Packet { hdr, messages })
}

pub fn message<'a>(buf: &mut Buf<'a>) -> Result<Message<'a>, Error> {
    let initial_offset = buf.pos();

    let hdr = msg_header(buf)?;
    let msg_tlv_block = tlv_block(buf)?;

    let count = buf.pos() - initial_offset;
    let restant_bytes = hdr.size - count;

    let address_tlv = AddressTlvIterator {
        address_length: hdr.address_length,
        buf: Buf::new(buf.get_bytes(restant_bytes)?),
    };

    Ok(Message {
        hdr,
        tlv_block: msg_tlv_block,
        address_tlv,
    })
}

pub fn msg_header<'a>(buf: &mut Buf<'a>) -> Result<MsgHeader<'a>, Error> {
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

    let mut orig_addr = None;
    if has_orig {
        orig_addr = Some(buf.get_bytes(address_length)?);
    }

    // Parse <msg-hop-limit>
    let has_hop_limit = flags.contains(MsgHeaderFlags::HAS_HOP_LIMIT);

    let mut hop_limit = None;
    if has_hop_limit {
        hop_limit = Some(buf.get_u8()?);
    }

    // Parse <msg-hop-count>
    let has_hop_count = flags.contains(MsgHeaderFlags::HAS_HOP_COUNT);

    let mut hop_count = None;
    if has_hop_count {
        hop_count = Some(buf.get_u8()?);
    }

    // Parse <msg-seq-num>
    let has_seq_num = flags.contains(MsgHeaderFlags::HAS_SEQ_NUM);

    let mut seq_num = None;
    if has_seq_num {
        seq_num = Some(buf.get_ne_u16()?);
    }

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

pub fn pkt_header<'a>(buf: &mut Buf<'a>) -> Result<PktHeader<'a>, Error> {
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

    let mut seq_num = None;
    if has_seq_num {
        seq_num = Some(buf.get_ne_u16()?);
    }

    // Parse <tlv-block>?
    let has_tlv = flags.contains(PktHeaderFlags::HAS_SEQ_NUM);

    let mut block = None;
    if has_tlv {
        block = Some(tlv_block(buf)?);
    }

    Ok(PktHeader {
        version,
        seq_num,
        tlv_block: block,
    })
}

pub fn address_block<'a>(
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
    let has_full_tail = addr_flags.contains(AddressBlockFlags::HAS_FULL_TAIL);
    let has_zero_tail = addr_flags.contains(AddressBlockFlags::HAS_ZERO_TAIL);
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
    let mut mid = None;
    if mid_length != 0 {
        mid = Some(buf.get_bytes(mid_length)?);
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
        (true, true) => (),
    }

    let mut prefix_lengths = None;
    if prefix_length_fields != 0 {
        let pfs = buf.get_bytes(prefix_length_fields)?;
        for pf in pfs {
            if usize::from(*pf) > (8 * address_length) {
                return Err(Error::PrefixTooLarge);
            }
        }

        prefix_lengths = Some(pfs);
    }

    Ok(AddressBlock {
        num_addr,
        head,
        tail,
        mid,
        prefix_lengths,
    })
}

/// Parse a <tlv-block>
pub fn tlv_block<'a>(buf: &mut Buf<'a>) -> Result<TlvBlockIterator<'a>, Error> {
    let length = buf.get_ne_u16().map(usize::from)?;
    let block = buf.get_bytes(length).map(Buf::new)?;

    Ok(TlvBlockIterator { buf: block })
}

/// Parse a `<tlv>`
pub fn tlv<'a>(buf: &mut Buf<'a>) -> Result<Tlv<'a>, Error> {
    // Parse <tlv-type> and <tlv-flag>
    let r#type = buf.get_u8()?;
    let flags = buf.get_u8().map(TlvFlags::from_bits)?.unwrap();

    // Parse <tlv-type-ext> if exists
    let mut type_ext = None;
    if flags.contains(TlvFlags::HAS_TYPE_EXT) {
        type_ext = Some(buf.get_u8()?);
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
