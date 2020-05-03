#[macro_use]
extern crate bitflags;

#[derive(Debug)]
pub enum Error {
    /// Unexpected End-Of-File.
    UnexpectedEof,
    /// An address prefix is larger than `8 * address_length`.
    PrefixTooLarge,
}

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

/// A type-length-value
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

pub mod parser;
