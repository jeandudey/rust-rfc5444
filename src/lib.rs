//! # `rust-rfc5444`
//!
//! <p align="center">
//!   <a href="">
//!   </a>
//!   <br>
//!   RFC 5444
//! </p>

#[macro_use]
extern crate bitflags;

#[derive(Debug)]
pub enum Error {
    /// Unexpected End-Of-File.
    UnexpectedEof,
    /// An address prefix is larger than `8 * address_length`.
    PrefixTooLarge,
    /// Invalid version
    InvalidVersion,
}

macro_rules! make_slice {
    ($buf:expr, $start:expr, $end:expr) => {{
        let buf = &$buf[$start..];
        let buf = &buf[..$end];
        buf
    }}
}

/// Parser buffer.
pub struct Buf<'a> {
    /// Internal buffer.
    buf: &'a [u8],
    /// Current offset.
    off: usize,
}

impl<'a> Buf<'a> {
    /// Create a new `Buf`
    #[inline(always)]
    pub fn new(buf: &'a [u8]) -> Buf<'a> {
        Buf {
            buf,
            off: 0,
        }
    }

    /// Check if we have sufficient bytes available to read. Returns an error
    /// on EOF.
    #[inline(always)]
    fn err_on_eof(&self, needed: usize) -> Result<(), Error> {
        if self.buf[self.off..].len() < needed {
            return Err(Error::UnexpectedEof);
        }
        Ok(())
    }

    pub fn is_eof(&self) -> bool {
        self.off >= self.buf.len()
    }

    /// Retrieve an `u8` from the buffer.
    #[inline(always)]
    pub fn get_u8(&mut self) -> Result<u8, Error> {
        self.err_on_eof(1)?;

        let v = self.buf[self.off];
        self.off += 1;
        Ok(v)
    }

    /// Read an `u16` in network-endian from the buffer.
    #[inline(always)]
    pub fn get_ne_u16(&mut self) -> Result<u16, Error> {
        self.err_on_eof(2)?;

        let mut ne_u16_b = [0u8; 2];
        ne_u16_b.copy_from_slice(make_slice!(self.buf, self.off, 2));
        self.off += 2;
        Ok(u16::from_be_bytes(ne_u16_b))
    }

    /// Read a byte slice.
    #[inline(always)]
    pub fn get_bytes(&mut self, count: usize) -> Result<&'a [u8], Error> {
        self.err_on_eof(count)?;
        let b = make_slice!(self.buf, self.off, count);
        self.off += count;
        Ok(b)
    }
}

/// Supported version of RFC 5444.
const RFC5444_VERSION: u8 = 0;

pub struct PktHeader<'a> {
    /// RFC 5444 version
    pub version: u8,
    /// Sequence number
    pub seq_num: Option<u16>,
    /// TLV block
    pub tlv_block: Option<TlvBlockIterator<'a>>,
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

/// Iterator over a TLV block
pub struct TlvBlockIterator<'a> {
    /// Tlv block buffer
    buf: Buf<'a>,
}

impl<'a> Iterator for TlvBlockIterator<'a> {
    type Item = Result<Tlv<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_eof() {
            return None;
        }

        match parser::tlv(&mut self.buf) {
            Ok(tlv) => {
                return Some(Ok(tlv));
            },
            Err(e) => Some(Err(e)),
        }
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
