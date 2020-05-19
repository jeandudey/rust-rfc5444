// Copyright 2020 Jean Pierre Dudey. See the LICENSE-MIT and
// LICENSE-APACHE files at the top-level directory of this
// distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::Error;

macro_rules! make_slice {
    ($buf:expr, $off:expr, $count:expr) => {
        &((&$buf[$off..])[..$count])
    };
}

#[test]
fn test_make_slice() {
    const BUF: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0xba, 0xbe, 0xca, 0xfe];
    let s0 = make_slice!(BUF, 1, 2);
    let s1 = make_slice!(BUF, 3, 2);
    let s2 = make_slice!(BUF, 5, 2);
    assert_eq!(s0, &[0xad, 0xbe]);
    assert_eq!(s1, &[0xef, 0xba]);
    assert_eq!(s2, &[0xbe, 0xca]);
}

/// Parser buffer.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Buf<'a> {
    /// Internal buffer.
    pub(crate) buf: &'a [u8],
    /// Current offset.
    off: usize,
}

impl<'a> Buf<'a> {
    /// Create a new `Buf`
    #[inline(always)]
    pub fn new(buf: &'a [u8]) -> Buf<'a> {
        Buf { buf, off: 0 }
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

    /// Is End-of-File?
    #[inline(always)]
    pub fn is_eof(&self) -> bool {
        self.off >= self.buf.len()
    }

    /// Current position in the buffer
    #[inline(always)]
    pub fn pos(&self) -> usize {
        self.off
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

#[cfg(test)]
pub mod test {
    use crate::buf::Buf;

    const BUF: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0xba, 0xbe, 0xca, 0xfe];

    #[test]
    fn test_buf_get_bytes() {
        let mut buf = Buf::new(BUF);
        let bytes = buf.get_bytes(4).unwrap();
        assert_eq!(bytes, &BUF[..4]);
        assert_eq!(buf.pos(), 4);
    }

    #[test]
    fn test_buf_get_ne_u16() {
        let mut buf = Buf::new(BUF);
        assert_eq!(buf.get_ne_u16().unwrap(), 0xdead);
        assert_eq!(buf.pos(), 2);
        assert_eq!(buf.get_ne_u16().unwrap(), 0xbeef);
        assert_eq!(buf.pos(), 4);
    }

    #[test]
    fn test_buf_get_u8() {
        let mut buf = Buf::new(BUF);
        for (i, c) in BUF.iter().enumerate() {
            assert_eq!(i, buf.pos());
            assert_eq!(*c, buf.get_u8().unwrap());
        }
    }

    #[test]
    fn test_buf_is_eof() {
        let mut buf = Buf::new(BUF);
        for _ in BUF {
            buf.get_u8().unwrap();
        }
        assert!(buf.is_eof());
    }
}
