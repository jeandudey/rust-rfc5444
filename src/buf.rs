use crate::Error;

macro_rules! make_slice {
    ($buf:expr, $off:expr, $count:expr) => {{
        let buf = &$buf[$off..];
        let buf = &buf[..$count];
        buf
    }};
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
#[derive(Debug)]
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
    pub fn is_eof(&self) -> bool {
        self.off >= self.buf.len()
    }

    /// Current position in the buffer
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
