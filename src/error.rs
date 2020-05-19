// Copyright 2020 Jean Pierre Dudey. See the LICENSE-MIT and
// LICENSE-APACHE files at the top-level directory of this
// distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// RFC 5444 error
#[derive(Debug)]
pub enum Error {
    /// Unexpected End-Of-File.
    UnexpectedEof,
    /// An address prefix is larger than `8 * address_length`.
    PrefixTooLarge,
    /// Invalid version
    InvalidVersion,
}

#[cfg(feature = "use_std")]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match *self {
            Error::UnexpectedEof => write!(f, "Unexpected EOF"),
            Error::PrefixTooLarge => write!(f, "Address prefix is too large"),
            Error::InvalidVersion => {
                write!(f, "Version is invalid, not supported")
            }
        }
    }
}

#[cfg(feature = "use_std")]
impl std::error::Error for Error {}
