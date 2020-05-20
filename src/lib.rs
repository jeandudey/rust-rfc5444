// Copyright 2020 Jean Pierre Dudey. See the LICENSE-MIT and
// LICENSE-APACHE files at the top-level directory of this
// distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # `rust-rfc5444`
//!
//! <p align="center">
//!   <a href="https://tools.ietf.org/html/rfc5444">
//!     Generalized Mobile Ad Hoc Network (MANET) Packet/Message Format
//!   </a>
//!   <br>
//!   RFC 5444
//! </p>
//!
//! # Introduction
//!
//! This is a crate for parsing and creating RFC 5444 packets, it's mean to be
//! fully compatible with the implementation and support all of the use cases.
//!
//! Also this crate has as it's goal to be small and embedded-friendly, with
//! full `no_std` support. This library should be useful for low-latency
//! applications, and as such, use of the heap is prohibited (unless you use
//! `use_std`).
//!
//! Other goal is to be secure, that means, 0 crashes, good error handling, and
//! well tested/fuzzed code. Also this means that usage of `unsafe` is banned
//! even for dependencies.
//!
//! # Non goals
//!
//! This library doesn't aims to be a "server" of some sort, or to handle any
//! logic in the packets, that's up to you, here the hard part is done to leave
//! the other things more simple such as handling sequence numbers, we don't
//! touch sequence numbers, nor we increment/decrement hop count, hop limits,
//! etc.
//!
//! # Minimum Supported Rust Version
//!
//! As a minimum the goal is to support Debian oldoldstable [`rustc`][deb]
//! (1.34.2 right now). Newer `rustc` versions will be supported when Debian
//! updates their `rustc` for Debian oldoldstable.
//!
//! Breakage of MSRV will be done in the minor versions when on `<1`. When a
//! stable version is released, the major verison **will** be incremented to not
//! break dependant crates depending on the MSRV.
//!
//! [deb]: https://packages.debian.org/jessie/rust-doc
//!
//! # Features
//!
//! - `use_std`: (default) enables usage of `std`, disable it to be compatible
//! with `no_std`.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "use_std"), no_std)]

#[macro_use]
extern crate bitflags;

mod addrtlv;
mod buf;
mod error;
mod msg;
mod packet;
mod tlv;

pub use addrtlv::{AddressBlock, AddressTlvIter, AddressTlvs, MAX_ADDR_LEN};
pub use buf::Buf;
pub use error::Error;
pub use msg::{Message, MessageIter, Messages, MsgHeader};
pub use packet::{Packet, PktHeader};
pub use tlv::{Tlv, TlvBlock};

/// Supported version of RFC 5444.
pub const RFC5444_VERSION: u8 = 0;
