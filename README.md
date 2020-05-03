# `rust-rfc5444`

<p align="center">
  <a href="https://tools.ietf.org/html/rfc5444">
    Generalized Mobile Ad Hoc Network (MANET) Packet/Message Format
  </a>
</p>

This is a crate implementing the RFC 5444 standard with some goals on mind:

- **Small:** this should fit on a microcontroller, and that's the aim.
- **Performant:** we don't use the heap at all, we don't copy anything unless
necessary, and absolutely with a high throughput.
- **Safe:** this shouldn't crash under any circustamces, it should be mission
critical, with good error handling.
- **Compliant:** complete compliance with the standards, 0 deviations.

Contributions are welcome, the rule is to write good and tested code (applies
to me too :roll_eyes:), without dependencies on external crates, do convince me
of reducing dependencies.

# [Documentation](https://docs.rs/rfc5444)

# Minimum Supported Rust Version (MSRV)

This crate is _only_ tested against the latest nightly builds of Rust, this
_will_ change in the future and the targeted `rustc` version will be the one of
the distributed with Debian oldstable.

To run fuzz tests (`cargo-fuzz` is your friend here), you'll need _nighly_ Rust.

# License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

# NOOOOOOOOOO YOU CAN'T TARGET OLD COMPILERS, NEWER FEATURINOS ARE AVAILABLE

![brrguy](https://raw.githubusercontent.com/jeandudey/rust-rfc5444/master/docs/brrrguy.jpg)

- Hahaha Debian oldstable rustc go brrrrrrrrrr.
