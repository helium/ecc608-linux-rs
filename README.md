[![Crates.io][crates-badge]][crates-url]
[![docs.rs][docs-badge]][docs-url]
[![Build Status][actions-badge]][actions-url]
[![Discord chat][discord-badge]][discord-url]

[crates-badge]: https://img.shields.io/crates/v/ecc608-linux.svg
[crates-url]: https://crates.io/crates/ecc608-linux
[docs-badge]: https://docs.rs/ecc608-linux/badge.svg
[docs-url]: https://docs.rs/ecc608-linux/latest/ecc608-linux/
[actions-badge]: https://github.com/helium/ecc608-linux-rs/actions/workflows/rust.yml/badge.svg
[actions-url]: https://github.com/helium/ecc608-linux-rs/actions/workflows/rust.yml
[discord-badge]: https://img.shields.io/discord/500028886025895936.svg?logo=discord&style=flat-square
[discord-url]: https://discord.gg/helium

## ecc608-linux-rs

This library implements various elliptic curve cryptographic functions used by
[Helium Blockchain](https://helium.com) using the Microchip ATECC608 family.
This includes creating keys for ECC types, signing messages, and configuring and
locking the chip down for production use. 

## Using

Add a dependency to your projects `Cargo.toml`:

```rust
ecc608-linux-rs = "<version>"
```
