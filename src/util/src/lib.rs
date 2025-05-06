// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

pub mod abbreviation;
pub mod array_ascii;
pub mod base16;
pub mod biguint_serde;
pub mod bitwise;
pub mod const_minmax;
pub mod csprng;
pub mod csrng;
pub mod file;
pub mod hex_dump;
pub mod index;
pub mod logging;
pub mod osrng;
pub mod prime;
pub mod serde;
pub mod text;
pub mod uint31;
pub mod uint53;
pub mod vec1;

#[rustfmt::skip]
static_assertions::assert_cfg!(
    not( all( feature = "eg-allow-unsafe-code",
              feature = "eg-forbid-unsafe-code" ) ),
    r##"Can't have both features `eg-allow-unsafe-code` and `eg-forbid-unsafe-code` active at the
 same time. You may need to specify `default-features = false, features =
 [\"only\",\"specifically\",\"desired\",\"features\"]` in `Cargo.toml`, and/or
 `--no-default-features --features only,specifically,desired,features` on the cargo command
 line. In VSCode, configure the `rust-analyzer.cargo.noDefaultFeatures` and
 `rust-analyzer.cargo.features` settings."##
);
