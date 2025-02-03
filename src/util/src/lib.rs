// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

pub mod abbreviation;
pub mod algebra;
pub mod algebra_utils;
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
pub mod uint31;
pub mod uint53;
pub mod vec1;
