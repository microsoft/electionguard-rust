// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use serde::{Deserialize, Deserializer, Serialize, Serializer};

//=================================================================================================|

#[inline]
pub fn serialize_stdioerror<S>(
    stdioerror: &std::io::Error,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    stdioerror.to_string().serialize(serializer)
}

#[allow(clippy::borrowed_box)]
#[inline]
pub fn serialize_bxstdioerror<S>(
    bx_stdioerror: &Box<std::io::Error>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let stdioerror: &std::io::Error = bx_stdioerror;
    serialize_stdioerror(stdioerror, serializer)
}

#[inline]
pub fn serialize_anyhowerror<S>(
    anyhowerror: &anyhow::Error,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    anyhowerror.to_string().serialize(serializer)
}

/// Serializes an [`Option`] as a string "None" or "Some(...)".
#[inline]
pub fn serialize_opt_opaque_as_str<S, Opaque>(
    opt_opaque: &Option<Opaque>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match opt_opaque {
        None => "None",
        Some(_) => "Some(...)",
    }
    .serialize(serializer)
}

/// Serializes an [`Option`] of bytes [`AsRef<[u8]>`](AsRef) as a string containing an even number of
/// uppercase hex digits.
///
/// Intended to be used with `serde(skip_serializing_if = "Option::is_none")`.
/// If the value is none, serializes an empty string instead
#[inline]
pub fn serialize_opt_bytes_as_uppercase_hex<S, Bytes>(
    opt_bytes: &Option<Bytes>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    Bytes: AsRef<[u8]>,
{
    match opt_bytes {
        None => "".serialize(serializer),
        Some(bytes) => serialize_bytes_as_uppercase_hex(bytes, serializer),
    }
}

/// Serializes bytes [`AsRef<[u8]>`](AsRef) as a string containing an even number of
/// uppercase hex digits.
#[inline]
pub fn serialize_bytes_as_uppercase_hex<S, Bytes>(
    bytes: Bytes,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    Bytes: AsRef<[u8]>,
{
    faster_hex::nopfx_uppercase::serialize(bytes, serializer)
}
