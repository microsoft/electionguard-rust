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

use std::sync::Arc;

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

#[inline]
pub fn serialize_asref_stdioerror<S, AsRefStdIoError>(
    asref_stdioerror: AsRefStdIoError,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    AsRefStdIoError: AsRef<std::io::Error>,
{
    let stdioerror: &std::io::Error = asref_stdioerror.as_ref();
    stdioerror.to_string().serialize(serializer)
}

#[inline]
pub fn serialize_std_collections_tryreserveerror<S>(
    std_collections_tryreserveerror: &std::collections::TryReserveError,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    std_collections_tryreserveerror
        .to_string()
        .serialize(serializer)
}

#[inline]
pub fn serialize_std_convert_infallible<S>(
    std_convert_infallible: &std::convert::Infallible,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    std_convert_infallible.to_string().serialize(serializer)
}

#[inline]
pub fn serialize_std_num_parseinterror<S>(
    std_num_parseinterror: &std::num::ParseIntError,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    std_num_parseinterror.to_string().serialize(serializer)
}

#[inline]
pub fn serialize_std_num_tryfrominterror<S>(
    std_num_tryfrominterror: &std::num::TryFromIntError,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    std_num_tryfrominterror.to_string().serialize(serializer)
}

#[inline]
pub fn serialize_std_string_fromutf8error<S>(
    std_num_parseinterror: &std::string::FromUtf8Error,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    std_num_parseinterror.to_string().serialize(serializer)
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

#[inline]
pub fn serialize_arc_anyhowerror<S>(
    anyhowerror: &Arc<anyhow::Error>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    anyhowerror.as_ref().to_string().serialize(serializer)
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
