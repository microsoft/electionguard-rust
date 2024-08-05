// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::base16::{biguint_from_str_with_prefix, biguint_from_str_uppercase_hex_bits, to_string_with_prefix, to_string_uppercase_hex_bits};

pub fn biguint_serialize<S>(u: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    //? TODO BUG left pad as necessary to ensure length is correct

    use serde::ser::Error;

    let s = to_string_with_prefix(u, 16, None).map_err(S::Error::custom)?;
    s.serialize(serializer)
}

pub fn biguint_serialize_256_bits<S>(u: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::Error;

    let len_bits: u32 = 256;
    let s = to_string_uppercase_hex_bits(u, len_bits).map_err(S::Error::custom)?;
    s.serialize(serializer)
}

pub fn biguint_serialize_4096_bits<S>(u: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::Error;

    let len_bits: u32 = 4096;
    let s = to_string_uppercase_hex_bits(u, len_bits).map_err(S::Error::custom)?;
    s.serialize(serializer)
}

pub fn biguint_deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(deserializer)?;
    biguint_from_str_with_prefix(&s).map_err(D::Error::custom)
}

pub fn biguint_deserialize_256_bits<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(deserializer)?;
    biguint_from_str_uppercase_hex_bits(&s, 256).map_err(D::Error::custom)
}

pub fn biguint_deserialize_4096_bits<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(deserializer)?;
    biguint_from_str_uppercase_hex_bits(&s, 4096).map_err(D::Error::custom)
}
