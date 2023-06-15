// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn biguint_serialize<S>(u: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    //? TODO: re-do this
    let hex = format!("0x{:x}", u);
    hex.serialize(serializer)
}

pub fn biguint_deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    //? TODO: re-do this
    use serde::de::Error;

    let hex = String::deserialize(deserializer)?;
    let bytes = hex.as_bytes();

    let opt_u = if !(3 <= bytes.len() && bytes[0] == b'0' && (bytes[1] == b'x' || bytes[1] == b'X'))
    {
        None
    } else {
        BigUint::parse_bytes(&bytes[2..], 16)
    };

    opt_u.ok_or_else(|| D::Error::custom(format!("Invalid BigUint: {}", hex)))
}
