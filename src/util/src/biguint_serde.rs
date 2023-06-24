// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use base64::Engine;
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const BASE64_ENGINE: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD_NO_PAD;

pub fn biguint_serialize<S>(u: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    #[cfg(biguint_serialize_hex)]
    {
        //? TODO: re-do this
        let hex = format!("0x{:x}", u);
        hex.serialize(serializer)
    }

    #[cfg(not(biguint_serialize_hex))]
    {
        //? TODO left pad as necessary to ensure length is correct
        let v = u.to_bytes_be();

        let s = BASE64_ENGINE.encode(v);

        s.serialize(serializer)
    }
}

pub fn biguint_deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    //? TODO: re-do this
    use serde::de::Error;

    #[cfg(biguint_serialize_hex)]
    {
        let hex = String::deserialize(deserializer)?;
        let bytes = hex.as_bytes();

        let opt_u =
            if !(3 <= bytes.len() && bytes[0] == b'0' && (bytes[1] == b'x' || bytes[1] == b'X')) {
                None
            } else {
                BigUint::parse_bytes(&bytes[2..], 16)
            };

        opt_u.ok_or_else(|| D::Error::custom(format!("Invalid BigUint: {}", hex)))
    }

    #[cfg(not(biguint_serialize_hex))]
    {
        let s = String::deserialize(deserializer)?;
        let s_bytes = s.as_bytes();

        let estimated_len = s_bytes.len() * 3 / 4;

        let mut bytes = Vec::<u8>::new();
        bytes.reserve_exact(estimated_len);

        BASE64_ENGINE
            .decode_vec(s_bytes, &mut bytes)
            .map_err(|e| D::Error::custom(format!("Invalid base64: {e}, {s}")))?;

        #[cfg(debug_assertions)]
        if estimated_len != bytes.len() {
            eprintln!(
                "Estimated length {} of base64 decode was wrong. Actual: {}",
                estimated_len,
                bytes.len()
            );
        }

        Ok(BigUint::from_bytes_be(&bytes))
    }
}
