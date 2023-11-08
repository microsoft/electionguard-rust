// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

#[cfg(biguint_serialize_base64)]
use base64::{engine::Config, Engine};

use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(biguint_serialize_base64)]
const BASE64_ENGINE: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[cfg(biguint_serialize_base64)]
const BASE64_PREFIX: &str = "base64:";

use crate::base16::{biguint_from_str_with_prefix, to_string_with_prefix};

pub fn biguint_serialize<S>(u: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    //? TODO BUG left pad as necessary to ensure length is correct

    use serde::ser::Error;

    #[cfg(not(biguint_serialize_base64))]
    {
        let s = to_string_with_prefix(u, 16, None).map_err(S::Error::custom)?;
        s.serialize(serializer)
    }

    #[cfg(biguint_serialize_base64)]
    {
        // The string "base64:" follwed by RFC 4648-base64
        // https://www.rfc-editor.org/rfc/rfc4648.html
        let v = u.to_bytes_be();

        let v_len = v.len();
        let encoded_len = base64::encoded_len(v_len, BASE64_ENGINE.config().encode_padding())
            .ok_or_else(|| S::Error::custom(format!("BigUint too large: {v_len} bytes")))?;

        let bytes_needed = BASE64_PREFIX.len().saturating_add(encoded_len);

        let mut s = String::new();
        s.reserve_exact(bytes_needed);
        s.push_str(BASE64_PREFIX);

        BASE64_ENGINE.encode_string(v, &mut s);

        debug_assert!(s.len() <= bytes_needed);

        s.serialize(serializer)
    }
}

pub fn biguint_deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    #[cfg(not(biguint_serialize_base64))]
    {
        let s = String::deserialize(deserializer)?;
        biguint_from_str_with_prefix(&s).map_err(D::Error::custom)
    }

    #[cfg(biguint_serialize_base64)]
    {
        let s = String::deserialize(deserializer)?;

        if !s.starts_with(BASE64_PREFIX) {
            return Err(D::Error::custom(format!(
                "Invalid BigUint, expecting to start with {BASE64_PREFIX:?}: {s}"
            )));
        }

        let s_bytes = &s[BASE64_PREFIX.len()..].as_bytes();

        let estimated_len = base64::decoded_len_estimate(s_bytes.len());

        let mut bytes = Vec::<u8>::new();
        bytes.reserve_exact(estimated_len);

        BASE64_ENGINE
            .decode_vec(s_bytes, &mut bytes)
            .map_err(|e| D::Error::custom(format!("Invalid base64: {e}, {s}")))?;

        #[cfg(debug_assertions)]
        if !(estimated_len..estimated_len.saturating_add(3)).contains(&bytes.len()) {
            eprintln!(
                "Estimated length {} of base64 decode was wrong. Actual: {}",
                estimated_len,
                bytes.len()
            );
        }

        Ok(BigUint::from_bytes_be(&bytes))
    }
}
