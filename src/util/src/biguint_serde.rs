// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::base16::{biguint_from_str_with_prefix, to_string_with_prefix};

pub fn biguint_serialize<S>(u: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    //? TODO BUG left pad as necessary to ensure length is correct

    use serde::ser::Error;

    let s = to_string_with_prefix(u, 16, None).map_err(S::Error::custom)?;
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
