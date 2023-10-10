// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use digest::{FixedOutput, Update};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use util::array_ascii::ArrayAscii;

type HmacSha256 = Hmac<sha2::Sha256>;

// "In ElectionGuard, all inputs that are used as the HMAC key, i.e. all inputs to the first
// argument of H have a fixed length of exactly 32 bytes."
// "The output of SHA-256 and therefore H is a 256-bit string, which can be interpreted as a
// byte array of 32 bytes."
pub const HVALUE_BYTE_LEN: usize = 32;
type HValueByteArray = [u8; HVALUE_BYTE_LEN];

#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HValue(pub HValueByteArray);

impl HValue {
    const HVALUE_SERIALIZE_PREFIX: &[u8] = b"H(";
    const HVALUE_SERIALIZE_SUFFIX: &[u8] = b")";
    const HVALUE_SERIALIZE_LEN: usize = HValue::HVALUE_SERIALIZE_PREFIX.len()
        + HVALUE_BYTE_LEN * 2
        + HValue::HVALUE_SERIALIZE_SUFFIX.len();

    fn display_as_ascii(&self) -> ArrayAscii<{ HValue::HVALUE_SERIALIZE_LEN }> {
        enum State {
            Prefix(usize),
            Nibble { lower: bool, ix: usize },
            Suffix(usize),
            End,
        }
        let mut state = State::Prefix(0);
        ArrayAscii::from_fn(|_out_ix| match state {
            State::Prefix(ix) => {
                state = if ix + 1 < HValue::HVALUE_SERIALIZE_PREFIX.len() {
                    State::Prefix(ix + 1)
                } else {
                    State::Nibble {
                        lower: false,
                        ix: 0,
                    }
                };
                HValue::HVALUE_SERIALIZE_PREFIX[ix]
            }
            State::Nibble { lower, ix } => {
                let upper = !lower;
                let nibble = if upper {
                    state = State::Nibble { lower: upper, ix };
                    self.0[ix] >> 4
                } else {
                    state = if ix + 1 < HVALUE_BYTE_LEN {
                        State::Nibble {
                            lower: upper,
                            ix: ix + 1,
                        }
                    } else {
                        State::Suffix(0)
                    };
                    self.0[ix] & 0x0f
                };
                b"0123456789ABCDEF"[nibble as usize]
            }
            State::Suffix(ix) => {
                state = if ix + 1 < HValue::HVALUE_SERIALIZE_SUFFIX.len() {
                    State::Suffix(ix + 1)
                } else {
                    State::End
                };
                HValue::HVALUE_SERIALIZE_SUFFIX[ix]
            }
            State::End => {
                debug_assert!(false, "Should not be called after End state");
                b' '
            }
        })
    }

    /// Reads `HValue` from a `std::io::Read`.
    pub fn from_reader(io_read: &mut dyn std::io::Read) -> Result<HValue> {
        serde_json::from_reader(io_read).map_err(|e| anyhow!("Error parsing HValue: {}", e))
    }

    /// Returns a pretty JSON `String` representation of the `HValue`.
    /// The final line will end with a newline.
    pub fn to_json(&self) -> String {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }

    /// Reads a `HValue` from a `std::io::Write`.
    pub fn from_stdioread(stdioread: &mut dyn std::io::Read) -> Result<Self> {
        let hashes: Self = serde_json::from_reader(stdioread).context("Reading HValue")?;

        Ok(hashes)
    }

    /// Writes a `HValue` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser).context("Error writing HValue")?;

        ser.into_inner()
            .write_all(b"\n")
            .context("Error writing HValue file")
    }

    pub fn to_string_hex_no_prefix_suffix(&self) -> String {
        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        let s = serde_json::to_string_pretty(self).unwrap();
        s[3..s.len() - 2].to_string()
    }
}

impl From<HValueByteArray> for HValue {
    #[inline]
    fn from(value: HValueByteArray) -> Self {
        HValue(value)
    }
}

impl From<&HValueByteArray> for HValue {
    #[inline]
    fn from(value: &HValueByteArray) -> Self {
        HValue(*value)
    }
}

impl AsRef<HValueByteArray> for HValue {
    #[inline]
    fn as_ref(&self) -> &HValueByteArray {
        &self.0
    }
}

impl std::fmt::Display for HValue {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(self.display_as_ascii().as_str())
    }
}

impl std::fmt::Debug for HValue {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Display::fmt(self, f)
    }
}

impl Serialize for HValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.display_as_ascii().as_str().serialize(serializer)
    }
}

impl std::str::FromStr for HValue {
    type Err = anyhow::Error;

    /// Parses a string into an HValue.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix_start_ix = 0usize;
        let prefix_end_ix = HValue::HVALUE_SERIALIZE_PREFIX.len();

        let suffix_start_ix = HValue::HVALUE_SERIALIZE_LEN - HValue::HVALUE_SERIALIZE_SUFFIX.len();
        let suffix_end_ix = HValue::HVALUE_SERIALIZE_LEN;

        let hex_start_ix = prefix_end_ix;
        let hex_end_ix = suffix_start_ix;

        let bytes = s.as_bytes();

        let prefix_and_suffix_look_ok = bytes.len() == HValue::HVALUE_SERIALIZE_LEN
            && &bytes[prefix_start_ix..prefix_end_ix] == HValue::HVALUE_SERIALIZE_PREFIX
            && &bytes[suffix_start_ix..suffix_end_ix] == HValue::HVALUE_SERIALIZE_SUFFIX;

        let make_error = || anyhow!("Invalid HValue: {}", s);

        if !prefix_and_suffix_look_ok {
            return Err(make_error());
        }

        let hex_digits = &bytes[hex_start_ix..hex_end_ix];

        fn hex_digit_to_nibble(hex_digit: u8) -> Option<u8> {
            match hex_digit {
                b'0'..=b'9' => Some(hex_digit - b'0'),
                b'a'..=b'f' => Some(hex_digit - b'a' + 10),
                b'A'..=b'F' => Some(hex_digit - b'A' + 10),
                _ => None,
            }
        }

        let mut bad_digit = false;
        let mut byte_iterator = hex_digits.chunks_exact(2).map(|hex_digit_pair| {
            hex_digit_pair
                .iter()
                .map(|hex_digit| {
                    hex_digit_to_nibble(*hex_digit).unwrap_or_else(|| {
                        bad_digit = true;
                        0
                    })
                })
                .fold(0u8, |acc, hex_digit| (acc << 4) | hex_digit)
        });

        //? TODO Use std::array::array_try_from_fn when available https://github.com/rust-lang/rust/issues/89379
        let mut missing_digit = false;
        let hvba: HValueByteArray = std::array::from_fn(|_ix| {
            byte_iterator.next().unwrap_or_else(|| {
                missing_digit = true;
                0
            })
        });

        debug_assert!(byte_iterator.next().is_none());

        if bad_digit || missing_digit {
            return Err(make_error());
        }

        Ok(HValue(hvba))
    }
}

impl<'de> Deserialize<'de> for HValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let s = String::deserialize(deserializer)?;

        s.parse().map_err(D::Error::custom)
    }
}

// ElectionGuard "H" function.
pub fn eg_h(key: &HValue, data: &dyn AsRef<[u8]>) -> HValue {
    // `unwrap()` is justified here because `HmacSha256::new_from_slice()` seems
    // to only fail on slice of incorrect size.
    #[allow(clippy::unwrap_used)]
    let hmac_sha256 = HmacSha256::new_from_slice(key.as_ref()).unwrap();

    AsRef::<[u8; 32]>::as_ref(&hmac_sha256.chain(data).finalize_fixed()).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test_eg_h {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_hvalue_std_fmt() {
        let h: HValue = std::array::from_fn(|ix| ix as u8).into();

        let expected = "H(000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F)";
        assert_eq!(h.to_string(), expected);
        assert_eq!(format!("{h}"), expected);
        assert_eq!(format!("{h:?}"), expected);
    }

    #[test]
    fn test_hvalue_serde_json() {
        let h: HValue = std::array::from_fn(|ix| ix as u8).into();

        let json = serde_json::to_string(&h).unwrap();

        let expected = "\"H(000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F)\"";
        assert_eq!(json, expected);

        let h2: HValue = serde_json::from_str(&json).unwrap();
        assert_eq!(h2, h);
    }

    #[test]
    fn test_evaluate_h() {
        let key: HValue = HValue::default();

        let data = [0u8; 0];

        let actual = eg_h(&key, &data);

        let expected =
            HValue::from_str("H(B613679A0814D9EC772F95D778C35FC5FF1697C493715653C6C712144292C5AD)")
                .unwrap();

        assert_eq!(actual, expected);
    }
}

// ElectionGuard "H" function (for WebAssembly)
pub fn eg_h_js(key: &[u8], data: &[u8]) -> String {
    // `unwrap()` is justified here because `HmacSha256::new_from_slice()` only fails on slice of
    // incorrect size.
    #[allow(clippy::unwrap_used)]
    let hmac_sha256 = HmacSha256::new_from_slice(key).unwrap();

    general_purpose::URL_SAFE_NO_PAD.encode(AsRef::<[u8; 32]>::as_ref(
        &hmac_sha256.chain(data).finalize_fixed(),
    ))
}
