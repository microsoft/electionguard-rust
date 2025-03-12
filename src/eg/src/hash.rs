// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::marker::PhantomData;

use anyhow::{Context, Result, anyhow};
use digest::{FixedOutput, Update};
use hmac::{Hmac, Mac};
use util::{
    algebra::{FieldElement, ScalarField},
    array_ascii::ArrayAscii,
    csrng::{Csrng, CsrngOps},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{errors::EgError, serializable::SerializableCanonical};

type HmacSha256 = Hmac<sha2::Sha256>;

// "In ElectionGuard, all inputs that are used as the HMAC key, i.e. all inputs to the first
// argument of H have a fixed length of exactly 32 bytes."
pub const HVALUE_BYTE_LEN: usize = 32;

// "The output of SHA-256 and therefore H is a 256-bit string, which can be interpreted as a
// byte array of 32 bytes."
pub type HValueByteArray = [u8; HVALUE_BYTE_LEN];

impl From<HValue> for HValueByteArray {
    #[inline]
    fn from(value: HValue) -> Self {
        value.0
    }
}

//-------------------------------------------------------------------------------------------------|

/// Represents a hash output value of the ElectionGuard hash function ‘H’. It is also
/// the type used as the first parameter, the HMAC key.
#[derive(
    Default,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Zeroize,
    ZeroizeOnDrop
)]
pub struct HValue(pub HValueByteArray);

impl HValue {
    /// The number of bits in an HValue.
    pub const fn bit_len() -> usize {
        HVALUE_BYTE_LEN * 8
    }

    /// The number of bytes in an HValue.
    pub const fn byte_len() -> usize {
        HVALUE_BYTE_LEN
    }

    /// Generates a random [`HValue`] from a [`Csrng`].
    pub fn generate_random(csrng: &dyn Csrng) -> Self {
        Self(csrng.next_arr_u8())
    }

    /// Reads `HValue` from a `std::io::Read`.
    pub fn from_reader(io_read: &mut dyn std::io::Read) -> Result<HValue> {
        serde_json::from_reader(io_read).map_err(|e| anyhow!("Error parsing HValue: {}", e))
    }

    /// Reads a `HValue` from a `std::io::Write`.
    pub fn from_stdioread(stdioread: &mut dyn std::io::Read) -> Result<Self> {
        let hashes: Self = serde_json::from_reader(stdioread).context("Reading HValue")?;

        Ok(hashes)
    }

    //const HVALUE_SERIALIZE_PREFIX: &'static [u8] = b"H(";
    //const HVALUE_SERIALIZE_SUFFIX: &'static [u8] = b")";
    const HVALUE_SERIALIZE_PREFIX: &'static [u8] = b"";
    const HVALUE_SERIALIZE_SUFFIX: &'static [u8] = b"";
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

        #[allow(clippy::const_is_empty)]
        let mut state = if HValue::HVALUE_SERIALIZE_PREFIX.is_empty() {
            State::Nibble {
                lower: false,
                ix: 0,
            }
        } else {
            State::Prefix(0)
        };

        let aa_result = ArrayAscii::try_from_fn(|_out_ix| match state {
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
                        #[allow(clippy::const_is_empty)]
                        if HValue::HVALUE_SERIALIZE_SUFFIX.is_empty() {
                            State::End
                        } else {
                            State::Suffix(0)
                        }
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
        });

        // `unwrap()` is justified here because we only emit a very limited set of characters.
        #[allow(clippy::unwrap_used)]
        aa_result.unwrap()
    }

    pub fn to_string_hex_no_prefix_suffix(&self) -> String {
        self.to_string()
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

impl TryFrom<&[u8]> for HValue {
    type Error = EgError;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        TryInto::<&HValueByteArray>::try_into(value)
            .map_err(|_| EgError::HValueByteLenMismatch {
                expected: HVALUE_BYTE_LEN,
                actual: value.len(),
            })
            .map(Into::into)
    }
}

impl AsRef<HValue> for HValue {
    #[inline]
    fn as_ref(&self) -> &HValue {
        self
    }
}

impl AsRef<HValueByteArray> for HValue {
    #[inline]
    fn as_ref(&self) -> &HValueByteArray {
        &self.0
    }
}

impl AsRef<[u8]> for HValue {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for HValue {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for HValue {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_as_ascii().as_str())
    }
}

impl serde::Serialize for HValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        util::serde::serialize_bytes_as_uppercase_hex(self, serializer)
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

impl<'de> serde::Deserialize<'de> for HValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(D::Error::custom)
    }
}

impl rand::Fill for HValue {
    fn fill<R: rand::Rng + ?Sized>(&mut self, rng: &mut R) {
        rng.fill(&mut self.0)
    }
}

impl SerializableCanonical for HValue {}

//=================================================================================================|

/// Hash value with a specific meaning.
///
/// `T` is a simply a tag for disambiguation. It can be any type.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SpecificHValue<T>(HValue, PhantomData<fn(T) -> T>)
where
    T: ?Sized;

impl<T: ?Sized> SpecificHValue<T> {
    /// The number of bits in an HValue.
    pub const fn bit_len() -> usize {
        HVALUE_BYTE_LEN * 8
    }

    /// The number of bytes in an HValue.
    pub const fn byte_len() -> usize {
        HVALUE_BYTE_LEN
    }

    /// ElectionGuard `H` hash function, returning this [`SpecificHValue`].
    pub fn compute_from_eg_h<K, D>(key: K, data: D) -> Self
    where
        K: AsRef<HValue>,
        D: AsRef<[u8]>,
    {
        eg_h(key, data).into()
    }

    /// Generates a random [`SpecificHValue<T>`] from a [`Csrng`].
    pub fn generate_random(csrng: &dyn Csrng) -> Self {
        HValue::generate_random(csrng).into()
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: ?Sized> Clone for SpecificHValue<T> {
    /// Clone trait must be implmented manually because of the [`PhantomData`].
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0.clone(), Default::default())
    }
}

impl<T: ?Sized> PartialEq for SpecificHValue<T> {
    /// [`PartialEq`] trait must be implmented manually because of the [`PhantomData`].
    #[inline]
    fn eq(&self, rhs: &Self) -> bool {
        let lhs: &HValueByteArray = self.as_ref();
        let rhs: &HValueByteArray = rhs.as_ref();
        lhs.eq(rhs)
    }
}

/// [`Eq`] trait must be implmented manually because of the [`PhantomData`].
impl<T: ?Sized> Eq for SpecificHValue<T> {}

impl<T: ?Sized> AsRef<SpecificHValue<T>> for SpecificHValue<T> {
    #[inline]
    fn as_ref(&self) -> &SpecificHValue<T> {
        self
    }
}

impl<T: ?Sized> AsRef<HValue> for SpecificHValue<T> {
    #[inline]
    fn as_ref(&self) -> &HValue {
        &self.0
    }
}

impl<T: ?Sized> AsRef<HValueByteArray> for SpecificHValue<T> {
    #[inline]
    fn as_ref(&self) -> &HValueByteArray {
        self.0.as_ref()
    }
}

impl<T: ?Sized> AsRef<[u8]> for SpecificHValue<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<T: ?Sized> std::fmt::Debug for SpecificHValue<T> {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl<T: ?Sized> std::fmt::Display for SpecificHValue<T> {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl<T: ?Sized> std::str::FromStr for SpecificHValue<T> {
    type Err = <HValue as std::str::FromStr>::Err;

    /// Attempts to parse a string `s` to return a [`SpecificHValue<T>`].
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HValue::from_str(s).map(Self::from)
    }
}

impl<T: ?Sized> From<HValue> for SpecificHValue<T> {
    /// A [`SpecificHValue<T>`] can always be made from a [`HValue`].
    #[inline]
    fn from(src: HValue) -> Self {
        Self(src, Default::default())
    }
}

impl<T: ?Sized> From<HValueByteArray> for SpecificHValue<T> {
    /// A [`SpecificHValue<T>`] can always be made from a [`HValueByteArray`].
    #[inline]
    fn from(src: HValueByteArray) -> Self {
        let hv = HValue::from(src);
        Self::from(hv)
    }
}

impl<T: ?Sized> serde::Serialize for SpecificHValue<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: ?Sized> serde::Deserialize<'de> for SpecificHValue<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        HValue::deserialize(deserializer).map(Self::from)
    }
}

impl<T: ?Sized> SerializableCanonical for SpecificHValue<T> {}

//=================================================================================================|

/// ElectionGuard `H` hash function.
pub fn eg_h<K, D>(key: K, data: D) -> HValue
where
    K: AsRef<HValue>,
    D: AsRef<[u8]>,
{
    fn eg_h_(key: &HValue, data: &[u8]) -> HValue {
        // `unwrap()` is justified here because `HmacSha256::new_from_slice()` seems
        // to only fail on slice of incorrect size.
        #[allow(clippy::unwrap_used)]
        let hmac_sha256 = HmacSha256::new_from_slice(key.as_ref()).unwrap();

        AsRef::<[u8; HVALUE_BYTE_LEN]>::as_ref(&hmac_sha256.chain(data).finalize_fixed()).into()
    }

    eg_h_(key.as_ref(), data.as_ref())
}

/// `H_q` hash function. ElectionGuard DS 2.1.0 sec 3.2.2 footnote 32.
/// It is basically just `H(...) mod q`
#[inline]
pub fn eg_h_q_as_field_element<K, D>(key: K, data: D, field: &ScalarField) -> FieldElement
where
    K: AsRef<HValue>,
    D: AsRef<[u8]>,
{
    let hv = eg_h::<K, D>(key, data);

    FieldElement::from_bytes_be(hv.as_ref(), field)
}

/// `H_q` hash function. ElectionGuard DS 2.1.0 sec 3.2.2 footnote 32.
/// It is basically just `H(...) mod q`
#[inline]
pub fn eg_h_q<K, D>(key: K, data: D, field: &ScalarField) -> HValue
where
    K: AsRef<HValue>,
    D: AsRef<[u8]>,
{
    let fe = eg_h_q_as_field_element::<K, D>(key, data, field);

    // Unwrap() is justified here because field `q` is matched to 32 byte hash value by design.
    #[allow(clippy::unwrap_used)]
    let aby32 = fe.try_into_32_be_bytes_arr().unwrap();

    HValue::from(aby32)
}

/// Identical to `H` but separate to follow the specification used for [`crate::guardian_share::GuardianEncryptedShare`]
pub fn eg_hmac(key: &HValue, data: &dyn AsRef<[u8]>) -> HValue {
    // `unwrap()` is justified here because `HmacSha256::new_from_slice()` seems
    // to only fail on slice of incorrect size.
    #[allow(clippy::unwrap_used)]
    let hmac_sha256 = HmacSha256::new_from_slice(key.as_ref()).unwrap();

    AsRef::<[u8; HVALUE_BYTE_LEN]>::as_ref(&hmac_sha256.chain(data).finalize_fixed()).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test_eg_h {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_hvalue_std_fmt() {
        assert_eq!(HValue::byte_len(), 32);
        assert_eq!(HValue::byte_len() * 8, HValue::bit_len());

        let h: HValue = std::array::from_fn(|ix| ix as u8).into();

        let expected = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        assert_eq!(h.to_string(), expected);
        assert_eq!(format!("{h}"), expected);
        assert_eq!(format!("{h:?}"), expected);
    }

    #[test]
    fn test_hvalue_serde_json() {
        let h: HValue = std::array::from_fn(|ix| ix as u8).into();

        let json = serde_json::to_string(&h).unwrap();

        let expected = "\"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\"";
        assert_eq!(json, expected);

        let h2: HValue = serde_json::from_str(&json).unwrap();
        assert_eq!(h2, h);
    }

    #[test]
    fn test_evaluate_h() {
        let key: HValue = HValue::default();

        let data = [0u8; 0];

        let actual = eg_h(&key, data);

        let expected =
            HValue::from_str("B613679A0814D9EC772F95D778C35FC5FF1697C493715653C6C712144292C5AD")
                .unwrap();

        assert_eq!(actual, expected);
    }
}
