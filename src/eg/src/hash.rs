// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use digest::{FixedOutput, Update};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<sha2::Sha256>;

// "In ElectionGuard, all inputs that are used as the HMAC key, i.e. all inputs to the first
// argument of H have a fixed length of exactly 32 bytes."
// "The output of SHA-256 and therefore H is a 256-bit string, which can be interpreted as a
// byte array of 32 bytes."
pub const HVALUE_BYTE_LEN: usize = 32;
type HValueByteArray = [u8; HVALUE_BYTE_LEN];

#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HValue(pub HValueByteArray);

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

impl std::fmt::LowerHex for HValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        for byte in self.0.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl std::fmt::UpperHex for HValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        for byte in self.0.iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for HValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::LowerHex::fmt(self, f)
    }
}

impl std::fmt::Debug for HValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "HValue({self:x})")
    }
}

// ElectionGuard "H" function.
pub fn eg_h(key: &HValue, data: &dyn AsRef<[u8]>) -> HValue {
    // `unwrap()` is justified here because `HmacSha256::new_from_slice()` only fails on slice of
    // incorrect size.
    #[allow(clippy::unwrap_used)]
    let hmac_sha256 = HmacSha256::new_from_slice(key.as_ref()).unwrap();

    AsRef::<[u8; 32]>::as_ref(&hmac_sha256.chain(data).finalize_fixed()).into()
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_evaluate_h() {
        let key: HValue = HValue::default();
        // println!("key Debug  : {key:?}");
        // println!("key Display:        {key}");
        // println!("key LowerHex:       {key:x}");
        // println!("key UpperHex:       {key:X}");

        let data = [0u8; 0];

        let actual = eg_h(&key, &data);
        // println!("actual Debug  : {actual:?}");
        // println!("actual Display:        {actual}");
        // println!("actual LowerHex:       {actual:x}");
        // println!("actual UpperHex:       {actual:X}");

        let expected = HValue::from(hex!(
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        ));

        assert_eq!(actual, expected);
    }
}
