// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

const UINT53_MAX_U64: u64 = (1_u64 << 53) - 1;

#[nutype::nutype(
    new_unchecked,
    validate(less_or_equal = UINT53_MAX_U64),
    default = 0,
    derive(Debug, Display, Default, Clone, Copy,
        PartialEq, Eq,
        PartialOrd, Ord,
        FromStr,
        AsRef, Deref,
        TryFrom, Into,
        Hash, Borrow,
        Serialize, Deserialize)
)]
pub struct Uint53(u64);

impl Uint53 {
    pub fn zero() -> Self {
        Self::default()
    }

    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }
}

impl From<u8> for Uint53 {
    #[inline]
    fn from(value: u8) -> Self {
        unsafe { Self::new_unchecked(value as u64) }
    }
}

impl From<u16> for Uint53 {
    #[inline]
    fn from(value: u16) -> Self {
        unsafe { Self::new_unchecked(value as u64) }
    }
}

impl From<u32> for Uint53 {
    #[inline]
    fn from(value: u32) -> Self {
        unsafe { Self::new_unchecked(value as u64) }
    }
}

impl TryFrom<usize> for Uint53 {
    type Error = Uint53Error;
    #[inline]
    fn try_from(value: usize) -> Result<Uint53, Self::Error> {
        if let Ok(valu64) = u64::try_from(value) {
            if valu64 <= UINT53_MAX_U64 {
                return Ok(unsafe { Self::new_unchecked(valu64) });
            }
        }
        Err(Uint53Error::LessOrEqualViolated)
    }
}

impl TryFrom<u128> for Uint53 {
    type Error = Uint53Error;
    #[inline]
    fn try_from(value: u128) -> Result<Uint53, Self::Error> {
        if value <= UINT53_MAX_U64 as u128 {
            return Ok(unsafe { Self::new_unchecked(value as u64) });
        }
        Err(Uint53Error::LessOrEqualViolated)
    }
}

impl TryFrom<Uint53> for usize {
    type Error = std::num::TryFromIntError;
    #[inline]
    fn try_from(value: Uint53) -> Result<usize, Self::Error> {
        let valu64 = *value;
        usize::try_from(valu64)
    }
}

impl From<Uint53> for u128 {
    #[inline]
    fn from(value: Uint53) -> Self {
        value.into_inner() as u128
    }
}

//-------------------------------------------------------------------------------------------------|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use anyhow::Result;

    #[test]
    fn t10() -> Result<()> {
        assert_eq!(Uint53::try_new(0)?.into_inner(), 0_u64);
        assert_eq!(
            Uint53::try_new((1_u64 << 53) - 1)?.into_inner(),
            UINT53_MAX_U64
        );
        assert!(Uint53::try_new(1_u64 << 53).is_err());
        assert!(Uint53::try_new(u64::MAX).is_err());

        assert_eq!(*Uint53::from(0_u8), 0_u64);
        assert_eq!(*Uint53::from(0xff_u8), 0xff_u64);

        assert_eq!(*Uint53::from(0_u16), 0_u64);
        assert_eq!(*Uint53::from(0xff_u16), 0xff_u64);

        assert_eq!(*Uint53::from(0_u32), 0_u64);
        assert_eq!(*Uint53::from(0xff_u32), 0xff_u64);

        assert_eq!(Uint53::try_from(123_usize), Ok(Uint53::from(123_u8)));

        assert_eq!(*Uint53::try_from(0_u64).unwrap(), 0_u64);
        assert_eq!(*Uint53::try_from(UINT53_MAX_U64).unwrap(), UINT53_MAX_U64);
        assert!(Uint53::try_from(UINT53_MAX_U64 + 1).is_err());

        assert_eq!(usize::try_from(Uint53::default()), Ok(0_usize));
        assert_eq!(u64::from(Uint53::default()), 0_u64);
        assert_eq!(u128::from(Uint53::default()), 0_u128);

        assert_eq!(*Uint53::try_from(0_u64).unwrap(), 0_u64);
        assert_eq!(*Uint53::try_from(UINT53_MAX_U64)?, UINT53_MAX_U64);
        assert!(Uint53::try_from(UINT53_MAX_U64 + 1).is_err());

        Ok(())
    }
}
