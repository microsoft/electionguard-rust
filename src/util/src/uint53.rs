// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

const UINT53_MAX_U64: u64 = (1_u64 << 53) - 1;

/// The main [`std::error::Error`] type returned by the `Uint53` type.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum U53Error {
    #[error("Value `{0}` out of range `0 <= n < 2^53` for a `Uint53`")]
    ValueOutOfRangeForUint53(i128),

    #[error("Value must be `>= 0` for a `Uint53`.")]
    ValueTooSmall,

    #[error("Value must be `<= 2^53 - 1` for a `Uint53`.")]
    ValueTooLarge,
}

impl From<Uint53Error> for U53Error {
    /// A [`U53Error`] can always be made from a [`Uint53Error`].
    #[inline]
    fn from(src: Uint53Error) -> Self {
        match src {
            Uint53Error::LessOrEqualViolated => U53Error::ValueTooSmall,
            Uint53Error::GreaterOrEqualViolated => U53Error::ValueTooLarge,
        }
    }
}

#[nutype::nutype(
    new_unchecked,
    validate(
        greater_or_equal = 0,
        less_or_equal = UINT53_MAX_U64),
    default = 0,
    derive(Clone, Copy,
        Debug, Display, Default,
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
    /// A [`Uint53`] with the default value of zero.
    pub fn zero() -> Self {
        Self::default()
    }

    /// Returns true if and only if `self == 0`.
    pub fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
}

impl TryFrom<i8> for Uint53 {
    type Error = Uint53Error;
    /// One can try to make a [`Uint53`] from an [`i8`].
    #[inline]
    fn try_from(value: i8) -> Result<Self, Self::Error> {
        u64::try_from(value)
            .map_err(|_| Uint53Error::GreaterOrEqualViolated)
            .and_then(Self::try_new)
    }
}

impl From<u8> for Uint53 {
    /// A [`Uint53`] can always be made from a [`u8`].
    #[inline]
    fn from(value: u8) -> Self {
        unsafe { Self::new_unchecked(value as u64) }
    }
}

impl TryFrom<i16> for Uint53 {
    type Error = Uint53Error;
    /// One can try to make a [`Uint53`] from an [`i16`].
    #[inline]
    fn try_from(value: i16) -> Result<Self, Self::Error> {
        u64::try_from(value)
            .map_err(|_| Uint53Error::GreaterOrEqualViolated)
            .and_then(Self::try_new)
    }
}

impl From<u16> for Uint53 {
    /// A [`Uint53`] can always be made from a [`u16`].
    #[inline]
    fn from(value: u16) -> Self {
        unsafe { Self::new_unchecked(value as u64) }
    }
}

impl TryFrom<i32> for Uint53 {
    type Error = Uint53Error;
    /// One can try to make a [`Uint53`] from a [`i32`].
    #[inline]
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        u64::try_from(value)
            .map_err(|_| Uint53Error::GreaterOrEqualViolated)
            .and_then(Self::try_new)
    }
}

impl From<u32> for Uint53 {
    /// A [`Uint53`] can always be made from a [`u32`].
    #[inline]
    fn from(value: u32) -> Self {
        unsafe { Self::new_unchecked(value as u64) }
    }
}

impl TryFrom<i64> for Uint53 {
    type Error = Uint53Error;
    /// One can try to make a [`Uint53`] from an [`i64`].
    #[inline]
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        u64::try_from(value)
            .map_err(|_| Uint53Error::GreaterOrEqualViolated)
            .and_then(Self::try_new)
    }
}

impl TryFrom<isize> for Uint53 {
    type Error = Uint53Error;
    /// One can try to make a [`Uint53`] from an [`isize`].
    #[inline]
    fn try_from(value: isize) -> Result<Self, Self::Error> {
        u64::try_from(value)
            .map_err(|_| Uint53Error::GreaterOrEqualViolated)
            .and_then(Self::try_new)
    }
}

impl TryFrom<usize> for Uint53 {
    type Error = Uint53Error;
    /// One can try to make a [`Uint53`] from a [`usize`].
    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if let Ok(valu64) = u64::try_from(value) {
            if valu64 <= UINT53_MAX_U64 {
                return Ok(unsafe { Self::new_unchecked(valu64) });
            }
        }
        Err(Uint53Error::LessOrEqualViolated)
    }
}

impl TryFrom<i128> for Uint53 {
    type Error = Uint53Error;
    /// One can try to make a [`Uint53`] from an [`i128`].
    #[inline]
    fn try_from(value: i128) -> Result<Self, Self::Error> {
        u128::try_from(value)
            .map_err(|_| Uint53Error::GreaterOrEqualViolated)
            .and_then(Self::try_from)
    }
}

impl TryFrom<u128> for Uint53 {
    type Error = Uint53Error;
    /// One can try to make a [`Uint53`] from a [`u128`].
    #[inline]
    fn try_from(value: u128) -> Result<Self, Self::Error> {
        if value <= UINT53_MAX_U64 as u128 {
            return Ok(unsafe { Self::new_unchecked(value as u64) });
        }
        Err(Uint53Error::LessOrEqualViolated)
    }
}

impl TryFrom<Uint53> for i8 {
    type Error = std::num::TryFromIntError;
    /// One can try to make an [`i8`] from a [`Uint53`].
    #[inline]
    fn try_from(valu53: Uint53) -> Result<Self, Self::Error> {
        valu53.into_inner().try_into()
    }
}

impl TryFrom<Uint53> for u8 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`u8`] from a [`Uint53`].
    #[inline]
    fn try_from(valu53: Uint53) -> Result<Self, Self::Error> {
        valu53.into_inner().try_into()
    }
}

impl TryFrom<Uint53> for i16 {
    type Error = std::num::TryFromIntError;
    /// One can try to make an [`i16`] from a [`Uint53`].
    #[inline]
    fn try_from(valu53: Uint53) -> Result<Self, Self::Error> {
        valu53.into_inner().try_into()
    }
}

impl TryFrom<Uint53> for u16 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`u16`] from a [`Uint53`].
    #[inline]
    fn try_from(valu53: Uint53) -> Result<Self, Self::Error> {
        valu53.into_inner().try_into()
    }
}

impl TryFrom<Uint53> for i32 {
    type Error = std::num::TryFromIntError;
    /// One can try to make an [`i32`] from a [`Uint53`].
    #[inline]
    fn try_from(valu53: Uint53) -> Result<Self, Self::Error> {
        valu53.into_inner().try_into()
    }
}

impl TryFrom<Uint53> for u32 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`u32`] from a [`Uint53`].
    #[inline]
    fn try_from(valu53: Uint53) -> Result<Self, Self::Error> {
        valu53.into_inner().try_into()
    }
}

impl From<Uint53> for i64 {
    /// An [`i64`] can always be made from a [`Uint53`].
    #[inline]
    fn from(valu53: Uint53) -> Self {
        valu53.into_inner() as i64
    }
}

impl TryFrom<Uint53> for isize {
    type Error = std::num::TryFromIntError;
    /// One can try to make an [`isize`] from a [`Uint53`].
    #[inline]
    fn try_from(valu53: Uint53) -> Result<Self, Self::Error> {
        valu53.into_inner().try_into()
    }
}

impl TryFrom<Uint53> for usize {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`usize`] from a [`Uint53`].
    #[inline]
    fn try_from(valu53: Uint53) -> Result<Self, Self::Error> {
        valu53.into_inner().try_into()
    }
}

impl From<Uint53> for i128 {
    /// An [`i128`] can always be made from a [`Uint53`].
    #[inline]
    fn from(valu53: Uint53) -> Self {
        valu53.into_inner() as i128
    }
}

impl From<Uint53> for u128 {
    /// A [`u128`] can always be made from a [`Uint53`].
    #[inline]
    fn from(valu53: Uint53) -> Self {
        valu53.into_inner() as u128
    }
}

//-------------------------------------------------------------------------------------------------|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::Result;

    use super::*;

    #[test]
    fn t10() -> Result<()> {
        // i8
        assert!(Uint53::try_from(-1_i8).is_err());
        assert_eq!(*Uint53::try_from(0_i8).unwrap(), 0_u64);
        assert_eq!(*Uint53::try_from(127_i8).unwrap(), 127_u64);

        assert_eq!(i8::try_from(Uint53::from(0_u16))?, 0_i8);
        assert_eq!(i8::try_from(Uint53::from(127_u16))?, 127_i8);
        assert!(i8::try_from(Uint53::from(128_u16)).is_err());

        // u8
        assert_eq!(*Uint53::from(0_u8), 0_u64);
        assert_eq!(*Uint53::from(u8::MAX), u8::MAX as u64);

        assert_eq!(u8::try_from(Uint53::from(0_u32))?, 0_u8);
        assert_eq!(u8::try_from(Uint53::from(255_u32))?, 255_u8);
        assert!(u8::try_from(Uint53::from(256_u32)).is_err());

        // i16
        assert!(Uint53::try_from(-1_i16).is_err());
        assert_eq!(*Uint53::try_from(0_i16).unwrap(), 0_u64);
        assert_eq!(*Uint53::try_from(32767_i16).unwrap(), 32767_u64);

        assert_eq!(i16::try_from(Uint53::from(0_u32))?, 0_i16);
        assert_eq!(i16::try_from(Uint53::from(32767_u32))?, 32767_i16);
        assert!(i16::try_from(Uint53::from(32768_u32)).is_err());

        // u16
        assert_eq!(*Uint53::from(0_u16), 0_u64);
        assert_eq!(*Uint53::from(u16::MAX), u16::MAX as u64);

        assert_eq!(u16::try_from(Uint53::from(0_u32))?, 0_u16);
        assert_eq!(u16::try_from(Uint53::from(u16::MAX))?, u16::MAX);
        assert!(u16::try_from(Uint53::from((u16::MAX as u32) + 1)).is_err());

        // i32
        assert!(Uint53::try_from(-1_i32).is_err());
        assert_eq!(*Uint53::try_from(0_i32).unwrap(), 0_u64);
        assert_eq!(*Uint53::try_from(i32::MAX).unwrap(), i32::MAX as u64);

        assert_eq!(i32::try_from(Uint53::from(0_u32))?, 0_i32);
        assert_eq!(i32::try_from(Uint53::from(i32::MAX as u32))?, i32::MAX);
        assert!(i32::try_from(Uint53::from(i32::MAX as u32 + 1)).is_err());

        // u32
        assert_eq!(*Uint53::from(0_u32), 0_u64);
        assert_eq!(*Uint53::from(u32::MAX), u32::MAX as u64);

        assert_eq!(u32::try_from(Uint53::from(0_u32))?, 0_u32);
        assert_eq!(u32::try_from(Uint53::from(u32::MAX))?, u32::MAX);
        assert!(u32::try_from(Uint53::try_from((u32::MAX as u64) + 1)?).is_err());

        // i64
        assert!(Uint53::try_from(-1_i64).is_err());
        assert_eq!(*Uint53::try_from(0_i64).unwrap(), 0_u64);
        assert_eq!(*Uint53::try_from(UINT53_MAX_U64 as i64)?, UINT53_MAX_U64);
        assert!(Uint53::try_from((UINT53_MAX_U64 as i64) + 1).is_err());

        assert_eq!(i64::from(Uint53::from(0_u8)), 0_i64);
        assert_eq!(
            i64::from(Uint53::try_from(UINT53_MAX_U64)?),
            UINT53_MAX_U64 as i64
        );

        // u64
        assert_eq!(*Uint53::default(), 0_u64);
        assert_eq!(*Uint53::try_from(0_u64).unwrap(), 0_u64);
        assert_eq!(*Uint53::try_from(UINT53_MAX_U64)?, UINT53_MAX_U64);
        assert!(Uint53::try_from(UINT53_MAX_U64 + 1).is_err());

        assert_eq!(*Uint53::try_from((1_u64 << 53) - 1)?, UINT53_MAX_U64);
        assert!(Uint53::try_from(1_u64 << 53).is_err());
        assert!(Uint53::try_from(u64::MAX).is_err());

        assert_eq!(u64::from(Uint53::from(0_u8)), 0_u64);
        assert_eq!(u64::from(Uint53::try_from(UINT53_MAX_U64)?), UINT53_MAX_U64);

        // isize
        let uint53max_isize = (isize::MAX as u64).min(UINT53_MAX_U64) as isize;
        let uint53max_usize = (usize::MAX as u64).min(UINT53_MAX_U64) as usize;
        assert!(Uint53::try_from(-1_isize).is_err());
        assert_eq!(*Uint53::try_from(0_isize)?, 0_u64);
        assert_eq!(*Uint53::try_from(uint53max_isize)?, uint53max_isize as u64);
        assert!(Uint53::try_from(isize::MAX).is_err());

        assert_eq!(isize::try_from(Uint53::from(0_u8))?, 0_isize);
        assert_eq!(
            isize::try_from(Uint53::try_from(uint53max_isize)?)?,
            uint53max_isize
        );

        // usize
        assert_eq!(*Uint53::try_from(0_usize)?, 0_u64);
        assert_eq!(*Uint53::try_from(uint53max_usize)?, uint53max_usize as u64);

        assert_eq!(usize::try_from(Uint53::from(0_u8))?, 0_usize);
        assert_eq!(
            usize::try_from(Uint53::try_from(uint53max_usize)?)?,
            uint53max_usize
        );

        // i128
        assert!(Uint53::try_from(-1_i128).is_err());
        assert_eq!(*Uint53::try_from(0_i128).unwrap(), 0_u64);
        assert_eq!(*Uint53::try_from(UINT53_MAX_U64 as i128)?, UINT53_MAX_U64);
        assert!(Uint53::try_from((UINT53_MAX_U64 as i128) + 1).is_err());

        assert_eq!(i128::from(Uint53::from(0_u8)), 0_i128);
        assert_eq!(
            i128::from(Uint53::try_from(UINT53_MAX_U64)?),
            UINT53_MAX_U64 as i128
        );

        // u128
        assert_eq!(*Uint53::try_from(0_u128).unwrap(), 0_u64);
        assert_eq!(*Uint53::try_from(UINT53_MAX_U64 as u128)?, UINT53_MAX_U64);
        assert!(Uint53::try_from((UINT53_MAX_U64 as u128) + 1).is_err());

        assert_eq!(u128::from(Uint53::from(0_u8)), 0_u128);
        assert_eq!(
            u128::from(Uint53::try_from(UINT53_MAX_U64)?),
            UINT53_MAX_U64 as u128
        );

        Ok(())
    }
}
