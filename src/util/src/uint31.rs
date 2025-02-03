// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

const UINT31_MAX_U32: u32 = (1_u32 << 31) - 1;

/// The main [`std::error::Error`] type returned by the `Uint31` type.
#[derive(thiserror::Error, Clone, Debug)]
pub enum U31Error {
    #[error("Value `{0}` out of range `0 <= n < 2^31` for a `Uint31`")]
    ValueOutOfRangeForUint31(i128),
}

#[nutype::nutype(
    new_unchecked,
    validate(
        greater_or_equal = 0,
        less_or_equal = UINT31_MAX_U32),
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
pub struct Uint31(u32);

impl Uint31 {
    /// A [`Uint31`] with the default value of zero.
    pub fn zero() -> Self {
        Self::default()
    }

    /// Returns true if and only if `self == 0`.
    pub fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
}

impl TryFrom<i8> for Uint31 {
    type Error = Uint31Error;
    /// One can try to make a [`Uint31`] from an [`i8`].
    #[inline]
    fn try_from(value: i8) -> Result<Self, Self::Error> {
        u32::try_from(value)
            .map_err(|_| Uint31Error::GreaterOrEqualViolated)
            .and_then(Self::try_new)
    }
}

impl From<u8> for Uint31 {
    /// A [`Uint31`] can always be made from a [`u8`].
    #[inline]
    fn from(value: u8) -> Self {
        unsafe { Self::new_unchecked(value as u32) }
    }
}

impl TryFrom<i16> for Uint31 {
    type Error = Uint31Error;
    /// One can try to make a [`Uint31`] from an [`i16`].
    #[inline]
    fn try_from(value: i16) -> Result<Self, Self::Error> {
        u32::try_from(value)
            .map_err(|_| Uint31Error::GreaterOrEqualViolated)
            .and_then(Self::try_new)
    }
}

impl From<u16> for Uint31 {
    /// A [`Uint31`] can always be made from a [`u16`].
    #[inline]
    fn from(value: u16) -> Self {
        unsafe { Self::new_unchecked(value as u32) }
    }
}

impl TryFrom<i32> for Uint31 {
    type Error = Uint31Error;
    /// One can try to make a [`Uint31`] from a [`i32`].
    #[inline]
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        u32::try_from(value)
            .map_err(|_| Uint31Error::GreaterOrEqualViolated)
            .and_then(Self::try_new)
    }
}

// u32

impl TryFrom<i64> for Uint31 {
    type Error = Uint31Error;
    /// One can try to make a [`Uint31`] from an [`i64`].
    #[inline]
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        u32::try_from(value)
            .map_err(|_| Uint31Error::GreaterOrEqualViolated)
            .and_then(Self::try_new)
    }
}

impl TryFrom<u64> for Uint31 {
    type Error = Uint31Error;
    /// One can try to make a [`Uint31`] from a [`u64`].
    #[inline]
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value <= UINT31_MAX_U32 as u64 {
            return Ok(unsafe { Self::new_unchecked(value as u32) });
        }
        Err(Uint31Error::LessOrEqualViolated)
    }
}

impl TryFrom<isize> for Uint31 {
    type Error = Uint31Error;
    /// One can try to make a [`Uint31`] from an [`isize`].
    #[inline]
    fn try_from(value: isize) -> Result<Self, Self::Error> {
        u32::try_from(value)
            .map_err(|_| Uint31Error::GreaterOrEqualViolated)
            .and_then(Self::try_new)
    }
}

impl TryFrom<usize> for Uint31 {
    type Error = Uint31Error;
    /// One can try to make a [`Uint31`] from a [`usize`].
    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value <= UINT31_MAX_U32 as usize {
            return Ok(unsafe { Self::new_unchecked(value as u32) });
        }
        Err(Uint31Error::LessOrEqualViolated)
    }
}

impl TryFrom<i128> for Uint31 {
    type Error = Uint31Error;
    /// One can try to make a [`Uint31`] from an [`i128`].
    #[inline]
    fn try_from(value: i128) -> Result<Self, Self::Error> {
        u128::try_from(value)
            .map_err(|_| Uint31Error::GreaterOrEqualViolated)
            .and_then(Self::try_from)
    }
}

impl TryFrom<u128> for Uint31 {
    type Error = Uint31Error;
    /// One can try to make a [`Uint31`] from a [`u128`].
    #[inline]
    fn try_from(value: u128) -> Result<Self, Self::Error> {
        if value <= UINT31_MAX_U32 as u128 {
            return Ok(unsafe { Self::new_unchecked(value as u32) });
        }
        Err(Uint31Error::LessOrEqualViolated)
    }
}

impl TryFrom<Uint31> for i8 {
    type Error = std::num::TryFromIntError;
    /// One can try to make an [`i8`] from a [`Uint31`].
    #[inline]
    fn try_from(valu31: Uint31) -> Result<Self, Self::Error> {
        valu31.into_inner().try_into()
    }
}

impl TryFrom<Uint31> for u8 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`u8`] from a [`Uint31`].
    #[inline]
    fn try_from(valu31: Uint31) -> Result<Self, Self::Error> {
        valu31.into_inner().try_into()
    }
}

impl TryFrom<Uint31> for i16 {
    type Error = std::num::TryFromIntError;
    /// One can try to make an [`i16`] from a [`Uint31`].
    #[inline]
    fn try_from(valu31: Uint31) -> Result<Self, Self::Error> {
        valu31.into_inner().try_into()
    }
}

impl TryFrom<Uint31> for u16 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`u16`] from a [`Uint31`].
    #[inline]
    fn try_from(valu31: Uint31) -> Result<Self, Self::Error> {
        valu31.into_inner().try_into()
    }
}

impl From<Uint31> for i32 {
    /// An [`i32`] can always be made from a [`Uint31`].
    #[inline]
    fn from(valu31: Uint31) -> Self {
        debug_assert!(UINT31_MAX_U32 as u128 <= i32::MAX as u128);
        valu31.into_inner() as i32
    }
}

// u32

impl From<Uint31> for i64 {
    /// An [`i64`] can always be made from a [`Uint31`].
    #[inline]
    fn from(valu31: Uint31) -> Self {
        valu31.into_inner() as i64
    }
}

impl From<Uint31> for u64 {
    /// An [`u64`] can always be made from a [`Uint31`].
    #[inline]
    fn from(valu31: Uint31) -> Self {
        valu31.into_inner() as u64
    }
}

impl From<Uint31> for isize {
    /// An [`isize`] can always be made from a [`Uint31`].
    #[inline]
    fn from(valu31: Uint31) -> Self {
        debug_assert!(UINT31_MAX_U32 as u128 <= isize::MAX as u128);
        valu31.into_inner() as isize
    }
}

impl From<Uint31> for usize {
    /// An [`usize`] can always be made from a [`Uint31`].
    #[inline]
    fn from(valu31: Uint31) -> Self {
        debug_assert!(UINT31_MAX_U32 as u128 <= usize::MAX as u128);
        valu31.into_inner() as usize
    }
}

impl From<Uint31> for i128 {
    /// An [`i128`] can always be made from a [`Uint31`].
    #[inline]
    fn from(valu31: Uint31) -> Self {
        valu31.into_inner() as i128
    }
}

impl From<Uint31> for u128 {
    /// A [`u128`] can always be made from a [`Uint31`].
    #[inline]
    fn from(valu31: Uint31) -> Self {
        valu31.into_inner() as u128
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
        assert!(Uint31::try_from(-1_i8).is_err());
        assert_eq!(*Uint31::try_from(0_i8)?, 0_u32);
        assert_eq!(*Uint31::try_from(i8::MAX)?, i8::MAX as u32);

        assert_eq!(i8::try_from(Uint31::from(0_u8))?, 0_i8);
        assert_eq!(i8::try_from(Uint31::from(i8::MAX as u8))?, i8::MAX);
        assert!(i8::try_from(Uint31::from((i8::MAX as u8) + 1)).is_err());

        // u8
        assert_eq!(*Uint31::from(0_u8), 0_u32);
        assert_eq!(*Uint31::from(u8::MAX), u8::MAX as u32);

        assert_eq!(u8::try_from(Uint31::from(0_u8))?, 0_u8);
        assert_eq!(u8::try_from(Uint31::from(u8::MAX))?, u8::MAX);
        assert!(u8::try_from(Uint31::from((u8::MAX as u16) + 1)).is_err());

        // i16
        assert!(Uint31::try_from(-1_i16).is_err());
        assert_eq!(*Uint31::try_from(0_i16)?, 0_u32);
        assert_eq!(*Uint31::try_from(i16::MAX)?, i16::MAX as u32);

        assert_eq!(i16::try_from(Uint31::from(0_u8))?, 0_i16);
        assert_eq!(i16::try_from(Uint31::from(i16::MAX as u16))?, i16::MAX);
        assert!(i16::try_from(Uint31::from((i16::MAX as u16) + 1)).is_err());

        // u16
        assert_eq!(*Uint31::from(0_u16), 0_u32);
        assert_eq!(*Uint31::from(u16::MAX), u16::MAX as u32);

        assert_eq!(u16::try_from(Uint31::from(0_u16))?, 0_u16);
        assert_eq!(u16::try_from(Uint31::from(u16::MAX))?, u16::MAX);
        assert!(u16::try_from(Uint31::try_from((u16::MAX as u32) + 1)?).is_err());

        // i32
        assert!(Uint31::try_from(-1_i32).is_err());
        assert_eq!(*Uint31::try_from(0_i32)?, 0_u32);
        assert_eq!(*Uint31::try_from(i32::MAX)?, i32::MAX as u32);

        assert_eq!(i32::from(Uint31::from(0_u8)), 0_i32);
        assert_eq!(
            i32::from(Uint31::try_from(i32::MAX as u32)?),
            UINT31_MAX_U32 as i32
        );
        //assert!(   i32::try_from(Uint31::try_from((i32::MAX as u32) + 1)?).is_err());

        // u32
        assert_eq!(*Uint31::try_from(0_u32)?, 0_u32);
        assert_eq!(*Uint31::try_from(UINT31_MAX_U32)?, UINT31_MAX_U32);
        assert!(Uint31::try_from(UINT31_MAX_U32 + 1).is_err());

        assert_eq!(u32::from(Uint31::from(0_u8)), 0_u32);
        assert_eq!(u32::from(Uint31::try_from(UINT31_MAX_U32)?), UINT31_MAX_U32);

        // i64
        assert!(Uint31::try_from(-1_i64).is_err());
        assert_eq!(*Uint31::try_from(0_i64)?, 0_u32);
        assert_eq!(*Uint31::try_from(UINT31_MAX_U32 as i64)?, UINT31_MAX_U32);
        assert!(Uint31::try_from((UINT31_MAX_U32 as i64) + 1).is_err());

        assert_eq!(i64::from(Uint31::from(0_u8)), 0_i64);
        assert_eq!(
            i64::from(Uint31::try_from(UINT31_MAX_U32)?),
            UINT31_MAX_U32 as i64
        );

        // u64
        assert_eq!(*Uint31::try_from(0_u64)?, 0_u32);
        assert_eq!(*Uint31::try_from(UINT31_MAX_U32 as u64)?, UINT31_MAX_U32);
        assert!(Uint31::try_from((UINT31_MAX_U32 as u64) + 1).is_err());

        assert_eq!(u64::from(Uint31::from(0_u8)), 0_u64);
        assert_eq!(
            u64::from(Uint31::try_from(UINT31_MAX_U32)?),
            UINT31_MAX_U32 as u64
        );

        // isize
        assert!(Uint31::try_from(-1_isize).is_err());
        assert_eq!(*Uint31::try_from(0_isize)?, 0_u32);
        assert_eq!(*Uint31::try_from(UINT31_MAX_U32 as isize)?, UINT31_MAX_U32);
        assert!(Uint31::try_from((UINT31_MAX_U32 as isize) + 1).is_err());

        assert_eq!(isize::from(Uint31::from(0_u8)), 0_isize);
        assert_eq!(
            isize::from(Uint31::try_from(UINT31_MAX_U32)?),
            UINT31_MAX_U32 as isize
        );

        // usize
        assert_eq!(*Uint31::try_from(0_usize)?, 0_u32);
        assert_eq!(*Uint31::try_from(UINT31_MAX_U32 as usize)?, UINT31_MAX_U32);
        assert!(Uint31::try_from((UINT31_MAX_U32 as usize) + 1).is_err());

        assert_eq!(usize::from(Uint31::from(0_u8)), 0_usize);
        assert_eq!(
            usize::from(Uint31::try_from(UINT31_MAX_U32)?),
            UINT31_MAX_U32 as usize
        );

        // i128
        assert!(Uint31::try_from(-1_i128).is_err());
        assert_eq!(*Uint31::try_from(0_i128)?, 0_u32);
        assert_eq!(*Uint31::try_from(UINT31_MAX_U32 as i128)?, UINT31_MAX_U32);
        assert!(Uint31::try_from((UINT31_MAX_U32 as i128) + 1).is_err());

        assert_eq!(i128::from(Uint31::from(0_u8)), 0_i128);
        assert_eq!(
            i128::from(Uint31::try_from(UINT31_MAX_U32)?),
            UINT31_MAX_U32 as i128
        );

        // u128
        assert_eq!(*Uint31::try_from(0_u128)?, 0_u32);
        assert_eq!(*Uint31::try_from(UINT31_MAX_U32 as u128)?, UINT31_MAX_U32);
        assert!(Uint31::try_from((UINT31_MAX_U32 as u128) + 1).is_err());

        assert_eq!(u128::from(Uint31::from(0_u8)), 0_u128);
        assert_eq!(
            u128::from(Uint31::try_from(UINT31_MAX_U32)?),
            UINT31_MAX_U32 as u128
        );

        Ok(())
    }
}
