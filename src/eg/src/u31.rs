// Copyright (C) Microsoft Corporation. All rights reserved.

const UINT31_MAX_U32: u32 = i32::MAX as u32;

#[nutype::nutype(
    new_unchecked,
    validate(less_or_equal = i32::MAX as u32),
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
pub struct Uint31(u32);

impl Uint31 {
    pub fn zero() -> Self {
        Self::default()
    }

    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }
}

impl From<u8> for Uint31 {
    #[inline]
    fn from(value: u8) -> Self {
        unsafe { Self::new_unchecked(value as u32) }
    }
}

impl From<u16> for Uint31 {
    #[inline]
    fn from(value: u16) -> Self {
        unsafe { Self::new_unchecked(value as u32) }
    }
}

impl TryFrom<i32> for Uint31 {
    type Error = Uint31Error;
    #[inline]
    fn try_from(value: i32) -> Result<Uint31, Self::Error> {
        if let Ok(v32) = u32::try_from(value) {
            if v32 <= UINT31_MAX_U32 {
                return Ok(unsafe { Self::new_unchecked(v32) });
            }
        }
        Err(Uint31Error::LessOrEqualViolated)
    }
}

impl TryFrom<usize> for Uint31 {
    type Error = Uint31Error;
    #[inline]
    fn try_from(value: usize) -> Result<Uint31, Self::Error> {
        if let Ok(v32) = u32::try_from(value) {
            if v32 <= UINT31_MAX_U32 {
                return Ok(unsafe { Self::new_unchecked(v32) });
            }
        }
        Err(Uint31Error::LessOrEqualViolated)
    }
}

impl TryFrom<u64> for Uint31 {
    type Error = Uint31Error;
    #[inline]
    fn try_from(value: u64) -> Result<Uint31, Self::Error> {
        if value <= UINT31_MAX_U32 as u64 {
            return Ok(unsafe { Self::new_unchecked(value as u32) });
        }
        Err(Uint31Error::LessOrEqualViolated)
    }
}

impl TryFrom<u128> for Uint31 {
    type Error = Uint31Error;
    #[inline]
    fn try_from(value: u128) -> Result<Uint31, Self::Error> {
        if value <= UINT31_MAX_U32 as u128 {
            return Ok(unsafe { Self::new_unchecked(value as u32) });
        }
        Err(Uint31Error::LessOrEqualViolated)
    }
}

impl TryFrom<Uint31> for usize {
    type Error = std::num::TryFromIntError;
    #[inline]
    fn try_from(value: Uint31) -> Result<usize, Self::Error> {
        let valu32 = *value;
        usize::try_from(valu32)
    }
}

impl From<Uint31> for u64 {
    #[inline]
    fn from(value: Uint31) -> Self {
        value.into_inner() as u64
    }
}

impl From<Uint31> for u128 {
    #[inline]
    fn from(value: Uint31) -> Self {
        value.into_inner() as u128
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use anyhow::Result;

    #[test]
    fn t10() -> Result<()> {
        assert_eq!(*Uint31::try_new(0)?, 0_u32);
        assert_eq!(*Uint31::try_new((1_u32 << 31) - 1)?, UINT31_MAX_U32);
        assert!(Uint31::try_new(1_u32 << 31).is_err());
        assert!(Uint31::try_new(u32::MAX).is_err());

        assert_eq!(*Uint31::from(0_u8), 0_u32);
        assert_eq!(*Uint31::from(0xff_u8), 0xff_u32);

        assert_eq!(*Uint31::from(0_u16), 0_u32);
        assert_eq!(*Uint31::from(0xff_u16), 0xff_u32);

        assert_eq!(Uint31::try_from(123_usize), Ok(Uint31::from(123_u8)));

        assert_eq!(*Uint31::try_from(0_u64).unwrap(), 0_u32);
        assert_eq!(
            *Uint31::try_from(UINT31_MAX_U32 as u64).unwrap(),
            UINT31_MAX_U32
        );
        assert!(Uint31::try_from(UINT31_MAX_U32 as u64 + 1).is_err());

        assert_eq!(*Uint31::try_from(0_usize).unwrap(), 0_u32);
        assert_eq!(
            *Uint31::try_from(UINT31_MAX_U32 as usize).unwrap(),
            UINT31_MAX_U32
        );
        assert!(Uint31::try_from(UINT31_MAX_U32 + 1).is_err());

        assert_eq!(u32::from(Uint31::default()), 0_u32);
        assert_eq!(u64::from(Uint31::default()), 0_u64);
        assert_eq!(u128::from(Uint31::default()), 0_u128);

        Ok(())
    }
}
