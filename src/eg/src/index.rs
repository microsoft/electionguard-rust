// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::marker::PhantomData;
use std::ops::RangeInclusive;

use anyhow::anyhow;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use static_assertions::const_assert;

use crate::errors::{EgError, EgResult};

/// A 1-based ordinal type that enforces a range 1 <= i < 2^31.
///
/// `T` is a tag for disambiguation. It can be any type.
///
/// This type can also be used represent cardinal numbers using the [`.as_quantity()`] method.
pub struct Index<T>(u32, PhantomData<fn(T) -> T>)
where
    T: ?Sized;

// Copy trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T: ?Sized> std::marker::Copy for Index<T> {}

// Clone trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T: ?Sized> Clone for Index<T> {
    fn clone(&self) -> Self {
        *self
    }
}

// PartialEq trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T: ?Sized> PartialEq for Index<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// Convenience for comparing indexes to numeric literals.
impl<T: ?Sized> PartialEq<u32> for Index<T> {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

// Eq trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T: ?Sized> Eq for Index<T> {}

// Convenience for comparing indexes to numeric literals.
impl<T: ?Sized> std::cmp::PartialOrd<u32> for Index<T> {
    fn partial_cmp(&self, other: &u32) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(other))
    }
}

// PartialOrd trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T: ?Sized> std::cmp::PartialOrd for Index<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

// Ord trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T: ?Sized> std::cmp::Ord for Index<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

// Verify that on the target platform `usize` is large enough to hold `i32::MAX`.
// If someone needs to target a 16-bit platform with this code, we will have to deal
// with `Vec` index type being too small to represent the spec commitment.
const INDEX_MAX_U32: u32 = (1u32 << 31) - 1;
const_assert!(INDEX_MAX_U32 as u64 <= (usize::MAX as u64));
const_assert!(INDEX_MAX_U32 as usize <= usize::MAX);

impl<T: ?Sized> Index<T> {
    /// Minimum valid value as a `u32`.
    pub const VALID_MIN_U32: u32 = 1;

    /// Maximum valid value as a `u32`.
    pub const VALID_MAX_U32: u32 = INDEX_MAX_U32;

    /// Minimum value.
    pub const MIN: Self = Self(Self::VALID_MIN_U32, PhantomData);

    /// Maximum value.
    pub const MAX: Self = Self(Self::VALID_MAX_U32, PhantomData);

    /// Valid [`RangeInclusive`]`<u32>`.
    pub const VALID_RANGEINCLUSIVE_U32: RangeInclusive<u32> =
        Self::VALID_MIN_U32..=Self::VALID_MAX_U32;

    /// Minimum valid value as a `usize`.
    pub const VALID_MIN_USIZE: usize = Self::VALID_MIN_U32 as usize;

    /// Maximum valid value as a `usize`.
    pub const VALID_MAX_USIZE: usize = Self::VALID_MAX_U32 as usize;

    /// Valid [`RangeInclusive`]`<usize>`.
    pub const VALID_RANGEINCLUSIVE_USIZE: RangeInclusive<usize> =
        Self::VALID_MIN_USIZE..=Self::VALID_MAX_USIZE;

    /// Returns the index value `1`.
    pub const fn one() -> Self {
        Self::MIN
    }

    /// Returns the index value `1 + rhs`. Since rhs is a `u16`, the result is always in the valid range.
    pub const fn one_plus_u16(rhs: u16) -> Self {
        Self(Self::VALID_MIN_U32 + rhs as u32, PhantomData)
    }

    /// An iterator over `Index` values over the inclusive range defined by [start, last].
    ///
    /// This is useful because `Index` cannot (yet) implement
    /// the `Step` trait necessary for iteration over a [`RangeInclusive`]
    /// because it's marked nightly-only.
    ///
    /// See rust issue 73121 "\[ER\] NonZeroX Step and better constructors"
    /// <https://github.com/rust-lang/rust/issues/73121>
    /// and libs-team issue 130 "Implement Step for NonZeroUxx"
    /// <https://github.com/rust-lang/libs-team/issues/130>
    pub fn iter_range_inclusive(start: Index<T>, last: Index<T>) -> impl Iterator<Item = Index<T>> {
        (start.0..=last.0).map(|i| Self(i, PhantomData))
    }

    /// Returns true iff `i` is a valid 1-based index value.
    pub const fn is_valid_one_based_index(i: u32) -> bool {
        // RangeInclusive::<Idx>::contains` is not yet stable as a const fn
        //Self::VALID_RANGEINCLUSIVE_U32.contains(&ix1)
        Self::VALID_MIN_U32 <= i && i <= Self::VALID_MAX_U32
    }

    /// Creates a new `Index` from a 1-based index value.
    pub const fn from_one_based_index_const(ix1: u32) -> Option<Self> {
        // _core::bool::<impl bool>::then_some` is not yet stable as a const fn
        // Self::is_valid_one_based_index(ix1).then_some(Self(ix1, PhantomData))

        if Self::is_valid_one_based_index(ix1) {
            Some(Self(ix1, PhantomData))
        } else {
            None
        }
    }

    /// Creates a new `Index` from a 1-based index value.
    pub fn from_one_based_index(ix1: u32) -> EgResult<Self> {
        Self::from_one_based_index_const(ix1)
            .ok_or_else(|| anyhow!("Index value {ix1} out of range"))
            .map_err(Into::into)
    }

    /// Returns true iff `ix0` is a valid 0-based index value.
    pub const fn is_valid_zero_based_index_usize(ix0: usize) -> bool {
        ix0 < Self::VALID_MAX_USIZE
    }

    /// Creates a new `Index` from a 1-based index value.
    /// All [`std::num::NonZeroU8`] values are valid.
    pub fn from_one_based_nonzero_u8(ix1: std::num::NonZeroU8) -> Self {
        Self(u8::from(ix1) as u32, PhantomData)
    }

    /// Creates a new `Index` from a 1-based index value.
    /// All [`std::num::NonZeroU16`] values are valid.
    pub fn from_one_based_nonzero_u16(ix1: std::num::NonZeroU16) -> Self {
        Self(u16::from(ix1) as u32, PhantomData)
    }

    /// Creates a new `Index` from a 1-based index value. It is a precondition that
    /// Self::VALID_MIN_U32 <= ix1 && ix1 <= Self::VALID_MAX_U32.
    pub fn from_one_based_index_unchecked(ix1: u32) -> Self {
        Self(ix1, PhantomData)
    }

    /// Creates a new `Index` from a 0-based index value.
    pub fn from_zero_based_index<U: Into<usize>>(ix0: U) -> EgResult<Self> {
        let ix0: usize = ix0.into();
        Self::is_valid_zero_based_index_usize(ix0)
            .then(|| Self((ix0 + 1) as u32, PhantomData))
            .ok_or_else(|| anyhow!("Index value {ix0} out of range for 0-based index"))
            .map_err(Into::into)
    }

    /// Creates a new `Index` from a 0-based index value. It is a precondition that
    /// 0 <= ix1 < Self::VALID_MAX_U32.
    pub fn from_zero_based_index_unchecked<U: Into<usize>>(ix0: U) -> Self {
        let ix0: usize = ix0.into();
        Self((ix0 + 1) as u32, PhantomData)
    }

    /// Obtains the 1-based index value as a `u32`.
    pub const fn get_one_based_u32(&self) -> u32 {
        debug_assert!(Self::is_valid_one_based_index(self.0));
        self.0
    }

    /// Obtains the 1-based index value as a `usize`.
    pub const fn get_one_based_usize(&self) -> usize {
        debug_assert!(Self::is_valid_one_based_index(self.0));
        self.0 as usize
    }

    /// Size of a container needed for this to be the highest index.
    /// Actually, this is just the same as [`Self::get_one_based_usize()`] but it
    /// reads more clearly when a cardinal number is needed.
    pub const fn as_quantity(&self) -> usize {
        self.get_one_based_usize()
    }

    /// Converts the 1-based index into a 0-based index as a `usize`.
    /// Suitable for indexing into a `std::Vec`.
    pub const fn get_zero_based_usize(&self) -> usize {
        self.get_one_based_usize() - 1
    }
}

/* impl<T, U> TryFrom<U> for Index<T>
where
    T: ?Sized,
    U: TryInto<u32>
{
    type Error = EgError;
    #[inline]
    fn try_from(value: U) -> EgResult<Self> {
        if let Ok(valu32) = u32::try_from(value) {
            if Self::VALID_RANGEINCLUSIVE_U32.contains(&valu32) {
                return Ok(Self::from_one_based_index_unchecked(valu32))
            }
        }
        return Err(anyhow!("Index value out of range 1..2^31.").into());
    }
} */

impl<T: ?Sized> TryFrom<u32> for Index<T> {
    type Error = EgError;
    #[inline]
    fn try_from(value: u32) -> EgResult<Self> {
        Self::from_one_based_index_const(value)
            .ok_or_else(|| anyhow!("Index value `{value}` out of range `1..2^31`"))
            .map_err(Into::into)
    }
}

impl<T: ?Sized> TryFrom<i32> for Index<T> {
    type Error = EgError;
    #[inline]
    fn try_from(value: i32) -> EgResult<Self> {
        if let Ok(valu32) = u32::try_from(value) {
            if Self::VALID_RANGEINCLUSIVE_U32.contains(&valu32) {
                return Ok(Self::from_one_based_index_unchecked(valu32));
            }
        }
        Err(anyhow!("Index value out of range 1..2^31.").into())
    }
}

impl<T: ?Sized> std::fmt::Display for Index<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl<T: ?Sized> std::fmt::Debug for Index<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Display::fmt(self, f)
    }
}

impl<T: ?Sized> std::str::FromStr for Index<T> {
    type Err = EgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_one_based_index(s.parse()?)
    }
}

impl<T: ?Sized> Serialize for Index<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for Index<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let ix1 = u32::deserialize(deserializer)?;

        Index::from_one_based_index(ix1).map_err(D::Error::custom)
    }
}

//-------------------------------------------------------------------------------------------------|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test_index {
    use super::*;

    use static_assertions::{assert_eq_size, assert_impl_all};

    #[allow(dead_code)]
    struct Foo;

    #[allow(dead_code)]
    struct Bar;

    type FooIndex = Index<Foo>;
    type BarIndex = Index<Bar>;

    // Checks on size and traits.
    assert_eq_size!(FooIndex, u32);
    assert_impl_all!(BarIndex: Clone, Copy, Send, Sync);

    #[test]
    fn test_range() {
        assert_eq!(FooIndex::VALID_MIN_U32, 1u32);
        assert_eq!(
            FooIndex::VALID_MIN_U32,
            *FooIndex::VALID_RANGEINCLUSIVE_U32.start()
        );
        assert_eq!(
            FooIndex::VALID_MAX_U32,
            *FooIndex::VALID_RANGEINCLUSIVE_U32.end()
        );
        assert_eq!(FooIndex::VALID_MAX_U32, INDEX_MAX_U32);

        // Verify VALID_MAX_U32 is 2^31 - 1.
        assert_eq!(FooIndex::VALID_MAX_U32, (1u32 << 31) - 1);
    }

    #[test]
    fn test_clone() {
        let foo_index1: FooIndex = FooIndex::from_one_based_index(1).unwrap();
        #[allow(clippy::clone_on_copy)]
        let foo_index2: FooIndex = foo_index1.clone();
        assert_eq!(
            foo_index1.get_zero_based_usize(),
            foo_index2.get_zero_based_usize()
        );
    }

    #[test]
    fn test_copy() {
        let foo_index1: FooIndex = FooIndex::from_one_based_index(1).unwrap();
        let foo_index2: FooIndex = foo_index1;
        assert_eq!(
            foo_index1.get_zero_based_usize(),
            foo_index2.get_zero_based_usize()
        );
    }

    #[test]
    fn test_00() {
        // Verify below lower limit
        assert!(FooIndex::from_one_based_index(0).is_err());

        // Verify within lower limit
        let foo_index = FooIndex::from_one_based_index(1).unwrap();
        assert_eq!(foo_index.get_one_based_usize(), 1);
        assert_eq!(foo_index.get_zero_based_usize(), 0);

        // Verify within upper limit
        let bar_index = BarIndex::from_one_based_index(BarIndex::VALID_MAX_U32).unwrap();

        assert_eq!(bar_index.get_one_based_usize(), BarIndex::VALID_MAX_USIZE);
        assert_eq!(
            bar_index.get_zero_based_usize(),
            FooIndex::VALID_MAX_USIZE - 1
        );

        // Verify above upper limit
        assert!(FooIndex::from_one_based_index(FooIndex::VALID_MAX_U32 + 1).is_err());

        // Verify that we can't mix up indices of different kinds.
        // Expected `Index<Foo>`, found `Index<Bar>`
        //let foo_index: FooIndex = bar_index;
    }
}
