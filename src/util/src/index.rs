// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::marker::PhantomData;
use std::ops::RangeInclusive;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use static_assertions::const_assert;

use crate::uint31::Uint31;

/// The [`std::error::Error`] type returned by the `Index` type.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum IndexError {
    #[error("Value `{0}` out of range `0 <= n < 2^31-1` for a zero-based index")]
    ValueOutOfRangeForZeroBasedIndex(i128),

    #[error("Value `{0}` out of range `1 <= n < 2^31` for a one-based index")]
    ValueOutOfRangeForOneBasedIndex(i128),

    #[error("(One-based) Index `{0}` not present in the collection or otherwise out of range")]
    IndexOutOfRange(u32),

    #[error("One-based Index could not be parsed from `{0}`: {1}")]
    ParseErr(
        String,
        #[serde(serialize_with = "crate::serde::serialize_std_num_parseinterror")]
        std::num::ParseIntError,
    ),
}

pub type IndexResult<T> = std::result::Result<T, IndexError>;

/// A 1-based ordinal type that enforces a range 1 <= i < 2^31.
///
/// `T` is a tag for disambiguation. It can be any type.
///
/// This type can also be used represent cardinal numbers using the [`.as_quantity()`] method.
pub struct Index<T>(u32, PhantomData<fn(T) -> T>)
where
    T: ?Sized;

/// Copy trait must be implmented manually because of the [`PhantomData`].
impl<T: ?Sized> std::marker::Copy for Index<T> {}

impl<T: ?Sized> Clone for Index<T> {
    /// Clone trait must be implmented manually because of the [`PhantomData`].
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> PartialEq for Index<T> {
    /// [`PartialEq`] trait must be implmented manually because of the [`PhantomData`].
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: ?Sized> PartialEq<u32> for Index<T> {
    /// Convenience for comparing indexes to numeric literals.
    #[inline]
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

/// [`Eq`] trait must be implmented manually because of the [`PhantomData`].
impl<T: ?Sized> Eq for Index<T> {}

impl<T: ?Sized> std::hash::Hash for Index<T> {
    /// Includes this value in the hash computation.
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<T: ?Sized> std::cmp::PartialOrd<u32> for Index<T> {
    /// Convenience for comparing indexes to numeric literals.
    #[inline]
    fn partial_cmp(&self, other: &u32) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(other))
    }
}

impl<T: ?Sized> std::cmp::PartialOrd for Index<T> {
    /// PartialOrd trait must be implmented manually because of the [`PhantomData`].
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl<T: ?Sized> std::cmp::Ord for Index<T> {
    /// Ord trait must be implmented manually because of the [`PhantomData`].
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

// Verify that on the target platform `usize` is large enough to hold `i32::MAX`.
// If someone needs to target a 16-bit platform with this code, we will have to deal
// with `Vec` index type being too small to represent the spec commitment.
const INDEX_MAX_U32: u32 = (1u32 << 31) - 1;
const_assert!(INDEX_MAX_U32 as u128 <= usize::MAX as u128);

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

    /// Returns the index value `MAX - rhs`. Since rhs is a `u16`, the result is always in the valid range.
    ///
    /// This is probably mostly just useful for unit tests.
    pub const fn max_minus_u16(rhs: u16) -> Self {
        Self(Self::VALID_MAX_U32 - rhs as u32, PhantomData)
    }

    /// An [`Iterator`] over [`Index`] values over the inclusive range defined by [start, last].
    ///
    /// This is useful because `Index` cannot (yet) implement
    /// the `Step` trait necessary for iteration over a [`RangeInclusive`]
    /// because it's marked nightly-only.
    ///
    /// See rust issue 73121 "\[ER\] NonZeroX Step and better constructors"
    /// <https://github.com/rust-lang/rust/issues/73121>
    ///
    /// Tracking issue for step_trait stabilization
    /// <https://github.com/rust-lang/rust/issues/42168>
    ///
    /// and libs-team issue 130 "Implement Step for NonZeroUxx"
    /// <https://github.com/rust-lang/libs-team/issues/130>
    #[inline]
    pub fn iter_range_inclusive(start: Index<T>, last: Index<T>) -> impl Iterator<Item = Index<T>> {
        (start.0..=last.0).map(|i| Self(i, PhantomData))
    }

    /// An [`Iterator`] over [`Index`] values over the inclusive range `[1, quantity]`.
    #[inline]
    pub fn iter_range_quantity(quantity: Uint31) -> impl Iterator<Item = Index<T>> {
        let quantity: u32 = quantity.into();
        (1_u32..=quantity).map(Self::from_one_based_index_unchecked)
    }

    /// Returns true iff `ix1` is a valid 1-based index value.
    #[inline]
    pub const fn is_valid_one_based_index_u32(ix1: u32) -> bool {
        Self::VALID_MIN_U32 <= ix1 && ix1 <= Self::VALID_MAX_U32
    }

    /// Returns true iff `ix0` is a valid 0-based index value.
    #[inline]
    pub const fn is_valid_zero_based_index_u32(ix0: u32) -> bool {
        ix0 < Self::VALID_MAX_U32
    }

    /// Tries to create a new `Index` from a 1-based index value.
    #[inline]
    pub const fn from_one_based_index_const_u32(ix1: u32) -> Option<Self> {
        if Self::is_valid_one_based_index_u32(ix1) {
            Some(Self(ix1, PhantomData))
        } else {
            None
        }
    }

    /// Tries to create a new `Index` from a 0-based index value.
    #[inline]
    pub const fn from_zero_based_index_const_u32(ix0: u32) -> Option<Self> {
        let ix1 = ix0.wrapping_add(1);
        Self::from_one_based_index_const_u32(ix1)
    }

    /// Tries to create a new `Index` from a 1-based index value.
    #[inline]
    pub fn try_from_one_based_index_u32(ix1: u32) -> IndexResult<Self> {
        Self::from_one_based_index_const_u32(ix1)
            .ok_or(IndexError::ValueOutOfRangeForOneBasedIndex(ix1.into()))
    }

    /// Tries to create a new `Index` from a 0-based index value.
    #[inline]
    pub fn try_from_zero_based_index_u32(ix0: u32) -> IndexResult<Self> {
        Self::from_zero_based_index_const_u32(ix0)
            .ok_or(IndexError::ValueOutOfRangeForZeroBasedIndex(ix0.into()))
    }

    /// Tries to create a new `Index` from a 1-based index value.
    pub fn try_from_one_based_index<U>(ix1: U) -> IndexResult<Self>
    where
        U: TryInto<u32> + TryInto<i128> + Copy,
    {
        TryInto::<u32>::try_into(ix1)
            .map_err(|_| {
                let ix1 = TryInto::<i128>::try_into(ix1).unwrap_or(i128::MAX);
                IndexError::ValueOutOfRangeForOneBasedIndex(ix1)
            })
            .and_then(Self::try_from_one_based_index_u32)
    }

    /// Tries to create a new `Index` from a 0-based index value.
    pub fn try_from_zero_based_index<U>(ix0: U) -> IndexResult<Self>
    where
        U: TryInto<u32> + TryInto<i128> + Copy,
    {
        TryInto::<u32>::try_into(ix0)
            .map_err(|_| {
                let ix0 = TryInto::<i128>::try_into(ix0).unwrap_or(i128::MAX);
                IndexError::ValueOutOfRangeForZeroBasedIndex(ix0)
            })
            .and_then(Self::try_from_zero_based_index_u32)
    }

    /// Creates a new `Index` from a 0-based index value, substituting [`Self::MAX`] for any values above
    /// the valid range.
    ///
    /// This should be used with care, as the situations in which saturating an index value is the
    /// right thing to do are probably pretty rare.
    #[inline]
    pub fn from_zero_based_index_saturating_u32_use_with_care(ix0: u32) -> Self {
        let ix0 = ix0.min(Self::VALID_MAX_U32 - 1);
        let ix1 = ix0 + 1;
        Self(ix1, PhantomData)
    }

    /// Creates a new `Index` from a 0-based index value of non-negative "unsigned" type, substituting
    /// [`Self::MAX`] for any values above the valid range.
    ///
    /// This should be used with care, as the situations in which saturating an index value is the
    /// right thing to do are probably pretty rare.
    pub fn from_zero_based_index_saturating_use_with_care<U>(ix0: U) -> Self
    where
        U: num_traits::sign::Unsigned + TryInto<u32> + Copy,
    {
        if let Ok(ix0) = TryInto::<u32>::try_into(ix0) {
            Self::from_zero_based_index_saturating_u32_use_with_care(ix0)
        } else {
            Self::MAX
        }
    }

    /// Creates a new `Index` from a 1-based index value.
    /// All [`std::num::NonZeroU8`] values are valid.
    #[inline]
    pub fn from_one_based_nonzero_u8(ix1: std::num::NonZeroU8) -> Self {
        Self(u8::from(ix1) as u32, PhantomData)
    }

    /// Creates a new `Index` from a 1-based index value.
    /// All [`std::num::NonZeroU16`] values are valid.
    #[inline]
    pub fn from_one_based_nonzero_u16(ix1: std::num::NonZeroU16) -> Self {
        Self(u16::from(ix1) as u32, PhantomData)
    }

    /// Creates a new `Index` from a 1-based index value. It is a precondition that
    /// Self::VALID_MIN_U32 <= ix1 && ix1 <= Self::VALID_MAX_U32.
    #[inline]
    pub const fn from_one_based_index_unchecked(ix1: u32) -> Self {
        debug_assert!(Self::is_valid_one_based_index_u32(ix1));
        Self(ix1, PhantomData)
    }

    /// Creates a new `Index` from a 0-based index value. It is a precondition that
    /// 0 <= ix1 < Self::VALID_MAX_U32.
    #[inline]
    pub fn from_zero_based_index_unchecked_usize(ix0: usize) -> Self {
        Self::from_one_based_index_unchecked(ix0.wrapping_add(1) as u32)
    }

    /// Obtains the 1-based index value as a `u32`.
    #[inline]
    pub const fn get_one_based_u32(&self) -> u32 {
        debug_assert!(Self::is_valid_one_based_index_u32(self.0));
        self.0
    }

    /// Obtains the 1-based index value as a big-endian four-byte array.
    #[inline]
    pub const fn get_one_based_4_be_bytes(&self) -> [u8; 4] {
        self.get_one_based_u32().to_be_bytes()
    }

    /// Obtains the 1-based index value as a `usize`.
    #[inline]
    pub const fn get_one_based_usize(&self) -> usize {
        self.get_one_based_u32() as usize
    }

    /// Obtains the 1-based index value as a `u64`.
    #[inline]
    pub const fn get_one_based_u64(&self) -> u64 {
        self.get_one_based_u32() as u64
    }

    /// Size of a container needed for this to be the highest index.
    /// Actually, this is just the same as [`Self::get_one_based_usize()`] but it
    /// reads more clearly when a cardinal number is needed.
    #[inline]
    pub const fn as_quantity(&self) -> usize {
        self.get_one_based_usize()
    }

    /// Converts the 1-based index into a 0-based index as a `u32`.
    #[inline]
    pub const fn get_zero_based_u32(&self) -> u32 {
        self.get_one_based_u32() - 1
    }

    /// Converts the 1-based index into a 0-based index as a `usize`.
    /// Suitable for indexing into a `std::Vec`.
    #[inline]
    pub const fn get_zero_based_usize(&self) -> usize {
        self.get_zero_based_u32() as usize
    }

    /// Converts the 1-based index into a 0-based index as a `u64`.
    #[inline]
    pub const fn get_zero_based_u64(&self) -> u64 {
        self.get_zero_based_u32() as u64
    }

    /// Returns true iff the index value has a successor (i.e., plus `1`).
    #[inline]
    pub const fn has_successor(self) -> bool {
        self.0 < Self::VALID_MAX_U32
    }

    /// Returns the successor (i.e., plus `1`) index value, if there is one.
    #[inline]
    pub const fn successor(self) -> Option<Self> {
        if self.has_successor() {
            Some(Self(self.0 + 1, PhantomData))
        } else {
            None
        }
    }

    /// Returns true iff this index value has a predecessor (i.e., minus `1`).
    #[inline]
    pub const fn has_predecessor(self) -> bool {
        Self::VALID_MIN_U32 < self.0
    }

    /// Returns the predecessor (i.e., minus `1`) index value, if there is one.
    #[inline]
    pub const fn predecessor(self) -> Option<Self> {
        if self.has_predecessor() {
            Some(Self(self.0 - 1, PhantomData))
        } else {
            None
        }
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

        Index::try_from_one_based_index_u32(ix1).map_err(D::Error::custom)
    }
}

impl<T: ?Sized> TryFrom<i8> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: i8) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
    }
}

impl<T: ?Sized> TryFrom<u8> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: u8) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
    }
}

impl<T: ?Sized> TryFrom<i16> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: i16) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
    }
}

impl<T: ?Sized> TryFrom<u16> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: u16) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
    }
}

impl<T: ?Sized> TryFrom<i32> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: i32) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
    }
}

impl<T: ?Sized> TryFrom<u32> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: u32) -> IndexResult<Self> {
        Self::try_from_one_based_index_u32(ix1)
    }
}

impl<T: ?Sized> TryFrom<i64> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: i64) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
    }
}

impl<T: ?Sized> TryFrom<u64> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: u64) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
    }
}

/*
impl<T: ?Sized> TryFrom<isize> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: isize) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
    }
}

impl<T: ?Sized> TryFrom<usize> for Index<T> {
    type Error = IndexError;
    #[inline]
    // maybe we really don't want this conversion
    //fn try_from(ix1: usize) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
    }
}
// */

impl<T: ?Sized> TryFrom<i128> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: i128) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
    }
}

impl<T: ?Sized> TryFrom<u128> for Index<T> {
    type Error = IndexError;
    #[inline]
    fn try_from(ix1: u128) -> IndexResult<Self> {
        Self::try_from_one_based_index(ix1)
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
    type Err = IndexError;
    /// One can try to parse an [`Index<T>`] from a [`&str`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>()
            .map_err(|e| IndexError::ParseErr(s.to_string(), e))
            .and_then(Self::try_from)
    }
}

impl<T: ?Sized> TryFrom<Index<T>> for i8 {
    type Error = std::num::TryFromIntError;
    /// One can try to make an [`i8`] from a [`Index<T>`].
    #[inline]
    fn try_from(ix: Index<T>) -> Result<Self, Self::Error> {
        ix.get_one_based_u32().try_into()
    }
}

impl<T: ?Sized> TryFrom<Index<T>> for u8 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`u8`] from a [`Index<T>`].
    #[inline]
    fn try_from(ix: Index<T>) -> Result<Self, Self::Error> {
        ix.get_one_based_u32().try_into()
    }
}

impl<T: ?Sized> TryFrom<Index<T>> for i16 {
    type Error = std::num::TryFromIntError;
    /// One can try to make an [`i16`] from a [`Index<T>`].
    #[inline]
    fn try_from(ix: Index<T>) -> Result<Self, Self::Error> {
        ix.get_one_based_u32().try_into()
    }
}

impl<T: ?Sized> TryFrom<Index<T>> for u16 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`u16`] from a [`Index<T>`].
    #[inline]
    fn try_from(ix: Index<T>) -> Result<Self, Self::Error> {
        ix.get_one_based_u32().try_into()
    }
}

impl<T: ?Sized> From<Index<T>> for i32 {
    /// An [`i32`] can always be made from a [`Index<T>`].
    #[inline]
    fn from(ix: Index<T>) -> Self {
        ix.get_one_based_u32() as i32
    }
}

impl<T: ?Sized> From<Index<T>> for u32 {
    /// A [`u32`] can always be made from a [`Index<T>`].
    #[inline]
    fn from(ix: Index<T>) -> Self {
        ix.get_one_based_u32()
    }
}

impl<T: ?Sized> From<Index<T>> for i64 {
    /// An [`i64`] can always be made from a [`Index<T>`].
    #[inline]
    fn from(ix: Index<T>) -> Self {
        ix.get_one_based_u32() as i64
    }
}

impl<T: ?Sized> From<Index<T>> for u64 {
    /// An [`u64`] can always be made from a [`Index<T>`].
    #[inline]
    fn from(ix: Index<T>) -> Self {
        ix.get_one_based_u32() as u64
    }
}

impl<T: ?Sized> From<Index<T>> for isize {
    /// An [`isize`] can always be made from a [`Index<T>`].
    #[inline]
    fn from(ix: Index<T>) -> Self {
        debug_assert!(INDEX_MAX_U32 as u128 <= isize::MAX as u128);
        ix.get_one_based_u32() as isize
    }
}

impl<T: ?Sized> From<Index<T>> for usize {
    /// An [`usize`] can always be made from a [`Index<T>`].
    #[inline]
    fn from(ix: Index<T>) -> Self {
        debug_assert!(INDEX_MAX_U32 as u128 <= usize::MAX as u128);
        ix.get_one_based_u32() as usize
    }
}

impl<T: ?Sized> From<Index<T>> for i128 {
    /// An [`i128`] can always be made from a [`Index<T>`].
    #[inline]
    fn from(ix: Index<T>) -> Self {
        ix.get_one_based_u32() as i128
    }
}

impl<T: ?Sized> From<Index<T>> for u128 {
    /// A [`u128`] can always be made from a [`Index<T>`].
    #[inline]
    fn from(ix: Index<T>) -> Self {
        ix.get_one_based_u32() as u128
    }
}

//-------------------------------------------------------------------------------------------------|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use static_assertions::{assert_eq_size, assert_impl_all};

    use super::*;

    #[allow(dead_code)]
    struct Foo;

    #[allow(dead_code)]
    struct Bar;

    type FooIndex = Index<Foo>;
    const FOO_IX_1: FooIndex = FooIndex::one_plus_u16(0);
    const FOO_IX_2: FooIndex = FooIndex::one_plus_u16(1);
    const FOO_IX_3: FooIndex = FooIndex::one_plus_u16(2);
    const FOO_IX_MAX_M2: FooIndex = FooIndex::max_minus_u16(2);
    const FOO_IX_MAX_M1: FooIndex = FooIndex::max_minus_u16(1);
    const FOO_IX_MAX: FooIndex = FooIndex::max_minus_u16(0);

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
    fn iter_range_quantity() {
        assert_eq!(
            FooIndex::iter_range_quantity(0_u8.into()).collect::<Vec<_>>(),
            Vec::<FooIndex>::new()
        );
        assert_eq!(
            FooIndex::iter_range_quantity(1_u8.into()).collect::<Vec<_>>(),
            vec![FOO_IX_1]
        );
        assert_eq!(
            FooIndex::iter_range_quantity(2_u8.into()).collect::<Vec<_>>(),
            vec![FOO_IX_1, FOO_IX_2]
        );
        assert_eq!(
            FooIndex::iter_range_quantity(3_u8.into()).collect::<Vec<_>>(),
            vec![FOO_IX_1, FOO_IX_2, FOO_IX_3]
        );
    }

    #[test]
    fn iter_range_inclusive() {
        assert_eq!(
            FooIndex::iter_range_inclusive(FOO_IX_2, FOO_IX_1).collect::<Vec<_>>(),
            Vec::<FooIndex>::new()
        );
        assert_eq!(
            FooIndex::iter_range_inclusive(FOO_IX_1, FOO_IX_1).collect::<Vec<_>>(),
            [FOO_IX_1]
        );
        assert_eq!(
            FooIndex::iter_range_inclusive(FOO_IX_1, FOO_IX_2).collect::<Vec<_>>(),
            [FOO_IX_1, FOO_IX_2]
        );
        assert_eq!(
            FooIndex::iter_range_inclusive(FOO_IX_2, FOO_IX_3).collect::<Vec<_>>(),
            [FOO_IX_2, FOO_IX_3]
        );
        assert_eq!(
            FooIndex::iter_range_inclusive(FOO_IX_1, FOO_IX_3).collect::<Vec<_>>(),
            [FOO_IX_1, FOO_IX_2, FOO_IX_3]
        );
    }

    #[test]
    fn clone() {
        let foo_index1: FooIndex = FooIndex::try_from_one_based_index_u32(1).unwrap();
        #[allow(clippy::clone_on_copy)]
        let foo_index2: FooIndex = foo_index1.clone();
        assert_eq!(
            foo_index1.get_zero_based_usize(),
            foo_index2.get_zero_based_usize()
        );
    }

    #[test]
    fn copy() {
        let foo_index1: FooIndex = FooIndex::try_from_one_based_index_u32(1).unwrap();
        let foo_index2: FooIndex = foo_index1;
        assert_eq!(
            foo_index1.get_zero_based_usize(),
            foo_index2.get_zero_based_usize()
        );
    }

    #[test]
    fn misc() {
        // Verify below lower limit
        assert!(FooIndex::try_from_one_based_index_u32(0).is_err());

        // Verify within lower limit
        let foo_index = FooIndex::try_from_one_based_index_u32(1).unwrap();
        assert_eq!(foo_index.get_one_based_usize(), 1);
        assert_eq!(foo_index.get_zero_based_usize(), 0);

        // Verify within upper limit
        let bar_index = BarIndex::try_from_one_based_index_u32(BarIndex::VALID_MAX_U32).unwrap();

        assert_eq!(bar_index.get_one_based_usize(), BarIndex::VALID_MAX_USIZE);
        assert_eq!(
            bar_index.get_zero_based_usize(),
            FooIndex::VALID_MAX_USIZE - 1
        );

        // Verify above upper limit
        assert!(FooIndex::try_from_one_based_index_u32(FooIndex::VALID_MAX_U32 + 1).is_err());

        // Verify that we can't mix up indices of different kinds.
        // Expected `Index<Foo>`, found `Index<Bar>`
        //let foo_index: FooIndex = bar_index;
    }

    #[rustfmt::skip]
    #[test]
    fn has_successor() {
        assert!(   FOO_IX_1      .has_successor() );
        assert!(   FOO_IX_2      .has_successor() );
        assert!(   FOO_IX_MAX_M1 .has_successor() );
        assert!( ! FOO_IX_MAX    .has_successor() );
    }

    #[rustfmt::skip]
    #[test]
    fn successor() {
        assert_eq!( FOO_IX_1      .successor(),   Some(FOO_IX_2)   );
        assert_eq!( FOO_IX_2      .successor(),   Some(FOO_IX_3)   );
        assert_eq!( FOO_IX_MAX_M1 .successor(),   Some(FOO_IX_MAX) );
        assert_eq!( FOO_IX_MAX    .successor(),   None             );
    }

    #[rustfmt::skip]
    #[test]
    fn has_predecessor() {
        assert!( ! FOO_IX_1      .has_predecessor() );
        assert!(   FOO_IX_2      .has_predecessor() );
        assert!(   FOO_IX_MAX_M1 .has_predecessor() );
        assert!(   FOO_IX_MAX    .has_predecessor() );
    }

    #[rustfmt::skip]
    #[test]
    fn predecessor() {
        assert_eq!( FOO_IX_1      .predecessor(), None                );
        assert_eq!( FOO_IX_2      .predecessor(), Some(FOO_IX_1)      );
        assert_eq!( FOO_IX_MAX_M1 .predecessor(), Some(FOO_IX_MAX_M2) );
        assert_eq!( FOO_IX_MAX    .predecessor(), Some(FOO_IX_MAX_M1) );
    }

    #[rustfmt::skip]
    #[test]
    fn from_zbi_saturating_u32() {
        assert_eq!(FooIndex::from_zero_based_index_saturating_u32_use_with_care( FOO_IX_1      .get_one_based_u32()      - 1), FOO_IX_1      );
        assert_eq!(FooIndex::from_zero_based_index_saturating_u32_use_with_care( FOO_IX_2      .get_one_based_u32()      - 1), FOO_IX_2      );
        assert_eq!(FooIndex::from_zero_based_index_saturating_u32_use_with_care( FOO_IX_MAX_M2 .get_one_based_u32()      - 1), FOO_IX_MAX_M2 );
        assert_eq!(FooIndex::from_zero_based_index_saturating_u32_use_with_care( FOO_IX_MAX_M1 .get_one_based_u32()      - 1), FOO_IX_MAX_M1 );
        assert_eq!(FooIndex::from_zero_based_index_saturating_u32_use_with_care( FOO_IX_MAX    .get_one_based_u32()      - 1), FOO_IX_MAX    );
        assert_eq!(FooIndex::from_zero_based_index_saturating_u32_use_with_care((FOO_IX_MAX    .get_one_based_u32() + 1) - 1), FOO_IX_MAX    );
    }

    #[rustfmt::skip]
    #[test]
    fn from_zbi_saturating() {
        assert_eq!(FooIndex::from_zero_based_index_saturating_use_with_care((FOO_IX_1      .get_one_based_u32() as    u8   ) - 1), FOO_IX_1      );
        assert_eq!(FooIndex::from_zero_based_index_saturating_use_with_care((FOO_IX_2      .get_one_based_u32() as usize   ) - 1), FOO_IX_2      );
        assert_eq!(FooIndex::from_zero_based_index_saturating_use_with_care((FOO_IX_MAX_M2 .get_one_based_u32()            ) - 1), FOO_IX_MAX_M2 );
        assert_eq!(FooIndex::from_zero_based_index_saturating_use_with_care((FOO_IX_MAX_M1 .get_one_based_u32() as   u64   ) - 1), FOO_IX_MAX_M1 );
        assert_eq!(FooIndex::from_zero_based_index_saturating_use_with_care((FOO_IX_MAX    .get_one_based_u32() as   u64   ) - 1), FOO_IX_MAX    );
        assert_eq!(FooIndex::from_zero_based_index_saturating_use_with_care((FOO_IX_MAX    .get_one_based_u32() as u128 + 1) - 1), FOO_IX_MAX    );
    }
}
