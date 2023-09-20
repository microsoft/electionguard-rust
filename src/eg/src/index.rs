// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO remove

use std::collections::TryReserveError;
use std::marker::PhantomData;
use std::ops::RangeInclusive;
use std::{alloc::LayoutError, ffi::c_char};

use anyhow::{anyhow, ensure, Context, Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use static_assertions::{assert_eq_size, assert_impl_all, const_assert};

/// A 1-based ordinal type that enforces a range 1 <= i < 2^31.
///
/// `T` is a tag for disambiguation. It can be any type.
///
/// This type can also be used represent cardinal numbers using the [`.as_quantity()`] method.
pub struct Index<T>(u32, PhantomData<fn(T) -> T>)
where
    T: ?Sized;

// Copy trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T> std::marker::Copy for Index<T> {}

// Clone trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T> std::clone::Clone for Index<T> {
    fn clone(&self) -> Self {
        *self
    }
}

// PartialEq trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T> std::cmp::PartialEq for Index<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// PartialOrd trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T> std::cmp::PartialOrd for Index<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

// Eq trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T> std::cmp::Eq for Index<T> {}

// Ord trait must be implmented manually because of the [`PhantomData`](std::marker::PhantomData).
impl<T> std::cmp::Ord for Index<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

// Verify that on the target platform `usize` is large enough to hold `i32::MAX`.
// If someone needs to target a 16-bit platform with this code, we will have to deal
// with `Vec` index type being too small to represent the spec commitment.
const INDEX_MAX_U32: u32 = (1u32 << 31) - 1;
static_assertions::const_assert!(INDEX_MAX_U32 as u64 <= (usize::MAX as u64));
static_assertions::const_assert!(INDEX_MAX_U32 as usize <= usize::MAX);

impl<T> Index<T> {
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

    pub const fn is_valid_one_based_index(ix1: u32) -> bool {
        // RangeInclusive::<Idx>::contains` is not yet stable as a const fn
        //Self::VALID_RANGEINCLUSIVE_U32.contains(&ix1)
        Self::VALID_MIN_U32 <= ix1 && ix1 <= Self::VALID_MAX_U32
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
    pub fn from_one_based_index(ix1: u32) -> Result<Self> {
        Self::from_one_based_index_const(ix1)
            .ok_or_else(|| anyhow!("Index value {ix1} out of range"))
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

impl<T> std::fmt::Display for Index<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl<T> std::fmt::Debug for Index<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Display::fmt(self, f)
    }
}

impl<T> std::str::FromStr for Index<T> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_one_based_index(s.parse()?)
    }
}

impl<T> Serialize for Index<T> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test_index {
    use super::*;

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
