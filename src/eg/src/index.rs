// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO remove

use std::alloc::LayoutError;
use std::collections::TryReserveError;
use std::marker::PhantomData;
use std::ops::RangeInclusive;

use anyhow::{ensure, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use static_assertions::const_assert;

// We may not actually need Serialize, Deserialize for this type.
pub struct GenericIndex<T>(u32, PhantomData<*const T>);

// Copy trait must be implmented manually because of the PhantomData.
impl<T> std::marker::Copy for GenericIndex<T> {}

// Clone trait must be implmented manually because of the PhantomData.
impl<T> std::clone::Clone for GenericIndex<T> {
    fn clone(&self) -> Self {
        *self
    }
}

// PartialEq trait must be implmented manually because of the PhantomData.
impl<T> std::cmp::PartialEq for GenericIndex<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// PartialOrd trait must be implmented manually because of the PhantomData.
impl<T> std::cmp::PartialOrd for GenericIndex<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

// Eq trait must be implmented manually because of the PhantomData.
impl<T> std::cmp::Eq for GenericIndex<T> {}

// Ord trait must be implmented manually because of the PhantomData.
impl<T> std::cmp::Ord for GenericIndex<T> {
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

impl<T> GenericIndex<T> {
    // Valid ranges of `GenericIndex` values are naturally expressed as u32.
    pub const VALID_MIN_U32: u32 = 1;
    pub const VALID_MAX_U32: u32 = INDEX_MAX_U32;
    pub const VALID_RANGEINCLUSIVE_U32: RangeInclusive<u32> =
        Self::VALID_MIN_U32..=Self::VALID_MAX_U32;

    // Defining ranges as `usize` is useful for code that needs to compare with collection lengths.
    pub const VALID_MIN_USIZE: usize = Self::VALID_MIN_U32 as usize;
    pub const VALID_MAX_USIZE: usize = Self::VALID_MAX_U32 as usize;
    pub const VALID_RANGEINCLUSIVE_USIZE: RangeInclusive<usize> =
        Self::VALID_MIN_USIZE..=Self::VALID_MAX_USIZE;

    pub fn from_one_based_index(ix1: u32) -> Result<Self> {
        ensure!(
            Self::VALID_RANGEINCLUSIVE_U32.contains(&ix1),
            "Index value out of range: {ix1}"
        );

        Ok(Self(ix1, PhantomData))
    }

    /// Obtains the 1-based index value as a usize.
    pub fn get_one_based_usize(&self) -> usize {
        debug_assert!(Self::VALID_RANGEINCLUSIVE_U32.contains(&self.0));

        self.0 as usize
    }

    /// Converts the 1-based index into a 0-based index suitable for indexing into a `std::Vec`.
    pub fn get_zero_based_usize(&self) -> usize {
        self.get_one_based_usize() - 1
    }
}

impl<T> std::fmt::Display for GenericIndex<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl<T> std::fmt::Debug for GenericIndex<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Display::fmt(self, f)
    }
}

impl<T> Serialize for GenericIndex<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for GenericIndex<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let ix1 = u32::deserialize(deserializer)?;

        GenericIndex::from_one_based_index(ix1).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod test_index {
    use super::*;

    #[allow(dead_code)]
    struct Foo;

    #[allow(dead_code)]
    struct Bar;

    type FooIndex = GenericIndex<Foo>;
    type BarIndex = GenericIndex<Bar>;

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
        // Expected `GenericIndex<Foo>`, found `GenericIndex<Bar>`
        //let foo_index: FooIndex = bar_index;
    }
}
