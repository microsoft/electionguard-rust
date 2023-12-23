// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::collections::TryReserveError;

use anyhow::{ensure, Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::index::Index;

/// A `Vec`-like container intended to be used when 1-based indexing is required.
/// It is missing many of the methods of `std::vec::Vec`, and not intended to be a general-purpose
/// replacement. In particular, the methods that would return slices are not provided, because
/// they are inherently 0-based.
/// Most of the methods that may panic are not provided either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vec1<T>(Vec<T>);

impl<T> Vec1<T> {
    // error[E0658]: inherent associated types are unstable
    // see issue #8995 <https://github.com/rust-lang/rust/issues/8995> for more information
    //pub type IndexType = Index<K>;

    /// Creates a new, empty `Vec1<T>`.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Creates a new, empty `Vec1<T>` with the specified capacity.
    pub fn with_capacity(c: usize) -> Self {
        Self(Vec::with_capacity(c))
    }

    /// Removes all contained elements. Compare to: [`Vec::clear`].
    pub fn clear(&mut self) {
        self.0.clear()
    }

    /// Returns the current allocated capacity. Compare to: [`Vec::capacity`].
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Returns the number of elements in the collection. Compare to: [`Vec::len`].
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the number of elements is zero. Compare to: [`Vec::is_empty`].
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Removes and returns the last element, if any. Compare to: [`Vec::pop`].
    pub fn pop(&mut self) -> Option<T> {
        self.0.pop()
    }

    /// Compare to: [`Vec::shrink_to_fit`].
    pub fn shrink_to_fit(&mut self) {
        self.0.shrink_to_fit()
    }

    /// Compare to: [`Vec::shrink_to`].
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.0.shrink_to(min_capacity)
    }

    /// Removes elements from the end of the vector as necessary to reach the specified len. Compare to: [`Vec::truncate`].
    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }

    /// Pushes an additional element onto the end of the Vec1, unless
    /// doing so would exceed the size of a `Index<T>`.
    /// Compare to: [`Vec::push`].
    pub fn try_push(&mut self, value: T) -> Result<()> {
        ensure!(self.len() < Index::<T>::VALID_MAX_USIZE, "Vec1 is full");

        self.0.try_reserve(1)?;
        self.0.push(value);
        Ok(())
    }

    /// Attempts to reserve capacity for at least the specified number of additional elements to be
    /// added. Compare to: [`Vec::try_reserve`].
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.0.try_reserve(additional)
    }

    /// Attempts to reserve capacity for exactly the specified number of additional elements to be
    /// added. Compare to: [`Vec::try_reserve_exact`].
    pub fn try_reserve_exact(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.0.try_reserve_exact(additional)
    }

    /// Returns a ref to a contained element, if one exists at the supplied index.
    /// Compare to: [`slice::get`].
    pub fn get(&self, index: Index<T>) -> Option<&T> {
        self.0.get(index.get_zero_based_usize())
    }

    /// Returns a mut ref to a contained element, if one exists at the supplied index.
    /// Compare to: [`slice::get_mut`].
    pub fn get_mut(&mut self, index: Index<T>) -> Option<&mut T> {
        self.0.get_mut(index.get_zero_based_usize())
    }

    /// Returns an iterator over the 1-based indices of any contained elements.
    #[allow(clippy::reversed_empty_ranges)]
    pub fn indices(&self) -> impl Iterator<Item = Index<T>> {
        let n = self.0.len();
        let ri = if Index::<T>::VALID_RANGEINCLUSIVE_USIZE.contains(&n) {
            // Iterate 1 through n.
            1u32..=(n as u32)
        } else {
            // It should not have been possible to construct a Vec1 with a length that exceeds
            // the valid max.
            assert!(n <= Index::<T>::VALID_MAX_USIZE);

            // Empty range, no iteration.
            1u32..=0
        };

        ri.map(|ix1| {
            // `unwrap()` is justified here because `unwrap_or` ensures it is only called when
            // ix1 is known to be in range.
            #[allow(clippy::unwrap_used)]
            Index::from_one_based_index(ix1).unwrap()
        })
    }

    /// Returns an iterator over refs to any contained elements.
    /// Compare to: [`slice::iter`].
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    //todo!(); //? TODO: consider iterator over index value and ref
    //todo!(); //? TODO: consider iterator over index value and mut ref
}

impl<T> Default for Vec1<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

/// Attempt to create a [`Vec1<T>`] from a [`Vec<T>`].
/// This will fail if the source has 2^31 or more elements.
impl<T> std::convert::TryFrom<std::vec::Vec<T>> for Vec1<T> {
    type Error = Error;
    fn try_from(v: std::vec::Vec<T>) -> Result<Self> {
        ensure!(
            v.len() <= Index::<T>::VALID_MAX_USIZE,
            "Source Vec is too large for Vec1"
        );
        Ok(Self(v))
    }
}

/// Attempt to create a [`Vec1<T>`] from a fixed-length array `[T; N]`.
/// This will fail if the array has 2^31 or more elements.
///
/// It is hoped that someday Rust's const generics feature will have improved to
/// the point that we can prove this at compile time, and implement [`From`] instead.
impl<T, const N: usize> std::convert::TryFrom<[T; N]> for Vec1<T> {
    type Error = Error;
    fn try_from(arr: [T; N]) -> Result<Self> {
        let v: std::vec::Vec<T> = arr.into();
        v.try_into()
    }
}

impl<T> Serialize for Vec1<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for Vec1<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let v = Vec::<T>::deserialize(deserializer)?;

        v.try_into().map_err(D::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test_vec1 {
    use super::*;

    type CharIndex = Index<char>;

    #[test]
    fn test() {
        let mut vec1: Vec1<char> = Vec1::new();
        assert_eq!(vec1.len(), 0);

        let mut iter = vec1.indices();
        assert_eq!(iter.next(), None);

        vec1.try_push('a').unwrap();
        assert_eq!(vec1.len(), 1);
        assert_eq!(
            *vec1
                .get(CharIndex::from_one_based_index(1).unwrap())
                .unwrap(),
            'a'
        );
        let mut iter = vec1.indices();
        assert_eq!(
            iter.next(),
            Some(CharIndex::from_one_based_index(1).unwrap())
        );
        assert_eq!(iter.next(), None);

        vec1.try_push('b').unwrap();
        assert_eq!(vec1.len(), 2);
        assert_eq!(
            *vec1
                .get(CharIndex::from_one_based_index(2).unwrap())
                .unwrap(),
            'b'
        );

        let mut iter = vec1.indices();
        assert_eq!(
            iter.next(),
            Some(CharIndex::from_one_based_index(1).unwrap())
        );
        assert_eq!(
            iter.next(),
            Some(CharIndex::from_one_based_index(2).unwrap())
        );
        assert_eq!(iter.next(), None);
    }
}
