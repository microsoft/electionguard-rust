// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

#[cfg(feature = "eg-test-data-generation")]
use rand::Rng;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    errors::{EgError, EgResult},
    index::Index,
    zk::ProofRange,
};

/// Trait for specifying a type that a [`Vec1<T>`] should be indexed by [`Index<IndexType>`].
pub trait HasIndexType {
    type IndexType;
}

/// Marker trait for marking that a [`Vec1<T>`] should be indexed by [`Index<T>`].
pub trait HasIndexTypeMarker {}

impl<T: HasIndexTypeMarker> HasIndexType for T {
    type IndexType = T;
}

/// A `Vec`-like container intended to be used when 1-based indexing is required.
/// It is missing many of the methods of `Vec`, and not intended to be a general-purpose
/// replacement. In particular, the methods that would return slices are not provided, because
/// they are inherently 0-based.
/// Most of the methods that may panic are not provided either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vec1<T>(Vec<T>);

impl<T: HasIndexType> Vec1<T> {
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

    /// Attempt to create a [`Vec1<T>`] from an [`IntoIterator<Item = T>`].
    /// This will fail if the source produces `2^31` or more elements.
    pub fn try_from_into_iterator<I: IntoIterator<Item = T>>(i: I) -> EgResult<Self> {
        Self::try_from(i.into_iter().collect::<Vec<T>>())
    }

    /// Attempt to create a [`Vec1<T>`] from an [`Iterator<Item = T>`].
    /// This will fail if the source produces `2^31` or more elements.
    pub fn try_from_iter<I: Iterator<Item = T>>(i: I) -> EgResult<Self> {
        Self::try_from(i.collect::<Vec<T>>())
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
    pub fn try_push(&mut self, value: T) -> EgResult<()> {
        if Index::<T>::VALID_MAX_USIZE <= self.len() {
            return Err(EgError::CollectionCantGrow);
        }

        self.0.try_reserve(1).map_err(EgError::TryReserveError)?;
        self.0.push(value);
        Ok(())
    }

    /// Pushes an additional element onto the Vec1. It is a precondition that doing so would not exceed
    /// the size of a `Index<T>`.
    pub fn push_unchecked(&mut self, value: T) {
        self.0.push(value);
    }

    /// Attempts to reserve capacity for at least the specified number of additional elements to be
    /// added. Compare to: [`Vec::try_reserve`].
    pub fn try_reserve(&mut self, additional: usize) -> EgResult<()> {
        self.0
            .try_reserve(additional)
            .map_err(EgError::TryReserveError)
    }

    /// Attempts to reserve capacity for exactly the specified number of additional elements to be
    /// added. Compare to: [`Vec::try_reserve_exact`].
    pub fn try_reserve_exact(&mut self, additional: usize) -> EgResult<()> {
        self.0
            .try_reserve_exact(additional)
            .map_err(EgError::TryReserveError)
    }

    /// Returns a ref to a contained element, if one exists at the supplied index.
    /// Compare to: [`slice::get`].
    pub fn get(&self, index: Index<T::IndexType>) -> Option<&T> {
        self.0.get(index.get_zero_based_usize())
    }

    /// Returns a mut ref to a contained element, if one exists at the supplied index.
    /// Compare to: [`slice::get_mut`].
    pub fn get_mut(&mut self, index: Index<T::IndexType>) -> Option<&mut T> {
        self.0.get_mut(index.get_zero_based_usize())
    }

    /// Returns a ref to the underlying `Vec<T>`.
    pub fn as_vec(&self) -> &Vec<T> {
        &self.0
    }

    /// Returns a slice ref `&[T]`.
    pub fn as_slice(&self) -> &[T] {
        self.as_vec().as_slice()
    }

    /// Returns the range of 1-based indices contained.
    /// Due to `std::iter::Step` currently being nightly-only, these are represented as u32.
    ///
    /// Prefer instead [`contains_index()`] to test for existence,
    /// or [`indices()`] for iteration.
    fn indices_rangeinclusive_u32(&self) -> std::ops::RangeInclusive<u32> {
        let n = self.0.len();
        if !Index::<T::IndexType>::VALID_RANGEINCLUSIVE_USIZE.contains(&n) {
            // It should not have been possible to construct a Vec1 with a length that exceeds
            // the valid max.
            assert_eq!(n, 0);
        }
        1..=(n as u32)
    }

    /// Returns `true` if the supplied value is within the range of contained 1-based indices.
    pub fn contains_index<Ix>(&self, index: Ix) -> bool
    where
        Ix: TryInto<Index<T::IndexType>>,
    {
        let Ok(index) = index.try_into() else {
            return false;
        };
        self.indices_rangeinclusive_u32()
            .contains(&index.get_one_based_u32())
    }

    /// Returns an iterator over the 1-based indices of any contained elements.
    pub fn indices(&self) -> impl Iterator<Item = Index<T::IndexType>> {
        self.indices_rangeinclusive_u32()
            .map(Index::<T::IndexType>::from_one_based_index_unchecked)
    }

    /// Returns an iterator over the 1-based indices and `&T` of contained elements.
    pub fn enumerate(&self) -> impl Iterator<Item = (Index<T::IndexType>, &T)> {
        self.0.iter().enumerate().map(|(ix0, ref_t)| {
            // Unwrap() is justified here because we are retrieving these indices directly from a Vec1.
            (
                Index::<T::IndexType>::from_zero_based_index_unchecked(ix0),
                ref_t,
            )
        })
    }

    /// Returns an iterator over the 1-based indices and `&mut T` of contained elements.
    pub fn enumerate_mut(&mut self) -> impl Iterator<Item = (Index<T::IndexType>, &mut T)> {
        self.0.iter_mut().enumerate().map(|(ix0, mutref_t)| {
            // Unwrap() is justified here because we are retrieving these indices directly from a Vec1.
            (
                Index::<T::IndexType>::from_zero_based_index_unchecked(ix0),
                mutref_t,
            )
        })
    }

    /// Returns an iterator over refs to any contained elements.
    /// Compare to: [`slice::iter`].
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    /// Returns the index of a randomly selected element, or `None` if the collection is empty.
    #[cfg(feature = "eg-test-data-generation")]
    pub fn random_index<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<Index<T::IndexType>> {
        match self.len() {
            0 => None,
            1 => Some(Index::<T::IndexType>::one()),
            _ => {
                let ix_u32 = rng.gen_range(self.indices_rangeinclusive_u32());
                Some(Index::<T::IndexType>::from_one_based_index_unchecked(
                    ix_u32,
                ))
            }
        }
    }
}

impl<T: HasIndexType> Default for Vec1<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> IntoIterator for Vec1<T> {
    type Item = T;

    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Attempt to create a [`Vec1<T>`] from a [`Vec<T>`].
/// This will fail if the source has 2^31 or more elements.
impl<T: HasIndexType> TryFrom<Vec<T>> for Vec1<T> {
    type Error = EgError;
    fn try_from(v: Vec<T>) -> EgResult<Self> {
        if Index::<T>::VALID_MAX_USIZE < v.len() {
            return Err(EgError::CollectionTooLarge(v.len()));
        }
        Ok(Self(v))
    }
}

/// Attempt to create a [`Vec1<T>`] from a [`&[T]`].
/// This will fail if the source has 2^31 or more elements.
impl<T: HasIndexType + Clone + Sized> TryFrom<&[T]> for Vec1<T> {
    type Error = EgError;
    fn try_from(slice: &[T]) -> EgResult<Self> {
        Vec::<T>::from(slice).try_into()
    }
}

/// Attempt to create a [`Vec1<T>`] from a fixed-length array `[T; N]`.
/// This will fail if the array has 2^31 or more elements.
///
/// It is hoped that someday Rust's const generics feature will have improved to
/// the point that we can prove this at compile time, and implement [`From`] instead.
impl<T: HasIndexType, const N: usize> TryFrom<[T; N]> for Vec1<T> {
    type Error = EgError;
    fn try_from(arr: [T; N]) -> EgResult<Self> {
        Vec::<T>::from(arr).try_into()
    }
}

impl<T: HasIndexType> Serialize for Vec1<T>
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

impl<'de, T: HasIndexType> Deserialize<'de> for Vec1<T>
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

impl HasIndexTypeMarker for Vec1<ProofRange> {}

//-------------------------------------------------------------------------------------------------|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test_vec1 {
    use super::*;

    type CharIndex = Index<char>;
    impl HasIndexTypeMarker for char {}

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
