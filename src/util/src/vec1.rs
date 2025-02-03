// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

#[cfg(feature = "eg-allow-test-data-generation")]
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::index::{Index, IndexError};

/// Trait for specifying the type that a [`Vec1<T>`] should be indexed by [`Index<IndexTypeParam>`].
/// Typically this will be `T`, but sometimes multiple types will prefer to share an index type.
pub trait HasIndexType {
    type IndexTypeParam;
}

impl<T: HasIndexType + ?Sized> HasIndexType for &T {
    type IndexTypeParam = <T as HasIndexType>::IndexTypeParam;
}

impl<T: HasIndexType + ?Sized> HasIndexType for &mut T {
    type IndexTypeParam = <T as HasIndexType>::IndexTypeParam;
}

impl<T: HasIndexType + ?Sized> HasIndexType for Box<T> {
    type IndexTypeParam = <T as HasIndexType>::IndexTypeParam;
}

impl<T: HasIndexType + ?Sized> HasIndexType for std::rc::Rc<T> {
    type IndexTypeParam = <T as HasIndexType>::IndexTypeParam;
}

impl<T: HasIndexType + ?Sized> HasIndexType for std::sync::Arc<T> {
    type IndexTypeParam = <T as HasIndexType>::IndexTypeParam;
}

/// The [`std::error::Error`] type returned by the `Vec1` type.
#[derive(thiserror::Error, Clone, Debug)]
pub enum Vec1Error {
    #[error(
        "A collection containing `{0}` elements of some kind was provided, which is larger than the limit of `2^31 - 1`."
    )]
    CollectionTooLarge(usize),

    #[error(
        "An attempt was made to grow a collection already containing the maximum `2^31 - 1` elements."
    )]
    CollectionCantGrow,

    #[error("Likely out of memory: {0}")]
    TryReserveError(#[from] std::collections::TryReserveError),

    #[error(transparent)]
    IndexError(#[from] IndexError),

    #[error(transparent)]
    StdConvertInfallible(#[from] std::convert::Infallible),
}

pub type Vec1Result<T> = std::result::Result<T, Vec1Error>;

/// A `Vec`-like container intended to be used when 1-based indexing is required.
/// It is missing many of the methods of `Vec`, and not intended to be a general-purpose
/// replacement. In particular, the methods that would return slices are not provided, because
/// they are inherently 0-based.
/// Most of the methods that may panic are not provided either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vec1<T: HasIndexType>(Vec<T>);

impl<T: HasIndexType> Vec1<T> {
    // error[E0658]: inherent associated types are unstable
    // see issue #8995 <https://github.com/rust-lang/rust/issues/8995> for more information
    //pub type IndexType = Index<<T as HasIndexType>::IndexTypeParam>;

    /// Creates a new, empty `Vec1<T>`.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Creates a new, empty `Vec1<T>` with the specified capacity.
    pub fn with_capacity(c: usize) -> Self {
        Self(Vec::with_capacity(c))
    }

    /// Attempt to create a [`Vec1<T>`] from an [`IntoIterator<Item = S>`],
    /// where S can [`TryInto<T>`](std::convert::TryInto).
    ///
    /// This will fail if any element fails to convert or if the source has
    /// 2^31 or more elements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use util::vec1::{self, Vec1, Vec1Error};
    /// struct Ch(pub char);
    /// impl vec1::HasIndexType for Ch { type IndexTypeParam = Ch; }
    /// impl From<char> for Ch { fn from(c: char) -> Ch { Ch(c) } }
    /// assert_eq!(Vec1::<Ch>::try_from_iter(['a', 'b', 'c'])?.len(), 3);
    /// # Ok::<(), Vec1Error>(())
    /// ```
    #[inline]
    pub fn try_from_iter<S, I: IntoIterator<Item = S>>(i: I) -> Vec1Result<Self>
    where
        S: TryInto<T> + Clone,
        <S as TryInto<T>>::Error: Into<Vec1Error>,
    {
        let mut v: Vec<T> = vec![];
        for elem_s in i {
            let elem_t: T = elem_s.clone().try_into().map_err(Into::<Vec1Error>::into)?;
            v.push(elem_t);
        }
        Self::try_from_vec(v)
    }

    /// Attempt to create a [`Vec1<T>`] from a [`Vec<T>`].
    ///
    /// This will fail if the source has
    /// 2^31 or more elements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use util::vec1::{self, Vec1, Vec1Error};
    /// struct Ch(pub char);
    /// impl vec1::HasIndexType for Ch { type IndexTypeParam = Ch; }
    /// impl From<char> for Ch { fn from(c: char) -> Ch { Ch(c) } }
    /// assert_eq!(Vec1::<Ch>::try_from_vec(vec![Ch('a'), Ch('b'), Ch('c')])?.len(), 3);
    /// # Ok::<(), Vec1Error>(())
    /// ```
    #[inline]
    pub fn try_from_vec(v: Vec<T>) -> Vec1Result<Self> {
        if Index::<T>::VALID_MAX_USIZE < v.len() {
            return Err(Vec1Error::CollectionTooLarge(v.len()));
        }
        Ok(Self(v))
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
    pub fn try_push(&mut self, value: T) -> Vec1Result<()> {
        if Index::<T>::VALID_MAX_USIZE <= self.len() {
            return Err(Vec1Error::CollectionCantGrow);
        }

        self.0.try_reserve(1).map_err(Vec1Error::TryReserveError)?;
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
    pub fn try_reserve(&mut self, additional: usize) -> Vec1Result<()> {
        self.0
            .try_reserve(additional)
            .map_err(Vec1Error::TryReserveError)
    }

    /// Attempts to reserve capacity for exactly the specified number of additional elements to be
    /// added. Compare to: [`Vec::try_reserve_exact`].
    pub fn try_reserve_exact(&mut self, additional: usize) -> Vec1Result<()> {
        self.0
            .try_reserve_exact(additional)
            .map_err(Vec1Error::TryReserveError)
    }

    /// Returns a ref to a contained element, if one exists at the supplied index.
    /// Compare to: [`slice::get`].
    pub fn get(&self, index: Index<T::IndexTypeParam>) -> Option<&T> {
        self.0.get(index.get_zero_based_usize())
    }

    /// Returns a mut ref to a contained element, if one exists at the supplied index.
    /// Compare to: [`slice::get_mut`].
    pub fn get_mut(&mut self, index: Index<T::IndexTypeParam>) -> Option<&mut T> {
        self.0.get_mut(index.get_zero_based_usize())
    }

    /// Returns a ref to a contained element, if one exists at the supplied index.
    /// Otherwise, returns Vec1Error.
    pub fn try_get(&self, index: Index<T::IndexTypeParam>) -> Vec1Result<&T> {
        self.get(index)
            .ok_or(IndexError::IndexOutOfRange(index.into()).into())
    }

    /// Returns a mut ref to a contained element, if one exists at the supplied index.
    /// Otherwise, returns Vec1Error.
    pub fn try_get_mut(&mut self, index: Index<T::IndexTypeParam>) -> Vec1Result<&mut T> {
        self.get_mut(index)
            .ok_or(IndexError::IndexOutOfRange(index.into()).into())
    }

    /// Returns a ref to the underlying `Vec<T>`.
    pub fn as_vec(&self) -> &Vec<T> {
        &self.0
    }

    /// Returns a slice ref `&[T]`.
    pub fn as_slice(&self) -> &[T] {
        self.as_vec().as_slice()
    }

    /// Converts the Vec1 into `Vec<T>`.
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }

    /// Returns a plain array of `&T`, if this `Vec1` contains at least N elements.
    /// If `N < self.len()`, the additional elements are not included.
    ///
    /// Note that the resulting regular array is 0-based indexed.
    pub fn arr_refs<const N: usize>(&self) -> Vec1Result<[&T; N]> {
        let v = self.as_vec();

        if v.len() < N {
            let nn: u32 = { N }.try_into().unwrap_or(u32::MAX - 1).saturating_add(1);
            return Err(IndexError::IndexOutOfRange(nn).into());
        }

        Ok(std::array::from_fn(|ix0| &v[ix0]))
    }

    /// Returns the range of 1-based indices contained.
    /// Due to `std::iter::Step` currently being nightly-only, these are represented as u32.
    ///
    /// Prefer instead [`contains_index()`] to test for existence,
    /// or [`indices()`] for iteration.
    fn indices_rangeinclusive_u32(&self) -> std::ops::RangeInclusive<u32> {
        let n = self.0.len();
        if !Index::<T::IndexTypeParam>::VALID_RANGEINCLUSIVE_USIZE.contains(&n) {
            // It should not have been possible to construct a Vec1 with a length that exceeds
            // the valid max.
            assert_eq!(n, 0);
        }
        1..=(n as u32)
    }

    /// Returns `true` if the supplied value is within the range of contained 1-based indices.
    pub fn contains_index<Ix>(&self, index: Ix) -> bool
    where
        Ix: TryInto<Index<T::IndexTypeParam>>,
    {
        let Ok(index) = index.try_into() else {
            return false;
        };
        self.indices_rangeinclusive_u32()
            .contains(&index.get_one_based_u32())
    }

    /// Returns an iterator over the 1-based indices of any contained elements.
    pub fn indices(&self) -> impl Iterator<Item = Index<T::IndexTypeParam>> {
        self.indices_rangeinclusive_u32()
            .map(Index::<T::IndexTypeParam>::from_one_based_index_unchecked)
    }

    /// Returns an iterator over the 1-based indices and `&T` of contained elements.
    pub fn enumerate(&self) -> impl Iterator<Item = (Index<T::IndexTypeParam>, &T)> {
        self.0.iter().enumerate().map(|(ix0, ref_t)| {
            // Unwrap() is justified here because we are retrieving these indices directly from a Vec1.
            (
                Index::<T::IndexTypeParam>::from_zero_based_index_unchecked_usize(ix0),
                ref_t,
            )
        })
    }

    /// Returns an iterator over the 1-based indices and `&mut T` of contained elements.
    pub fn enumerate_mut(&mut self) -> impl Iterator<Item = (Index<T::IndexTypeParam>, &mut T)> {
        self.0.iter_mut().enumerate().map(|(ix0, mutref_t)| {
            // Unwrap() is justified here because we are retrieving these indices directly from a Vec1.
            (
                Index::<T::IndexTypeParam>::from_zero_based_index_unchecked_usize(ix0),
                mutref_t,
            )
        })
    }

    /// Returns an iterator over refs to any contained elements.
    /// Compare to: [`slice::iter`].
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    /// Returns an iterator over mut refs to any contained elements.
    /// Compare to: [`slice::iter_mut`].
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.iter_mut()
    }

    /// Returns the index of a randomly selected element, or `None` if the collection is empty.
    #[cfg(feature = "eg-allow-test-data-generation")]
    pub fn random_index<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<Index<T::IndexTypeParam>> {
        match self.len() {
            0 => None,
            1 => Some(Index::<T::IndexTypeParam>::one()),
            _ => Some(Index::<T::IndexTypeParam>::from_one_based_index_unchecked(
                rng.random_range(self.indices_rangeinclusive_u32()),
            )),
        }
    }

    /// Builds a new Vec1<U> using the supplied function `&T -> U` on each element.
    pub fn map_into<'u, 's: 'u, F, U>(&'s self, mut f: F) -> Vec1<U>
    where
        U: HasIndexType + 'u,
        F: FnMut(&'s T) -> U,
    {
        let mut v: Vec<U> = Vec::with_capacity(self.len());
        for elem_t in self.0.iter() {
            let elem_u: U = f(elem_t);
            v.push(elem_u);
        }
        Vec1(v)
    }
}

impl<T: HasIndexType> Default for Vec1<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

// /*
impl<T: HasIndexType> TryFrom<Vec<T>> for Vec1<T> {
    type Error = Vec1Error;

    /// Attempt to create a [`Vec1<T>`] from a [`Vec<T>`].
    ///
    /// This will fail if the source has
    /// 2^31 or more elements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use util::vec1::{self, Vec1, Vec1Error};
    /// struct Ch(pub char);
    /// impl vec1::HasIndexType for Ch { type IndexTypeParam = Ch; }
    /// impl From<char> for Ch { fn from(c: char) -> Ch { Ch(c) } }
    /// assert_eq!(Vec1::<Ch>::try_from(vec![Ch('a'), Ch('b'), Ch('c')])?.len(), 3);
    /// # Ok::<(), Vec1Error>(())
    /// ```
    #[inline]
    fn try_from(v: Vec<T>) -> Vec1Result<Self> {
        Self::try_from_vec(v)
    }
}
// */
// /*
impl<T: HasIndexType> IntoIterator for Vec1<T> {
    type Item = T;

    type IntoIter = std::vec::IntoIter<T>;

    /// Converts the ['Vec1<T>'] into an [`Iterator`] over `T`.
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
// */
/*
impl<I, T> TryFrom<I> for Vec1<T>
where
    I: IntoIterator<Item = T>,
    T: HasIndexType,
{
    type Error = Vec1Error;

    /// Attempt to create a [`Vec1<T>`] from an [`IntoIterator<Item = T>`].
    ///
    /// This will fail if the source has
    /// 2^31 or more elements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use util::vec1::{self, Vec1, Vec1Error};
    /// struct Ch(pub char);
    /// impl vec1::HasIndexType for Ch { type IndexTypeParam = Ch; }
    /// impl From<char> for Ch { fn from(c: char) -> Ch { Ch(c) } }
    /// assert_eq!(Vec1::<Ch>::try_from(['a', 'b', 'c'])?.len(), 3);
    /// # Ok::<(), Vec1Error>(())
    /// ```
    #[inline]
    fn try_from(i: I) -> Vec1Result<Self> {
        let v: Vec<T> = i.into_iter().collect();
        //<Self as TryFrom<Vec<T>>>::try_from(v)
        if Index::<T>::VALID_MAX_USIZE < v.len() {
            return Err(Vec1Error::CollectionTooLarge(v.len()));
        }
        Ok(Self(v))
    }
}
// */

/*
impl<I, S, T> TryFrom<I> for Vec1<T>
where
    I: IntoIterator<Item = S>,
    S: TryInto<T> + Clone,
    <S as TryInto<T>>::Error: Into<Vec1Error>,
    T: HasIndexType,
{
    type Error = Vec1Error;

    /// Attempt to create a [`Vec1<T>`] from an [`IntoIterator<Item = S>`],
    /// where S can [`TryInto<T>`](std::convert::TryInto).
    ///
    /// This will fail if any element fails to convert or if the source has
    /// 2^31 or more elements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use util::vec1::{self, Vec1, Vec1Error};
    /// struct Ch(pub char);
    /// impl vec1::HasIndexType for Ch { type IndexTypeParam = Ch; }
    /// impl From<char> for Ch { fn from(c: char) -> Ch { Ch(c) } }
    /// assert_eq!(Vec1::<Ch>::try_from(['a', 'b', 'c'])?.len(), 3);
    /// # Ok::<(), Vec1Error>(())
    /// ```
    #[inline]
    fn try_from(i: I) -> Vec1Result<Self> {
        let mut v: Vec<T> = vec![];
        for elem_s in i {
            let elem_t: T = elem_s.clone().try_into()
                .map_err(Into::<Vec1Error>::into)?;
            v.push(elem_t);
        }
        //<Self as TryFrom<Vec<T>>>::try_from(v)
        if Index::<T>::VALID_MAX_USIZE < v.len() {
            return Err(Vec1Error::CollectionTooLarge(v.len()));
        }
        Ok(Self(v))
    }
}
// */

/*
impl<I, S, T> TryFrom<(I, bool)> for Vec1<T>
where
    I: IntoIterator<Item = S>,
    S: TryInto<T> + Clone,
    <S as TryInto<T>>::Error: Into<Vec1Error>,
    T: HasIndexType,
{
    type Error = Vec1Error;

    /// Attempt to create a [`Vec1<T>`] from an [`IntoIterator<Item = S>`],
    /// where S can [`TryInto<T>`](std::convert::TryInto).
    ///
    /// This will fail if any element fails to convert or if the source has
    /// 2^31 or more elements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use util::vec1::{self, Vec1, Vec1Error};
    /// struct Ch(pub char);
    /// impl vec1::HasIndexType for Ch { type IndexTypeParam = Ch; }
    /// impl From<char> for Ch { fn from(c: char) -> Ch { Ch(c) } }
    /// assert_eq!(Vec1::<Ch>::try_from((['a', 'b', 'c'], false))?.len(), 3);
    /// # Ok::<(), Vec1Error>(())
    /// ```
    #[inline]
    fn try_from((i, _b): (I, bool)) -> Vec1Result<Self> {
        let mut v: Vec<T> = vec![];
        for elem_s in i {
            let elem_t: T = elem_s.clone().try_into()
                .map_err(Into::<Vec1Error>::into)?;
            v.push(elem_t);
        }
        <Self as TryFrom<Vec<T>>>::try_from(v)
    }
}
// */

/*
impl<S, T> TryFrom<&[S]> for Vec1<T>
where
    S: TryInto<T> + Clone,
    <S as TryInto<T>>::Error: Into<Vec1Error>,
    T: HasIndexType,
{
    type Error = Vec1Error;

    /// Attempt to create a [`Vec1<T>`] from a [`&[S]`].
    /// This will fail if any element fails to convert or if the source has
    /// 2^31 or more elements.
    /// # Examples
    ///
    /// ```
    /// # use util::vec1::HasIndexType;
    /// impl HasIndexType for char { type IndexTypeParam = char; }
    /// assert_eq!(Vec1::from(['a', 'b', 'c'].as_slice()).get(2), Some('b'));
    /// ```
    #[inline]
    fn try_from(s: &[S]) -> Vec1Result<Self> {
        if Index::<T>::VALID_MAX_USIZE < s.len() {
            return Err(Vec1Error::CollectionTooLarge(s.len()));
        }
        let mut v = Vec::with_capacity(s.len());
        for elem_s in s {
            let elem_t: T = elem_s.clone().try_into()
                .map_err(Into::<Vec1Error>::into)?;
            v.push(elem_t);
        }
        Ok(Self(v))
    }
}
// */

// /*
impl<S, T, const N: usize> TryFrom<&[S; N]> for Vec1<T>
where
    S: TryInto<T> + Clone,
    <S as TryInto<T>>::Error: Into<Vec1Error>,
    T: HasIndexType,
{
    type Error = Vec1Error;

    /// Attempt to create a [`Vec1<T>`] from a fixed-length array `&[S; N]`.
    /// This will fail if any element fails to convert or if the source array has
    /// 2^31 or more elements.
    /// # Examples
    ///
    /// ```
    /// # use util::vec1::{self, Vec1, Vec1Error};
    /// struct Ch(pub char);
    /// impl vec1::HasIndexType for Ch { type IndexTypeParam = Ch; }
    /// impl From<char> for Ch { fn from(c: char) -> Ch { Ch(c) } }
    /// assert_eq!(Vec1::<Ch>::try_from(&['a', 'b', 'c'])?.len(), 3);
    /// # Ok::<(), Vec1Error>(())
    /// ```
    #[inline]
    fn try_from(arr: &[S; N]) -> Vec1Result<Self> {
        if Index::<T>::VALID_MAX_USIZE < arr.len() {
            return Err(Vec1Error::CollectionTooLarge(arr.len()));
        }
        let mut v = Vec::with_capacity(arr.len());
        for elem_t in arr {
            let elem_u: T = elem_t.clone().try_into().map_err(Into::<Vec1Error>::into)?;
            v.push(elem_u);
        }
        Ok(Self(v))
    }
}

// /*
impl<S, T, const N: usize> TryFrom<&mut [S; N]> for Vec1<T>
where
    S: TryInto<T> + Clone,
    <S as TryInto<T>>::Error: Into<Vec1Error>,
    T: HasIndexType,
{
    type Error = Vec1Error;

    /// Attempt to create a [`Vec1<T>`] from a fixed-length array `&mut [S; N]`.
    /// This will fail if any element fails to convert or if the source array has
    /// 2^31 or more elements.
    /// # Examples
    ///
    /// ```
    /// # use util::vec1::{self, Vec1, Vec1Error};
    /// struct Ch(pub char);
    /// impl vec1::HasIndexType for Ch { type IndexTypeParam = Ch; }
    /// impl From<char> for Ch { fn from(c: char) -> Ch { Ch(c) } }
    /// assert_eq!(Vec1::<Ch>::try_from(&mut ['a', 'b', 'c'])?.len(), 3);
    /// # Ok::<(), Vec1Error>(())
    /// ```
    #[inline]
    fn try_from(arr: &mut [S; N]) -> Vec1Result<Self> {
        if Index::<T>::VALID_MAX_USIZE < arr.len() {
            return Err(Vec1Error::CollectionTooLarge(arr.len()));
        }
        let mut v = Vec::with_capacity(arr.len());
        for elem_t in arr {
            let elem_u: T = elem_t.clone().try_into().map_err(Into::<Vec1Error>::into)?;
            v.push(elem_u);
        }
        Ok(Self(v))
    }
}

// /*
impl<S, T, const N: usize> TryFrom<[S; N]> for Vec1<T>
where
    S: TryInto<T> + Clone,
    <S as TryInto<T>>::Error: Into<Vec1Error>,
    T: HasIndexType,
{
    type Error = Vec1Error;

    /// Attempt to create a [`Vec1<T>`] from a fixed-length array `[S; N]`.
    /// This will fail if any element fails to convert or if the source array has
    /// 2^31 or more elements.
    /// # Examples
    ///
    /// ```
    /// # use util::vec1::{self, Vec1, Vec1Error};
    /// struct Ch(pub char);
    /// impl vec1::HasIndexType for Ch { type IndexTypeParam = Ch; }
    /// impl From<char> for Ch { fn from(c: char) -> Ch { Ch(c) } }
    /// assert_eq!(Vec1::<Ch>::try_from(['a', 'b', 'c'])?.len(), 3);
    /// # Ok::<(), Vec1Error>(())
    /// ```
    #[inline]
    fn try_from(arr: [S; N]) -> Vec1Result<Self> {
        if Index::<T>::VALID_MAX_USIZE < arr.len() {
            return Err(Vec1Error::CollectionTooLarge(arr.len()));
        }
        let mut v = Vec::with_capacity(arr.len());
        for elem_t in arr {
            let elem_u: T = elem_t.try_into().map_err(Into::<Vec1Error>::into)?;
            v.push(elem_u);
        }
        Ok(Self(v))
    }
}

// */
/*
impl<T, U, const N: usize> TryFrom<[T; N]> for Vec1<U>
where
    T: TryInto<U> + ?Sized,
    U: HasIndexType,
{
    type Error = Vec1Error;

    /// Attempt to create a [`Vec1<U>`] from a fixed-length array `[T; N]`.
    /// This will fail if any element fails to convert or if the source array has
    /// 2^31 or more elements.
    #[inline]
    fn try_from(arr: [T; N]) -> Vec1Result<Self> {
        if Index::<U>::VALID_MAX_USIZE < arr.len() {
            return Err(Vec1Error::CollectionTooLarge(arr.len()));
        }
        let mut v = Vec::with_capacity(arr.len());
        for elem_t in arr {
            let elem_u = elem_t.try_into()?
            v.pu
        }
        Ok(Self(v))
        Vec::<T>::from(arr).try_into()
    }
}
// */

impl<T> Serialize for Vec1<T>
where
    T: Serialize + HasIndexType,
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
    T: Deserialize<'de> + HasIndexType,
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

//-------------------------------------------------------------------------------------------------|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test_vec1 {
    use super::*;

    impl HasIndexType for char {
        type IndexTypeParam = char;
    }
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
                .get(CharIndex::try_from_one_based_index_u32(1).unwrap())
                .unwrap(),
            'a'
        );
        let mut iter = vec1.indices();
        assert_eq!(
            iter.next(),
            Some(CharIndex::try_from_one_based_index_u32(1).unwrap())
        );
        assert_eq!(iter.next(), None);

        vec1.try_push('b').unwrap();
        assert_eq!(vec1.len(), 2);
        assert_eq!(
            *vec1
                .get(CharIndex::try_from_one_based_index_u32(2).unwrap())
                .unwrap(),
            'b'
        );

        let mut iter = vec1.indices();
        assert_eq!(
            iter.next(),
            Some(CharIndex::try_from_one_based_index_u32(1).unwrap())
        );
        assert_eq!(
            iter.next(),
            Some(CharIndex::try_from_one_based_index_u32(2).unwrap())
        );
        assert_eq!(iter.next(), None);
    }
}
