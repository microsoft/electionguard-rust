// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(non_camel_case_types)] //? TODO remove?
#![allow(non_snake_case)] //? TODO remove?
#![allow(dead_code)] //? TODO remove
#![allow(unused_imports)] //? TODO remove

#[cfg(test)]
mod test;

custom_error::custom_error! {
    #[derive(PartialEq, Eq)]
    pub NanoVecError
    Full = "Container is full",
    Empty = "Container is empty",
    SourceTooLarge = "Source array has too many elements",
}

/// A very small contiguous container. Like `Vec`, but with a fixed capacity and a design
/// policy that forbids operations that could `panic`, like `[indexing]`.
/// 
/// As many `const` operations are available as is practical with the current stable toolchain.
///
/// `T` is the element type.
///
/// Internal storage is simply an array of `[Option<T>; CAPACITY]`. This implies that:
///
/// 1. Most operations such as `len()`, `push()`, and `pop()` are O(N) or O(`CAPACITY`).
///
/// 2. The best types to use for `T` are those for which `size_of<Option<T>> == size_of<T>`.
/// Some examples are `std::ptr::NonNull` and the `std::num::NonZero*` family of types.
/// These types have the rustc built-in attribute `#[rustc_nonnull_optimization_guaranteed]`.
/// Unfortunately, this attribute "will never be stable", so you'll need to convert your own
/// types to and from these basic types manually.
///
/// Since this is the primary use of this type, a const method `is_compact()` is provided
/// if you wish to verify that is the case.
/// 
/// Compared to [arrayvec::ArrayVec](https://crates.io/crates/arrayvec)
/// and [tinyvec::ArrayVec](https://crates.io/crates/tinyvec), `NanoVec` does not
/// store an additional length data member for length or support reallocation.
///
#[derive(Clone, Copy)]
pub struct NanoVec<T, const CAPACITY: usize>([Option<T>; CAPACITY]);

impl<T, const CAPACITY: usize> NanoVec<T, CAPACITY> {
    /// The maximum number of elements the container can store.
    /// This value is fixed, no reallocation is allowed.
    pub const CAPACITY: usize = CAPACITY;

    /// An instance of the empty container.
    pub const DEFAULT: Self = Self([Self::OPTION_T_NONE; CAPACITY]);
    const OPTION_T_NONE: Option<T> = None;

    /// Returns true iff no space is wasted over a simple array of `[T; CAPACITY]`.
    /// ```
    /// # use static_assertions::const_assert;
    /// # use std::num::NonZeroU8;
    /// # use nano_vec::NanoVec;
    /// const_assert!( ! NanoVec::<       u8, 1>::is_compact() );
    /// const_assert!(   NanoVec::<NonZeroU8, 1>::is_compact() );
    /// ```
    #[must_use]
    #[inline]
    pub const fn is_compact() -> bool {
        std::mem::size_of::<[Option<T>; CAPACITY]>() <= std::mem::size_of::<[T; CAPACITY]>()
    }

    /// The maximum number of elements the container can store.
    /// This value is fixed, no reallocation is allowed.
    #[must_use]
    #[inline]
    pub const fn capacity() -> usize {
        CAPACITY
    }

    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self::DEFAULT
    }

    /// Returns an `Option<&T>` possibly referring to the element at the specified index.
    #[inline]
    pub const fn opt_ref_at(&self, ix: usize) -> Option<&T> {
        if ix < Self::CAPACITY {
            self.0[ix].as_ref()
        } else {
            None
        }
    }

    /// Returns an `Option<&mut T>` possibly referring to the element at the specified
    /// index.
    #[inline]
    pub fn opt_mut_at(&mut self, ix: usize) -> Option<&mut T> {
        if ix < Self::CAPACITY {
            self.0[ix].as_mut()
        } else {
            None
        }
    }

    pub fn push(&mut self, t: T) -> Result<(), NanoVecError> {
        for refmut_opt_t in self.0.iter_mut() {
            if refmut_opt_t.is_none() {
                refmut_opt_t.replace(t);
                return Ok(());
            }
        }
        Err(NanoVecError::Full)
    }

    pub fn pop(&mut self) -> Result<T, NanoVecError> {
        for refmut_opt_t in self.0.iter_mut().rev() {
            if refmut_opt_t.is_some() {
                return Ok(refmut_opt_t.take().unwrap());
            }
        }
        Err(NanoVecError::Empty)
    }

    /// Returns the length of the stored sequence.
    ///
    /// # Examples
    ///
    /// ```
    /// # use static_assertions::const_assert_eq;
    /// # use std::num::NonZeroU8;
    /// # use nano_vec::NanoVec;
    /// const_assert_eq!(NanoVec::<NonZeroU8, 5>::new().len(), 0);
    /// assert_eq!(NanoVec::<u8, 5>::try_from_array([0, 1])?.len(), 2);
    /// assert_eq!(NanoVec::<u8, 5>::try_from_iter(0..3)?.len(), 3);
    /// # Ok::<(), nano_vec::NanoVecError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        // error[E0015]: cannot call non-const fn `<Filter<std::slice::Iter<'_, Option<T>>, [closure@nano-vec\src\lib.rs:148:30: 148:37]> as Iterator>::count` in constant functions
        //self.0.iter().filter(|opt_t| opt_t.is_some()).count()

        // error[E0658]: `for` is not allowed in a `const fn` https://github.com/rust-lang/rust/issues/87575

        let mut ix = 0usize;
        loop {
            if ix == Self::CAPACITY || self.0[ix].is_none() {
                return ix;
            }
            ix += 1;
        }
    }

    /// Shortens the the stored sequence.
    /// Has no effect if `resulting_len` is greater than or equal to the current length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use static_assertions::const_assert_eq;
    /// # use std::num::NonZeroU8;
    /// # use nano_vec::NanoVec;
    /// let mut nv = NanoVec::<u8, 10>::try_from_iter(0..10)?;
    /// assert_eq!(nv.len(), 10);
    /// nv.truncate(5);
    /// assert_eq!(nv.len(), 5);
    /// # Ok::<(), nano_vec::NanoVecError>(())
    /// ```
    pub fn truncate(&mut self, resulting_len: usize) {
        for opt_elem in self.0.iter_mut().skip(resulting_len) {
            if opt_elem.is_some() {
                *opt_elem = None;
            } else {
                break;
            }
        }
    }

    /// Attempt to convert an array of `S` into a `NanoVec<T, _>` of equal or greater capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use nano_vec::NanoVec;
    /// const S: [u8; 1] = [1];
    ///
    /// let nv = NanoVec::<u8, 4>::try_from_array(S)?;
    /// assert_eq!(nv.len(), S.len());
    /// assert_eq!(nv.opt_ref_at(0).copied(), Some(S[0]));
    /// assert_eq!(nv.opt_ref_at(1), None);
    /// # Ok::<(), nano_vec::NanoVecError>(())
    /// ```
    pub fn try_from_array<S, const N: usize>(s: [S; N]) -> Result<Self, NanoVecError>
    where
        S: Into<T>,
    {
        // error[E0015]: cannot call non-const fn `<[S; N] as IntoIterator>::into_iter` in constant functions
        Self::try_from_iter(s.into_iter())
    }

    /// Attempt to construct a `NanoVec<T, ...>` from an `Iterator` of `S`.
    /// This fails if the `Iterator` produces more elements than `CAPACITY`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use nano_vec::NanoVec;
    /// let sequence = "OK".chars();
    /// let nv = NanoVec::<char, 4>::try_from_iter(sequence)?;
    /// assert_eq!(nv.opt_ref_at(0).copied(), Some('O'));
    /// assert_eq!(nv.opt_ref_at(1).copied(), Some('K'));
    /// assert_eq!(nv.opt_ref_at(2), None);
    /// # Ok::<(), nano_vec::NanoVecError>(())
    /// ```
    pub fn try_from_iter<S, IIS>(ii: IIS) -> Result<Self, NanoVecError>
    where
        IIS: IntoIterator<Item = S>,
        S: Into<T>,
    {
        // Can't yet do const, because:
        // error[E0493]: destructor of `<IIS as IntoIterator>::IntoIter` cannot be evaluated at compile-time

        // #![feature(array_into_iter_constructors)] https://github.com/rust-lang/rust/issues/91583

        let mut iter = ii.into_iter();

        let mut end_reached = false;
        let a = std::array::from_fn(|_ix| {
            if !end_reached {
                if let Some(s) = iter.next() {
                    Some(Into::<T>::into(s))
                } else {
                    end_reached = true;
                    None
                }
            } else {
                None
            }
        });

        if !end_reached && iter.next().is_some() {
            Err(NanoVecError::SourceTooLarge)
        } else {
            Ok(Self(a))
        }
    }

    //? TODO pub fn push_within_capacity(&mut self, value: T) -> Result<(), T>
    //? TODO pub fn insert(&mut self, index: usize, element: T)
    //? TODO pub fn remove(&mut self, index: usize) -> T
    //? TODO retain?
    //? TODO retain_mut?
    //? TODO dedup_by_key?
    //? TODO dedup_by?
    //? TODO pub fn clear(&mut self)
    //? TODO pub fn iter(&self) -> Iter<'_, T>
    //? TODO pub fn iter_mut(&mut self) -> IterMut<'_, T>
    //? TODO pub fn as_mut(&mut self) -> Option<&mut T>
}