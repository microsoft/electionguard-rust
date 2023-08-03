// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

#[must_use]
#[inline(always)]
pub const fn is_nonnul_7bit_ascii(by: u8) -> bool {
    0x01 <= by && by < 0x80
}

/// Fixed-length array of bytes containing non-NUL 7-bit ASCII values.
/// (i.e., `1 <= b < 128`).
/// This is similar to the built-in `str` type, but it has a size
/// known at compile-time, so can be returned directly from functions.
///
/// Compare to [`ASCII code point`](https://infra.spec.whatwg.org/#ascii-code-point)
/// defined by [WHATWG](https://whatwg.org/).
pub struct ArrayAscii<const N: usize>([u8; N]);

impl<const N: usize> ArrayAscii<N> {
    /// Creates a new `ArrayAscii` from a function taking `usize` array index
    /// and returning `u8`.
    /// Note: when debug assertions are turned off (`--release` profile),
    /// it may be possible to create an `ArrayAscii` with non-ASCII values,
    /// or even invalid UTF-8.
    /// Inspired by `std::array::from_fn`.
    #[must_use]
    #[inline(always)]
    pub fn from_fn<F>(f: F) -> Self
    where
        F: FnMut(usize) -> u8,
    {
        let aa = Self(std::array::from_fn(f));

        debug_assert!(aa.0.iter().copied().all(is_nonnul_7bit_ascii));

        aa
    }

    /// Provides the length of an instance of `ArrayAscii`.
    #[must_use]
    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns `true` iff the instance of `ArrayAscii` has 0 elements.
    /// This exists to make clippy happy:
    /// <https://rust-lang.github.io/rust-clippy/master/index.html#/len_without_is_empty>
    #[must_use]
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Provides access to the `ArrayAscii` as a sized array of bytes.
    #[must_use]
    #[inline(always)]
    pub const fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    /// Provides access to the `ArrayAscii` as a sized array of bytes.
    #[must_use]
    #[inline(always)]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Provides access to the `ArrayAscii` as a byte slice.
    #[must_use]
    #[inline(always)]
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Provides access to the `ArrayAscii` as a `&str`.
    /// May panic if the `ArrayAscii` contains invalid UTF-8.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        #[cfg(eg_allow_unsafe)]
        unsafe {
            std::str::from_utf8_unchecked(&self.0)
        }

        // `unwrap()` is justified here because we took pains to ensure
        // all values are non-NUL 7-bit ASCII values.
        #[allow(clippy::unwrap_used)]
        #[cfg(not(eg_allow_unsafe))]
        std::str::from_utf8(&self.0).unwrap()
    }
}

impl<const N: usize> TryFrom<[u8; N]> for ArrayAscii<N> {
    type Error = &'static str;

    /// Attempts to convert a sized array of bytes into an `ArrayAscii`.
    /// Returns an error if any of the bytes are not non-NUL 7-bit ASCII.
    fn try_from(arr: [u8; N]) -> Result<Self, Self::Error> {
        if arr.iter().copied().all(is_nonnul_7bit_ascii) {
            Ok(Self(arr))
        } else {
            Err("ArrayAscii only accepts values 0x01..0x80.")
        }
    }
}

impl<const N: usize> From<ArrayAscii<N>> for [u8; N] {
    /// Converts an `ArrayAscii` to a sized array of bytes.
    #[must_use]
    #[inline(always)]
    fn from(aa: ArrayAscii<N>) -> Self {
        aa.0
    }
}
