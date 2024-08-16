// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]

#[derive(thiserror::Error, Debug)]
pub enum ArrayAsciiError {
    #[error("Supplied byte value is not a non-NUL 7-bit ASCII value")]
    SuppliedNotNonnul7bitAscii,
}

/// Returns `true` iff the supplied byte is a non-NUL 7-bit ASCII value.
/// (i.e., `0x01 <= by < 0x80`).
#[must_use]
#[inline(always)]
pub const fn is_nonnul_7bit_ascii(by: u8) -> bool {
    0x01 <= by && by < 0x80
}

/// Fixed-length array of bytes containing non-NUL 7-bit ASCII values.
/// (i.e., `0x01 <= by < 0x80`).
///
/// This is similar to the built-in `str` type, but it has a size
/// known at compile time, so can be returned directly from functions.
///
/// Compare to [`ASCII code point`](https://infra.spec.whatwg.org/#ascii-code-point)
/// defined by [WHATWG](https://whatwg.org/).
pub struct ArrayAscii<const N: usize>([u8; N]);

impl<const N: usize> ArrayAscii<N> {
    /// Tries to create an `ArrayAscii` from a function taking `usize` array index
    /// and returning `u8`. Returns `Err` if any of the values are not non-NUL 7-bit ASCII.
    ///
    /// Inspired by `std::array::from_fn`.
    #[inline(always)]
    pub fn try_from_fn<F>(f: F) -> Result<Self, ArrayAsciiError>
    where
        F: FnMut(usize) -> u8,
    {
        let arr = std::array::from_fn(f);

        if arr.iter().copied().all(is_nonnul_7bit_ascii) {
            Ok(Self(arr))
        } else {
            Err(ArrayAsciiError::SuppliedNotNonnul7bitAscii)
        }
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
    #[must_use]
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        if cfg!(feature = "eg-allow-unsafe-code") {
            unsafe {
                // `from_utf8_unchecked()` is justified here because we took pains to ensure
                // all values are non-NUL 7-bit ASCII values.
                std::str::from_utf8_unchecked(&self.0)
            }
        } else {
            // `unwrap()` is justified here because we took pains to ensure
            // all values are non-NUL 7-bit ASCII values.
            #[allow(clippy::unwrap_used)]
            std::str::from_utf8(&self.0).unwrap()
        }
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
