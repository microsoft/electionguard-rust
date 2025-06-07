// Copyright (C) Microsoft Corporation. All rights reserved.
//     MIT License
//
//    Copyright (c) Microsoft Corporation.
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::ops::RangeInclusive;

use static_assertions::{assert_cfg, assert_impl_all, assert_obj_safe, const_assert};

use crate::{
    error::{Error, Result},
    imp::sym_set::SymSet,
};

//=================================================================================================|

/// The representation type for [`Sym`] as a zero-based ordinal.
pub type Sym_ReprType = u16;

/// A symbol. Currently limited to one or two lowercase letters `[a-z]{1,2}`.
#[derive(Copy, Clone, Hash, PartialEq, Ord, Eq, PartialOrd)]
pub struct Sym(Sym_ReprType);

impl Sym {
    /// The total number of values.
    pub(crate) const CNT_TOTAL_VALUES: usize = 27 * 26;

    /// The minimum zero-based ordinal.
    pub(crate) const ZBO_MIN: Sym_ReprType = 0;

    /// The maximum zero-based ordinal.
    pub(crate) const ZBO_MAX: Sym_ReprType = (Self::CNT_TOTAL_VALUES - 1) as Sym_ReprType;

    /// The inclusive range of the zero-based ordinal.
    pub(crate) const ZBO_RANGEINCLUSIVE: RangeInclusive<Sym_ReprType> =
        Self::ZBO_MIN..=Self::ZBO_MAX;

    /// The inclusive range of the zero-based ordinal.
    pub(crate) fn is_valid_zbo<T>(val: T) -> bool
    where
        T: TryInto<Sym_ReprType>,
    {
        #[allow(clippy::manual_range_contains, clippy::absurd_extreme_comparisons)]
        if let Ok(repr) = TryInto::<Sym_ReprType>::try_into(val) {
            Self::ZBO_MIN <= repr && repr <= Self::ZBO_MAX
        } else {
            false
        }
    }

    pub(crate) const fn zbo_rangeinclusive() -> RangeInclusive<Sym_ReprType> {
        Self::ZBO_RANGEINCLUSIVE
    }

    //pub const fn cnt_total_values() -> usize {
    //    Self::CNT_TOTAL_VALUES
    //}

    //pub(crate) fn all_zbos() -> impl Iterator<Item = Sym_ReprType> {
    //    Self::ZBO_RANGEINCLUSIVE
    //}

    pub fn all_values() -> impl Iterator<Item = Sym> {
        Self::ZBO_RANGEINCLUSIVE.map(Self::from_zbo_be_careful)
    }

    #[allow(clippy::unwrap_used)]
    pub(crate) fn zbo_to_string_unwrap(zbo: Sym_ReprType) -> String {
        Self::zbo_tryinto_string(zbo).unwrap()
    }

    //#[allow(clippy::manual_range_contains)]
    fn zbo_tryinto_string(zbo: Sym_ReprType) -> Option<String> {
        match zbo {
            a @ 0..26 => {
                let mut ach: [char; 1] = [intou32_to_radix26_char_be_careful(a)];
                Some(ach.iter().collect())
            }
            a @ 26..=Self::ZBO_MAX => {
                let (b, c) = (a / 26, a % 26);
                assert!((1..=26).contains(&b)); // first char of multiple is radix 27
                let b = b - 1;
                let mut ach: [char; 2] = [
                    intou32_to_radix26_char_be_careful(b),
                    intou32_to_radix26_char_be_careful(c),
                ];
                Some(ach.iter().collect())
            }
            _ => None,
        }
    }

    #[allow(clippy::absurd_extreme_comparisons)]
    pub(crate) const fn from_zbo_unwrap(repr: Sym_ReprType) -> Self {
        assert!(Self::ZBO_MIN <= repr && repr <= Self::ZBO_MAX);
        Self(repr)
    }

    #[allow(clippy::absurd_extreme_comparisons)]
    pub(crate) const fn from_zbo_be_careful(zbo: Sym_ReprType) -> Self {
        debug_assert!(Self::ZBO_MIN <= zbo && zbo <= Self::ZBO_MAX);
        Self(zbo)
    }

    #[allow(clippy::absurd_extreme_comparisons)]
    const fn try_from_zbo(zbo: Sym_ReprType) -> Option<Self> {
        if Self::ZBO_MIN <= zbo && zbo <= Self::ZBO_MAX {
            Some(Self(zbo))
        } else {
            None
        }
    }

    pub(crate) fn try_from_tryinto_repr_zbo<T>(val: T) -> Option<Self>
    where
        T: TryInto<Sym_ReprType>,
    {
        TryInto::<Sym_ReprType>::try_into(val)
            .ok()
            .and_then(Self::try_from_zbo)
    }

    #[inline]
    pub(crate) const fn into_zbo(self) -> Sym_ReprType {
        self.0
    }

    pub fn predecessor(&self) -> Option<Self> {
        (Self::ZBO_MIN < self.0).then(|| Self::from_zbo_be_careful(self.0 - 1))
    }

    pub fn successor(&self) -> Option<Self> {
        (self.0 < Self::ZBO_MAX).then(|| Self::from_zbo_be_careful(self.0 + 1))
    }
}

const_assert!(Sym::CNT_TOTAL_VALUES as u64 - 1 <= Sym_ReprType::MAX as u64);
//-------------------------------------------------------------------------------------------------|
impl std::fmt::Debug for Sym {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for Sym {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write;
        f.write_str(&Self::zbo_to_string_unwrap(self.0))
    }
}
//-------------------------------------------------------------------------------------------------|
impl serde::Serialize for Sym {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Sym {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct SymVisitor;
        impl serde::de::Visitor<'_> for SymVisitor {
            type Value = Sym;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A Sym is one or two lowercase letters")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Sym, E> {
                value.parse::<Sym>()
                    .map_err(|_e| serde::de::Error::custom("not a valid Sym"))
            }
        }
        deserializer.deserialize_any(SymVisitor)
    }
}
//-------------------------------------------------------------------------------------------------|
impl arbitrary::Arbitrary<'_> for Sym {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let zbo: Sym_ReprType = u.int_in_range(Self::ZBO_RANGEINCLUSIVE)?;
        let ss = Self::from_zbo_be_careful(zbo);
        Ok(ss)
    }
}

impl proptest::arbitrary::Arbitrary for Sym {
    type Parameters = ();
    /*
    type Strategy =
        proptest::strategy::Map<proptest::char::CharStrategy<'static>, fn(char) -> Self>;
    fn arbitrary_with(_top: Self::Parameters) -> Self::Strategy {
        let prop_char_range = proptest::char::range('a', 'z');
        proptest::strategy::Strategy::prop_map(prop_char_range, |ch| Sym::unwrap_from_ascii_u8(ch as u8))
    }
    // */
    type Strategy = proptest_arbitrary_interop::ArbStrategy<Self>;
    fn arbitrary_with(_top: Self::Parameters) -> Self::Strategy {
        proptest_arbitrary_interop::arb()
    }
}
//-------------------------------------------------------------------------------------------------|
impl std::str::FromStr for Sym {
    type Err = Error;

    /// Attempts to parse a string `s` to return a [`Sym`].
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut repr: Sym_ReprType = 0;
        let mut have_at_least_one_char = false;
        for (digit_ix, ch) in s.chars().enumerate() {
            let radix26 = (ch as u32).wrapping_sub('a' as u32);
            if 26 <= radix26 {
                return Err(Error::ParseSym);
            } else {
                have_at_least_one_char = true;
            }

            // Surprising: if there are multiple digits, the first digit is actually radix-27,
            // because we don't allow leading '0's, so 'a-z' represent '1-26'.
            if digit_ix == 1 {
                repr += 1;
            }

            repr = repr.checked_mul(26).ok_or(Error::ParseSym)?;
            repr = repr
                .checked_add(radix26 as Sym_ReprType)
                .ok_or(Error::ParseSym)?;
        }

        if !have_at_least_one_char {
            return Err(Error::ParseSym);
        }

        Self::try_from_zbo(repr).ok_or(Error::ParseSym)
    }
}
//-------------------------------------------------------------------------------------------------|
impl<T: Into<SymSet>> std::ops::BitAnd<T> for Sym {
    type Output = SymSet;

    #[inline]
    fn bitand(self, rhs: T) -> Self::Output {
        SymSet::from(self) & rhs
    }
}
//-------------------------------------------------------------------------------------------------|
impl<T: Into<SymSet>> std::ops::BitOr<T> for Sym {
    type Output = SymSet;

    #[inline]
    fn bitor(self, rhs: T) -> Self::Output {
        SymSet::from(self) | rhs
    }
}
//-------------------------------------------------------------------------------------------------|
fn tryinto_radix26_char<T: TryInto<u32>>(u: T) -> Option<char> {
    if let Ok(u) = TryInto::<u32>::try_into(u) {
        if u < 26 {
            return Some(u32_to_radix26_char_be_careful(u));
        }
    }
    None
}
//-------------------------------------------------------------------------------------------------|
fn intou32_to_radix26_char_be_careful<T: Into<u32>>(u: T) -> char {
    let u: u32 = u.into();
    u32_to_radix26_char_be_careful(u)
}
//-------------------------------------------------------------------------------------------------|
fn u32_to_radix26_char_be_careful(u: u32) -> char {
    debug_assert!(u < 26);
    char::from(('a' as u32 + u) as u8)
}
//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    //use anyhow::{anyhow, bail, ensure, Context, Result};
    //?use insta::assert_ron_snapshot;
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;

    use super::*;

    // [`Sym`] tests
    proptest! {
        #[test]
        fn sym_valid_val(s in "[a-z]") {
            let sym: Sym = s.parse().unwrap();
            prop_assert_eq!(sym.to_string(), s);
        }

        #[test]
        fn sym_invalid_val(s in "[^a-z]") {
            prop_assert!(s.parse::<Sym>().is_err());
        }

        #[test]
        fn sym_arbitrary(sym: Sym) {
            prop_assert!(Sym::all_values().any(|s| s == sym));
            let str2 = sym.to_string();
            let sym2: Sym = str2.parse().unwrap();
            prop_assert_eq!(sym, sym2);
            let str3 = sym2.to_string();
            prop_assert_eq!(str3, str2);
        }
    }
}
