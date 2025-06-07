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
#![allow(clippy::needless_lifetimes)] //? TODO: Remove temp development code
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

use arbitrary::unstructured::ArbitraryIter;
//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use rand::{distr::Uniform, Rng, RngCore};
use smallbitvec::SmallBitVec;
use static_assertions::{assert_cfg, assert_impl_all, assert_obj_safe, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::{Error, Result},
    imp::sym::{Sym, Sym_ReprType},
};

//=================================================================================================|

//pub type SymSet_ReprType = u32;
//const_assert!(Sym::CNT_TOTAL_VALUES <= size_of::<SymSet_ReprType>()*8);

pub type SymSet_ReprType = SmallBitVec;

#[derive(Clone, Default, Hash, PartialEq, Eq)]
pub struct SymSet(SymSet_ReprType);

impl SymSet {
    pub(crate) const SYM_ZBO_RANGEINCLUSIVE: std::ops::RangeInclusive<Sym_ReprType> =
        Sym::ZBO_RANGEINCLUSIVE;

    /*
    pub(crate) const MIN_REPR: SymSet_ReprType = 0;
    pub(crate) const MAX_REPR: SymSet_ReprType = ((1u64 << Sym::CNT_TOTAL_VALUES) - 1) as SymSet_ReprType;
    pub(crate) const RANGEINCLUSIVE_REPR: std::ops::RangeInclusive<SymSet_ReprType> = Self::MIN_REPR..=Self::MAX_REPR;
    // */

    pub const fn new() -> Self {
        Self(SymSet_ReprType::new())
    }

    /*
    const fn from_repr_unchecked(u: SymSet_ReprType) -> Self {
        debug_assert!(u <= Self::MAX_REPR);
        Self(u)
    }

    const fn try_from_repr(u: SymSet_ReprType) -> Option<Self> {
        if u <= Self::MAX_REPR {
            Some(Self(u))
        } else {
            None
        }
    }

    fn try_from_tryinto_repr<T>(val: T) -> Option<Self>
    where
        T: TryInto<SymSet_ReprType> + ?Sized,
    {
        TryInto::<SymSet_ReprType>::try_into(val)
        .ok()
        .and_then(Self::try_from_repr)
    }

    #[inline]
    pub const fn into_repr(self) -> SymSet_ReprType {
        self.0
    }
    // */

    pub fn contains(&self, sym: Sym) -> bool {
        self.contains_sym_by_zbo(sym.into_zbo())
    }

    pub(crate) fn contains_sym_by_zbo(&self, sym_zbo: Sym_ReprType) -> bool {
        self.0.get(sym_zbo as usize).unwrap_or(false)
    }

    pub fn is_empty(&self) -> bool {
        self.0.all_false()
    }

    pub fn len(&self) -> usize {
        self.0.iter().filter(|b| *b).count()
    }

    pub fn contains_all_of(&self, other: &SymSet) -> bool {
        for (ix, other_b) in other.0.iter().enumerate() {
            if other_b {
                let this_b = self.0.get(ix).unwrap_or(false);
                if other_b && !this_b {
                    return false;
                }
            }
        }
        true
    }

    pub fn count_set(&self) -> usize {
        self.0.iter().filter(|b| *b).count()
    }

    #[inline]
    pub fn iter(&self) -> SymSet_Iterator<'_> {
        let cnt_remain = self.count_set();
        SymSet_Iterator {
            sbv: &self.0,
            next_ix: 0,
            cnt_remain,
        }
    }

    fn get_at_zbo(&self, zbo: usize) -> bool {
        self.0.get(zbo).unwrap_or(false)
    }

    fn set_at_zbo(&mut self, zbo: usize) {
        let cur_sbv_len = self.0.len();
        if cur_sbv_len <= zbo {
            if cur_sbv_len < zbo {
                self.0.resize(zbo, false);
            }
            self.0.push(true);
        } else {
            // We just checked the len
            unsafe { self.0.set_unchecked(zbo, true) }
        }
    }
}
//-------------------------------------------------------------------------------------------------|

#[allow(non_camel_case_types)]
pub struct SymSet_Iterator<'a> {
    sbv: &'a SmallBitVec,
    next_ix: usize,
    cnt_remain: usize,
}

impl<'a> Iterator for SymSet_Iterator<'a> {
    type Item = Sym;
    fn next(&mut self) -> Option<Self::Item> {
        while self.cnt_remain != 0 && self.next_ix < self.sbv.len() {
            let this_ix = self.next_ix;
            self.next_ix += 1;
            if unsafe { self.sbv.get_unchecked(this_ix) } {
                debug_assert!(0 < self.cnt_remain);
                self.cnt_remain -= 1;
                return Some(Sym::from_zbo_be_careful(this_ix as Sym_ReprType));
            }
        }
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.cnt_remain, Some(self.cnt_remain))
    }
}

impl<'a> std::iter::ExactSizeIterator for SymSet_Iterator<'a> {}
//-------------------------------------------------------------------------------------------------|
impl IntoIterator for SymSet {
    type Item = Sym;
    type IntoIter = SymSet_IntoIterator;
    fn into_iter(self) -> SymSet_IntoIterator {
        let cnt_remain = self.count_set();
        let Self(sbv) = self;
        SymSet_IntoIterator {
            sbv,
            next_ix: 0,
            cnt_remain,
        }
    }
}

#[allow(non_camel_case_types)]
pub struct SymSet_IntoIterator {
    sbv: SmallBitVec,
    next_ix: usize,
    cnt_remain: usize,
}

impl Iterator for SymSet_IntoIterator {
    type Item = Sym;
    fn next(&mut self) -> Option<Self::Item> {
        while self.cnt_remain != 0 && self.next_ix < self.sbv.len() {
            let this_ix = self.next_ix;
            self.next_ix += 1;
            if unsafe { self.sbv.get_unchecked(this_ix) } {
                debug_assert!(0 < self.cnt_remain);
                self.cnt_remain -= 1;
                return Some(Sym::from_zbo_be_careful(this_ix as Sym_ReprType));
            }
        }
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.cnt_remain, Some(self.cnt_remain))
    }
}

impl std::iter::ExactSizeIterator for SymSet_IntoIterator {}
//-------------------------------------------------------------------------------------------------|
impl std::fmt::Debug for SymSet {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for SymSet {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write;
        f.write_char('{')?;
        let mut sym_iter = self.iter();
        if let Some(sym) = sym_iter.next() {
            std::fmt::Display::fmt(&sym, f)?;
            //#[allow(clippy::while_let_on_iterator)]
            //while let Some(sym) = sym_iter.next()
            for sym in sym_iter {
                f.write_char(',')?;
                std::fmt::Display::fmt(&sym, f)?;
            }
        }
        f.write_char('}')
    }
}
//-------------------------------------------------------------------------------------------------|
impl serde::Serialize for SymSet {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SymSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct SymVisitor;
        impl serde::de::Visitor<'_> for SymVisitor {
            type Value = SymSet;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A SymSet is one or two lowercase letters")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<SymSet, E> {
                value.parse::<SymSet>()
                    .map_err(|_e| serde::de::Error::custom("not a valid SymSet"))
            }
        }
        deserializer.deserialize_any(SymVisitor)
    }
}
//-------------------------------------------------------------------------------------------------|
impl arbitrary::Arbitrary<'_> for SymSet {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let ss: SymSet = u.arbitrary_iter::<Sym>()?.filter_map(|r| r.ok()).collect();
        Ok(ss)
    }

    fn arbitrary_take_rest(u: arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let ss: SymSet = u
            .arbitrary_take_rest_iter::<Sym>()?
            .filter_map(|r| r.ok())
            .collect();
        Ok(ss)
    }

    #[inline]
    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl proptest::arbitrary::Arbitrary for SymSet {
    type Parameters = ();
    type Strategy = proptest_arbitrary_interop::ArbStrategy<Self>;
    fn arbitrary_with(_top: Self::Parameters) -> Self::Strategy {
        proptest_arbitrary_interop::arb()
    }
}
//-------------------------------------------------------------------------------------------------|
impl From<Sym> for SymSet {
    /// A [`SymSet`] can always be made from a [`Sym`].
    #[inline]
    fn from(sym: Sym) -> Self {
        let ix = sym.into_zbo() as usize;
        let mut sbv = SmallBitVec::with_capacity(ix + 1);
        sbv.resize(ix, false);
        sbv.push(true);
        Self(sbv)
    }
}

impl From<&Sym> for SymSet {
    /// A [`SymSet`] can always be made from a [`&Sym`].
    #[inline]
    fn from(sym: &Sym) -> Self {
        Self::from(*sym)
    }
}
//-------------------------------------------------------------------------------------------------|
impl std::iter::FromIterator<Sym> for SymSet {
    fn from_iter<II: IntoIterator<Item = Sym>>(ii: II) -> Self {
        ii.into_iter().fold(SymSet::new(), |ss, s| ss | s)
    }
}

impl<'a> std::iter::FromIterator<&'a Sym> for SymSet {
    fn from_iter<II: IntoIterator<Item = &'a Sym>>(ii: II) -> Self {
        ii.into_iter().copied().collect()
    }
}
//-------------------------------------------------------------------------------------------------|
/*
// An error which can be returned when parsing a [`SymSet`].
#[derive(Clone, Copy, Debug)]
pub struct SymSetParseError;

impl std::fmt::Display for SymSetParseError {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
// */

impl std::str::FromStr for SymSet {
    type Err = Error;

    /// Attempts to parse a string `s` to return a [`SymSet`].
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut e = false;
        let opt_ss = s
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .map(|s| {
                //println!("symset::from_str splitting: {:?}", s);
                s.split(',')
                    .filter_map(|s| {
                        //println!("symset::from_str split: {:?}", s);
                        if s.is_empty() {
                            // This happens with "{}"
                            None
                        } else {
                            let opt_sym = Sym::from_str(s).ok();
                            e |= opt_sym.is_none();
                            opt_sym
                        }
                    })
                    .collect::<SymSet>()
            });
        if e { None } else { opt_ss }.ok_or(Error::ParseSymSet)
    }
}
//-------------------------------------------------------------------------------------------------|
impl std::ops::BitAndAssign<Sym> for SymSet {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn bitand_assign(&mut self, rhs: Sym) {
        let mut ss = SymSet::new();
        if self.contains(rhs) {
            ss |= rhs;
        }
        std::mem::swap(self, &mut ss);
    }
}

impl std::ops::BitAndAssign<&SymSet> for SymSet {
    fn bitand_assign(&mut self, rhs: &SymSet) {
        let mut rhs_iter = rhs.0.iter();
        if rhs.0.len() < self.0.len() {
            self.0.truncate(rhs.0.len());
        }
        let sbv_len = self.0.len();
        unsafe {
            for ix in 0..sbv_len {
                if self.0.get_unchecked(ix) && !rhs.0.get_unchecked(ix) {
                    self.0.set_unchecked(ix, false)
                }
            }
        }
    }
}

impl std::ops::BitAnd<&SymSet> for SymSet {
    type Output = SymSet;
    #[inline]
    fn bitand(mut self, rhs: &SymSet) -> Self::Output {
        self &= rhs;
        self
    }
}

impl<T: Into<SymSet>> std::ops::BitAnd<T> for SymSet {
    type Output = SymSet;
    #[inline]
    fn bitand(mut self, rhs: T) -> Self::Output {
        self &= &Into::<SymSet>::into(rhs);
        self
    }
}
//-------------------------------------------------------------------------------------------------|
impl std::ops::BitOrAssign<Sym> for SymSet {
    fn bitor_assign(&mut self, rhs: Sym) {
        let rhs_zbo = rhs.into_zbo() as usize;
        self.set_at_zbo(rhs_zbo)
    }
}

//impl std::ops::BitOrAssign<SymSet> for SymSet {
//    fn bitor_assign(&mut self, rhs: SymSet) {
//        std::ops::BitOrAssign::<&SymSet>::bitor_assign(self, &rhs)
//    }
//}

impl std::ops::BitOrAssign<&SymSet> for SymSet {
    fn bitor_assign(&mut self, rhs: &SymSet) {
        for sym in rhs.iter() {
            self.bitor_assign(sym)
        }
    }
}

impl std::ops::BitOr<&SymSet> for SymSet {
    type Output = SymSet;
    #[inline]
    fn bitor(mut self, rhs: &SymSet) -> Self::Output {
        self |= rhs;
        self
    }
}

impl<T: Into<SymSet>> std::ops::BitOr<T> for SymSet {
    type Output = SymSet;
    #[inline]
    fn bitor(mut self, rhs: T) -> Self::Output {
        self |= &Into::<SymSet>::into(rhs);
        self
    }
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

    #[test]
    fn t0() {
        let str2 = "{}".to_string();
        let ss2: SymSet = str2.parse().unwrap();
        let str3 = ss2.to_string();
        assert_eq!(str3, str2);
    }

    #[test]
    fn t1() {
        let sym_a: Sym = "a".parse().unwrap();
        let sym_b: Sym = "b".parse().unwrap();
        let sym_c: Sym = "c".parse().unwrap();

        let ss = SymSet::new();
        assert_eq!(ss.to_string().as_str(), "{}");
        let ss_a = ss.clone() | sym_a;
        let ss_b = ss.clone() | sym_b;
        let ss_c = ss.clone() | sym_c;
        assert_eq!(ss_a.to_string().as_str(), "{a}");
        let ss_ab = ss_a.clone() | sym_b;
        let ss_ac = ss_a.clone() | sym_c;
        assert_eq!(ss_ab.to_string().as_str(), "{a,b}");
        let ss_bc = sym_b | sym_c;
        assert_eq!(ss_bc.to_string().as_str(), "{b,c}");
        let ss_abc = ss_a.clone() | &ss_bc;
        assert_eq!(ss_abc.to_string().as_str(), "{a,b,c}");

        let ss_ab_and_bc = ss_ab.clone() & &ss_bc;
        assert_eq!(ss_ab_and_bc.to_string().as_str(), "{b}");

        assert!(ss_a.contains_all_of(&ss));
        assert!(ss_ab.contains_all_of(&ss));

        assert!(ss_ab.contains_all_of(&ss_a));
        assert!(ss_ab.contains_all_of(&ss_b));
        assert!(ss_ab.contains_all_of(&ss_ab));

        assert!(ss_abc.contains_all_of(&ss_a));
        assert!(ss_abc.contains_all_of(&ss_b));
        assert!(ss_abc.contains_all_of(&ss_b));
        assert!(ss_abc.contains_all_of(&ss_ab));
        assert!(ss_abc.contains_all_of(&ss_ac));
        assert!(ss_abc.contains_all_of(&ss_bc));
        assert!(ss_abc.contains_all_of(&ss_abc));
    }

    // [`SymSet`] tests
    proptest! {
        #[test]
        fn symset_arbitrary_sym(sym: Sym) {
            let symset: SymSet = sym.into();
        }

        #[test]
        fn symset_arbitrary(ss1: SymSet) {
            let str1 = ss1.to_string();

            let ss2: SymSet = str1.parse().unwrap();
            prop_assert_eq!(&ss2, &ss1);

            let str2 = ss2.to_string();
            prop_assert_eq!(str2, str1);
        }

        #[test]
        fn symset_bitor_op(ss1: SymSet, ss2: SymSet) {
            let ss3 = ss1.clone() | &ss2;
            prop_assert!(ss3.contains_all_of(&ss1));
            prop_assert!(ss3.contains_all_of(&ss2));
        }

        #[test]
        fn symset_bitor_assign_op(mut ss1: SymSet, ss2: SymSet) {
            let mut ss3 = ss1.clone();
            ss3 |= &ss2;
            prop_assert!(ss3.contains_all_of(&ss1));
            prop_assert!(ss3.contains_all_of(&ss2));
        }

        #[test]
        fn symset_bitand_op(ss1: SymSet, ss2: SymSet) {
            let ss3 = ss1.clone() & &ss2;
            prop_assert!(ss1.contains_all_of(&ss3));
            prop_assert!(ss2.contains_all_of(&ss3));
        }

        #[test]
        fn symset_bitand_assign_op(mut ss1: SymSet, ss2: SymSet) {
            let mut ss3 = ss1.clone();
            ss3 &= &ss2;
            prop_assert!(ss1.contains_all_of(&ss3));
            prop_assert!(ss2.contains_all_of(&ss3));
        }
    }
}
