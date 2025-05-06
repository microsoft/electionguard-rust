// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(clippy::let_and_return)] //? TODO: Remove temp development code
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

use std::marker::PhantomData;
#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    borrow::Cow,
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //hash::{BuildHasher, Hash, Hasher},
    //io::{BufRead, Cursor},
    //iter::zip,
    //marker::PhantomData,
    //path::{Path, PathBuf},
    //process::ExitCode,
    //rc::Rc,
    //str::FromStr,
    sync::{
        Arc,
        //LazyLock,
        //OnceLock,
    },
};

use const_default::ConstDefault;

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use futures_lite::future::{self, FutureExt};
//use hashbrown::HashMap;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

//use crate::{};

//=================================================================================================|
pub trait HasName {
    const STATE_NAME: &str;
}

pub struct Ready;
impl HasName for Ready {
    const STATE_NAME: &str = "Ready";
}

pub struct Consuming;
impl HasName for Consuming {
    const STATE_NAME: &str = "Consuming";
}

pub struct Empty;
impl HasName for Empty {
    const STATE_NAME: &str = "Empty";
}

//-------------------------------------------------------------------------------------------------|

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashLcgInternalState(u64);
impl HashLcgInternalState {
    pub const fn from_u64(s: u64) -> Self {
        Self(s)
    }

    pub const fn to_u64(&self) -> u64 {
        self.0
    }
}

fn fmt64(n: u64) -> String {
    format!("0x_{:08X}_{:08X}_u64", (n >> 32) as u32, n as u32)
}

impl std::fmt::Display for HashLcgInternalState {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "0x_{:08X}_{:08X}_u64",
            (self.0 >> 32) as u32,
            self.0 as u32
        ))
    }
}

impl std::fmt::Debug for HashLcgInternalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("HashLcgInternalState({self})"))
    }
}

//-------------------------------------------------------------------------------------------------|

#[derive(Clone)]
pub struct Hash<State>((u64, PhantomData<State>))
where
    State: HasName;

impl<State> Hash<State>
where
    State: HasName,
{
    // L'Ecuyer (1999)
    const A_CONSUME_BYTE: u64 = 2862933555777941757;
    const A_CLOSE: u64 = 3202034522624059733;
    const A_MAKE_MLCG: u64 = Mlcg::A_MLCG;

    const DEFAULT_INTERNAL_STATE_U64: u64 = Hash::<Ready>::A_CLOSE.rotate_left(31);
    const DEFAULT_INTERNAL_STATE: HashLcgInternalState =
        HashLcgInternalState::from_u64(Self::DEFAULT_INTERNAL_STATE_U64);

    pub const fn get_internal_state(&self) -> HashLcgInternalState {
        HashLcgInternalState::from_u64(self.s())
    }
    pub const fn from_internal_state(is: HashLcgInternalState) -> Self {
        Self((is.to_u64(), PhantomData))
    }

    const fn clone_(&self) -> Self {
        Self((self.0.0, PhantomData))
    }

    const fn s(&self) -> u64 {
        self.0.0
    }
    const fn from_s(s: u64) -> Self {
        Self((s, PhantomData))
    }

    const fn consume_bytes_(self, mut aby: &[u8]) -> Hash<Consuming> {
        let Self((mut s, _)) = self;
        while let [fst, rest @ ..] = aby {
            s = Self::op_consume_by(s, *fst);
            aby = rest;
        }
        Hash::<Consuming>::from_s(s)
    }

    const fn op_consume_by(s: u64, by: u8) -> u64 {
        let m = ((by as u16) << 1) | 1;
        Self::op(s, m, Self::A_CONSUME_BYTE)
    }
    const fn op_close(s: u64) -> u64 {
        Self::op(s, 1, Self::A_CLOSE)
    }
    const fn op_make_mlcg(s: u64) -> u64 {
        Self::op(s, 1, Self::A_MAKE_MLCG)
    }
    const fn op(s: u64, m: u16, a: u64) -> u64 {
        (s.wrapping_add(m as u64)).wrapping_mul(a)
    }
}

impl<State> std::fmt::Debug for Hash<State>
where
    State: HasName,
{
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.get_internal_state();
        f.write_fmt(format_args!("Hash<{}>({st})", State::STATE_NAME))
    }
}

impl<State> std::fmt::Display for Hash<State>
where
    State: HasName,
{
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Hash is {}.", State::STATE_NAME))
    }
}

impl Hash<Ready> {
    pub const STATE_NAME: &str = "Ready";

    pub const fn consume_bytes(self, mut aby: &[u8]) -> Hash<Consuming> {
        self.consume_bytes_(aby)
    }

    pub const fn make_mlcg(self) -> (Hash<Empty>, Mlcg) {
        let s = self.s();
        let lcg = Mlcg(Self::op_make_mlcg(s));
        (Hash::<Empty>::from_s(s), lcg)
    }
}

impl ConstDefault for Hash<Ready> {
    const DEFAULT: Self = Self::from_internal_state(Self::DEFAULT_INTERNAL_STATE);
}

impl Hash<Consuming> {
    pub const STATE_NAME: &str = "Consuming";

    pub const fn from_seed_u64(seed: u64) -> Hash<Consuming> {
        Hash::<Ready>::DEFAULT
            .consume_bytes(&seed.to_le_bytes())
            .close()
            .consume_bytes(b"")
    }

    pub const fn consume_bytes(self, mut aby: &[u8]) -> Hash<Consuming> {
        self.consume_bytes_(aby)
    }

    pub const fn close(self) -> Hash<Ready> {
        let s = self.s();
        let s = Self::op_close(s);
        Hash::<Ready>::from_s(s)
    }
}

impl ConstDefault for Hash<Consuming> {
    const DEFAULT: Self = Self::from_internal_state(Self::DEFAULT_INTERNAL_STATE);
}

impl Hash<Empty> {
    pub const STATE_NAME: &str = "Empty";

    pub const fn close(self) -> Hash<Ready> {
        Hash::<Consuming>::from_s(self.s()).close()
    }
    pub const fn make_duplicate_mlcg(&self) -> (Hash<Empty>, Mlcg) {
        let s = self.s();
        let lcg = Mlcg(Self::op_make_mlcg(s));
        (Hash::<Empty>::from_s(s), lcg)
    }
}

impl ConstDefault for Hash<Empty> {
    const DEFAULT: Self = Self::from_internal_state(Self::DEFAULT_INTERNAL_STATE);
}

//-------------------------------------------------------------------------------------------------|

pub struct Mlcg(u64);

impl Mlcg {
    // L'Ecuyer (1999)
    const A_MLCG: u64 = 3935559000370003845;

    pub const fn get_internal_state(&self) -> HashLcgInternalState {
        HashLcgInternalState::from_u64(self.0)
    }

    pub const fn next_u32(self) -> (Mlcg, u32) {
        let s = self.0;
        let s = s.wrapping_add(1).wrapping_mul(Self::A_MLCG);
        (Self(s), (s >> 32) as u32)
    }

    pub const fn next_u64(self) -> (Mlcg, u64) {
        let (m, hi32) = self.next_u32();
        let (m, lo32) = m.next_u32();
        let n64 = ((hi32 as u64) << 32) | (lo32 as u64);
        (m, n64)
    }
}

impl ConstDefault for Mlcg {
    const DEFAULT: Self = Mlcg(Self::A_MLCG.rotate_left(29));
}

impl std::fmt::Debug for Mlcg {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for Mlcg {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = self.get_internal_state();
        f.write_fmt(format_args!("Mlcg({v})"))
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use insta::{assert_debug_snapshot, assert_snapshot};

    #[test]
    fn t1() {
        let his = HashLcgInternalState::from_u64(0x_FEDCBA98_76543210_u64);
        assert_snapshot!(format!("{:016X}", his.to_u64()), @"FEDCBA9876543210");
        assert_debug_snapshot!(his, @"HashLcgInternalState(0x_FEDCBA98_76543210_u64)");
        assert_snapshot!(his, @"0x_FEDCBA98_76543210_u64");
    }

    #[test]
    fn t2() {
        let h = Hash::<Ready>::DEFAULT;
        assert_debug_snapshot!(h, @"Hash<Ready>(0x_73C5B4AA_9637F4B7_u64)");
        assert_snapshot!(h, @"Hash is Ready.");

        let h = h.consume_bytes(b"");
        assert_debug_snapshot!(h, @"Hash<Consuming>(0x_73C5B4AA_9637F4B7_u64)");

        let h = h.consume_bytes(b"\0");
        assert_debug_snapshot!(h, @"Hash<Consuming>(0x_4FBE89B2_340B59D8_u64)");

        let h = h.close();
        assert_debug_snapshot!(h, @"Hash<Ready>(0x_24346BFE_8771D60D_u64)");

        let (h, m) = h.make_mlcg();
        assert_debug_snapshot!(h, @"Hash<Empty>(0x_24346BFE_8771D60D_u64)");
        assert_debug_snapshot!(m, @"Mlcg(0x_40B42BBB_06D7A746_u64)");
    }

    #[test]
    fn t3() {
        let (h, ma) = Hash::<Ready>::DEFAULT.make_mlcg();
        assert_debug_snapshot!(h, @"Hash<Empty>(0x_73C5B4AA_9637F4B7_u64)");
        assert_debug_snapshot!(ma, @"Mlcg(0x_BDAFE647_C2E36B98_u64)");

        let mb = Mlcg::DEFAULT;
        assert_debug_snapshot!(mb, @"Mlcg(0x_E634A7F0_A6D3BD41_u64)");

        let ma64 = ma.get_internal_state().to_u64();
        let mb64 = mb.get_internal_state().to_u64();
        let diff = ma64.wrapping_sub(mb64);
        assert_debug_snapshot!(diff, @"15527072684143783511");
    }

    fn fmt32(n: u32) -> String {
        format!("0x_{n:08X}_u32")
    }

    #[test]
    fn t4() {
        // Test Mlcg output sequence

        let m = Mlcg::DEFAULT;
        assert_debug_snapshot!(m, @"Mlcg(0x_E634A7F0_A6D3BD41_u64)");

        let (m, n) = m.next_u32();
        assert_debug_snapshot!(m, @"Mlcg(0x_2B99F1A5_651E914A_u64)");
        assert_snapshot!(fmt32(n), @r#"0x_2B99F1A5_u32"#);

        let (m, n) = m.next_u32();
        assert_debug_snapshot!(m, @"Mlcg(0x_BBFF56B8_0EF9F0F7_u64)");
        assert_snapshot!(fmt32(n), @"0x_BBFF56B8_u32");

        let (m, n) = m.next_u32();
        assert_debug_snapshot!(m, @"Mlcg(0x_107EA60F_11FF38D8_u64)");
        assert_snapshot!(fmt32(n), @"0x_107EA60F_u32");

        let (m, n) = m.next_u64();
        assert_debug_snapshot!(m, @"Mlcg(0x_295C460F_912C4FB6_u64)");
        assert_snapshot!(fmt64(n), @"0x_A1D21D5A_295C460F_u64");
    }

    #[test]
    fn t5() {
        // Test various hashes

        fn h(aby: &[u8]) -> String {
            let h = Hash::<Ready>::DEFAULT.consume_bytes(aby).close();
            let (h, g) = h.make_mlcg();
            let a = h.get_internal_state().to_u64();
            let b = g.get_internal_state().to_u64();
            let (_g, c) = g.next_u64();
            format!("{}, {}, {}", fmt64(a), fmt64(b), fmt64(c))
        }

        assert_snapshot!(h(b""), @"0x_C379A184_BBDBB918_u64, 0x_A2D869B3_C1D150FD_u64, 0x_54790E62_2F3A55DC_u64");
        assert_snapshot!(h(&[0]), @"0x_24346BFE_8771D60D_u64, 0x_40B42BBB_06D7A746_u64, 0x_064D2206_70BEBA71_u64");
        assert_snapshot!(h(&[1]), @"0x_BB9D8918_5CB4E80F_u64, 0x_C08FD26D_51688050_u64, 0x_0EA2417D_6F6CD013_u64");
        assert_snapshot!(h(&[2]), @"0x_5306A632_31F7FA11_u64, 0x_406B791F_9BF9595A_u64, 0x_16F760F4_6E1AE5B6_u64");
        assert_snapshot!(h(&[3]), @"0x_EA6FC34C_073B0C13_u64, 0x_C0471FD1_E68A3264_u64, 0x_1F4C806B_6CC8FB59_u64");
        assert_snapshot!(h(b"asdf"), @"0x_F76F873D_9AA48408_u64, 0x_44608BE5_A6C3CFAD_u64, 0x_3B8A6080_E6D1344B_u64");
    }
}
