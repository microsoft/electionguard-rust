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


#![allow(clippy::assertions_on_constants)]
#![allow(clippy::unwrap_used)] // This is test code
#![allow(clippy::expect_used)] // This is test code
#![allow(clippy::panic)] // This is test code
#![allow(clippy::manual_assert)] // This is test code
#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code

use anyhow::{anyhow, bail, ensure, Context, Result};
use cfg_if::cfg_if;
use static_assertions::{assert_impl_all, const_assert, const_assert_eq};

//=================================================================================================|

macro_rules! test_bits3 {
    ($bits:literal, $module:ident, $type:ident) => {
        mod $module {
            const TEST_BITS: usize = 256;
            //type Nonnegative = $type;
            include!("tests-impl-n.inc.rs");
        }
    };
}

macro_rules! test_bits2 {
    //(    8 ) => { #[cfg( feature="bits-8"    )] test_bits3!(    8, bits_8,    Nonnegative_8    ); }; TODO temp commented out due to limitations of crate::significant_first::ops::add_returning_carry
    //(   16 ) => { #[cfg( feature="bits-16"   )] test_bits3!(   16, bits_16,   Nonnegative_16   ); };
    //(   32 ) => { #[cfg( feature="bits-32"   )] test_bits3!(   32, bits_32,   Nonnegative_32   ); };
    //(   64 ) => { #[cfg( feature="bits-64"   )] test_bits3!(   64, bits_64,   Nonnegative_64   ); };
    (  128 ) => { #[cfg( feature="bits-128"  )] test_bits3!(  128, bits_128,  Nonnegative_128  ); };
    (  256 ) => { #[cfg( feature="bits-256"  )] test_bits3!(  256, bits_256,  Nonnegative_256  ); };
    (  512 ) => { #[cfg( feature="bits-512"  )] test_bits3!(  512, bits_512,  Nonnegative_512  ); };
    ( 1024 ) => { #[cfg( feature="bits-1024" )] test_bits3!( 1024, bits_1024, Nonnegative_1024 ); };
    ( 2048 ) => { #[cfg( feature="bits-2048" )] test_bits3!( 2048, bits_2048, Nonnegative_2048 ); };
    ( 4096 ) => { #[cfg( feature="bits-4096" )] test_bits3!( 4096, bits_4096, Nonnegative_4096 ); };
    ( $bits:literal ) => { }
}

//=================================================================================================|

cfg_if! { if #[cfg(
    all( feature="basic-array",
         any( feature="basic-array-u8",
              feature="basic-array-u16",
              feature="basic-array-u32",
              feature="basic-array-u64",
              feature="basic-array-u128" ),
         any( // all( feature="bits-8",        feature="basic-array-u8" ),TODO temp commented out due to limitations of crate::significant_first::ops::add_returning_carry
              all( feature="bits-16",  any( feature="basic-array-u8",
                                            feature="basic-array-u16" ) ),
              all( feature="bits-32",  any( feature="basic-array-u8",
                                            feature="basic-array-u16",
                                            feature="basic-array-u32" ) ),
              all( feature="bits-64",  any( feature="basic-array-u8",
                                            feature="basic-array-u16",
                                            feature="basic-array-u32",
                                            feature="basic-array-u64" ) ),
              all( feature="bits-128", any( feature="basic-array-u8",
                                            feature="basic-array-u16",
                                            feature="basic-array-u32",
                                            feature="basic-array-u64",
                                            feature="basic-array-u128" ) ),
              feature="bits-256",
              feature="bits-512",
              feature="bits-1024",
              feature="bits-2048",
              feature="bits-4096" ) )
)] {
    macro_rules! test_bits {
        //(    8 ) => { #[cfg( all( feature="bits-8",   TODO temp commented out due to limitations of crate::significant_first::ops::add_returning_carry
        //                          feature="basic-array-u8"          ) )] test_bits2!(     8 ); };
        (   16 ) => { #[cfg( all( feature="bits-16",
                                  any( feature="basic-array-u8",
                                       feature="basic-array-u16"  ) ) )] test_bits2!(   16 ); };
        (   32 ) => { #[cfg( all( feature="bits-32",
                                  any( feature="basic-array-u8",
                                       feature="basic-array-u16",
                                       feature="basic-array-u32"  ) ) )] test_bits2!(   32 ); };
        (   64 ) => { #[cfg( all( feature="bits-64",
                                  any( feature="basic-array-u8",
                                       feature="basic-array-u16",
                                       feature="basic-array-u32",
                                       feature="basic-array-u64"  ) ) )] test_bits2!(   64 ); };
        (  128 ) => { #[cfg( all( feature="bits-128",
                                  any( feature="basic-array-u8",
                                       feature="basic-array-u16",
                                       feature="basic-array-u32",
                                       feature="basic-array-u64",
                                       feature="basic-array-u128" ) ) )] test_bits2!(  128 ); };
        (  256 ) => { #[cfg(      feature="bits-256"                  )] test_bits2!(  256 ); };
        (  512 ) => { #[cfg(      feature="bits-512"                  )] test_bits2!(  512 ); };
        ( 1024 ) => { #[cfg(      feature="bits-1024"                 )] test_bits2!( 1024 ); };
        ( 2048 ) => { #[cfg(      feature="bits-2048"                 )] test_bits2!( 2048 ); };
        ( 4096 ) => { #[cfg(      feature="bits-4096"                 )] test_bits2!( 4096 ); };
        ( $bits:literal ) => { };
    }

    #[cfg(feature="basic-array-u8")]   mod basicarray_u8   { use fixed_width_nonnegative::basicarray_u8::*;   include!("tests-impl.inc.rs"); }
    #[cfg(feature="basic-array-u16")]  mod basicarray_u16  { use fixed_width_nonnegative::basicarray_u16::*;  include!("tests-impl.inc.rs"); }
    #[cfg(feature="basic-array-u32")]  mod basicarray_u32  { use fixed_width_nonnegative::basicarray_u32::*;  include!("tests-impl.inc.rs"); }
    #[cfg(feature="basic-array-u64")]  mod basicarray_u64  { use fixed_width_nonnegative::basicarray_u64::*;  include!("tests-impl.inc.rs"); }
    // #[cfg(feature="basic-array-u128")] mod basicarray_u128 { use fixed_width_nonnegative::basicarray_u128::*; include!("tests-impl.inc.rs"); }  TODO temp commented out due to limitations of crate::significant_first::ops::add_returning_carry
} } // if cfg_if!

//=================================================================================================|

cfg_if! { if #[cfg(
    all( feature="crypto-bigint",
         any( feature="bits-64",
              feature="bits-128",
              feature="bits-256",
              feature="bits-512",
              feature="bits-1024",
              feature="bits-2048",
              feature="bits-4096" ) )
)] {
    macro_rules! test_bits {
        // (   8) => { test_bits2!(    8 ); }; TODO temp commented out due to limitations of crate::significant_first::ops::add_returning_carry
        (  16) => { test_bits2!(   16 ); };
        (  32) => { test_bits2!(   32 ); };
        (  64) => { test_bits2!(   64 ); };
        ( 128) => { test_bits2!(  128 ); };
        ( 256) => { test_bits2!(  256 ); };
        ( 512) => { test_bits2!(  512 ); };
        (1024) => { test_bits2!( 1024 ); };
        (2048) => { test_bits2!( 2048 ); };
        (4096) => { test_bits2!( 4096 ); };
        ( $bits:literal ) => { };
    }

    mod cryptobigint { use fixed_width_nonnegative::cryptobigint::*; include!("tests-impl.inc.rs"); }
} } // if cfg_if!

//=================================================================================================|

cfg_if! { if #[cfg(
    all( feature="hacl-rs",
         any( feature="hacl-rs-u32",
              feature="hacl-rs-u64" ),
         any( feature="bits-256",
              feature="bits-4096" ) )
)] {
    macro_rules! test_bits {
        (  256 ) => { test_bits2!(  256 ); };
        ( 4096 ) => { test_bits2!( 4096 ); };
        ( $bits:literal ) => { };
    }

    #[cfg(feature="hacl-rs-u32")] mod haclrs_u32 { use fixed_width_nonnegative::haclrs_u32::*; include!("tests-impl.inc.rs"); }
    #[cfg(feature="hacl-rs-u64")] mod haclrs_u64 { use fixed_width_nonnegative::haclrs_u64::*; include!("tests-impl.inc.rs"); }
} } // if cfg_if!

//=================================================================================================|

cfg_if! { if #[cfg(
    all( feature="num-bigint",
         any( // feature="bits-8",TODO temp commented out due to limitations of crate::significant_first::ops::add_returning_carry
              feature="bits-16",
              feature="bits-32",
              feature="bits-64",
              feature="bits-128",
              feature="bits-256",
              feature="bits-512",
              feature="bits-1024",
              feature="bits-2048",
              feature="bits-4096" ) )
)] {
    macro_rules! test_bits {
        // (    8 ) => { test_bits2!(    8 ); };TODO temp commented out due to limitations of crate::significant_first::ops::add_returning_carry
        (   16 ) => { test_bits2!(   16 ); };
        (   32 ) => { test_bits2!(   32 ); };
        (   64 ) => { test_bits2!(   64 ); };
        (  128 ) => { test_bits2!(  128 ); };
        (  256 ) => { test_bits2!(  256 ); };
        (  512 ) => { test_bits2!(  512 ); };
        ( 1024 ) => { test_bits2!( 1024 ); };
        ( 2048 ) => { test_bits2!( 2048 ); };
        ( 4096 ) => { test_bits2!( 4096 ); };
        ( $bits:literal ) => { };
    }

    mod numbigint { use fixed_width_nonnegative::numbigint::*; include!("tests-impl.inc.rs"); }
} } // if cfg_if!

//=================================================================================================|

#[test]
fn some_impl_feature_was_specified() {
    let mut some_impl = false;
    #[cfg(feature="basic-array"  )] { some_impl = true; }
    #[cfg(feature="crypto-bigint")] { some_impl = true; }
    #[cfg(feature="hacl-rs"      )] { some_impl = true; }
    #[cfg(feature="num-bigint"   )] { some_impl = true; }
    assert!(some_impl, "No implementation feature was specified. You can specify the feature to `cargo test` using the `--features basic-array,crypto-bigint,hacl-rs,num-bigint` parameter.");
}

//=================================================================================================|
