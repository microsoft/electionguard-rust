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


//#![rustfmt::skip]

#![allow(clippy::assertions_on_constants)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code

//use std::{
//};

use anyhow::{anyhow, bail, ensure, Context, Result};

/*
use cfg_if::cfg_if;
use criterion::{criterion_group, criterion_main};
use num_traits::identities::Zero;
use rand::Rng;

use bench_util::CheapPrng_new;

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
//    (    8 ) => { #[cfg( feature="bits-8"    )] test_bits3!(    8, bits_8,    Nonnegative_8    ); }; TODO temp commented out due to limitations of crate::significant_first::ops::add_returning_carry
    (   16 ) => { #[cfg( feature="bits-16"   )] test_bits3!(   16, bits_16,   Nonnegative_16   ); };
    (   32 ) => { #[cfg( feature="bits-32"   )] test_bits3!(   32, bits_32,   Nonnegative_32   ); };
    (   64 ) => { #[cfg( feature="bits-64"   )] test_bits3!(   64, bits_64,   Nonnegative_64   ); };
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
        (    8 ) => { #[cfg( // all( feature="bits-8", TODO temp commented out due to limitations of crate::significant_first::ops::add_returning_carry
                                  feature="basic-array-u8"          ) )] test_bits2!(     8 ); };
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

    /*
    criterion_group!(
        benches_basicarray,
        bench_basicarray::u8::b8::bench,
        bench_basicarray::u8::b16::bench,
        bench_basicarray::u8::b32::bench,
        bench_basicarray::u8::b64::bench,
        bench_basicarray::u8::b128::bench,
        bench_basicarray::u8::b256::bench,
        bench_basicarray::u8::b512::bench,
        bench_basicarray::u8::b1024::bench,
        bench_basicarray::u8::b2048::bench,
        bench_basicarray::u8::b4096::bench,
        bench_basicarray::u16::b8::bench,
        bench_basicarray::u16::b16::bench,
        bench_basicarray::u16::b32::bench,
        bench_basicarray::u16::b64::bench,
        bench_basicarray::u16::b128::bench,
        bench_basicarray::u16::b256::bench,
        bench_basicarray::u16::b512::bench,
        bench_basicarray::u16::b1024::bench,
        bench_basicarray::u16::b2048::bench,
        bench_basicarray::u16::b4096::bench,
        bench_basicarray::u32::b8::bench,
        bench_basicarray::u32::b16::bench,
        bench_basicarray::u32::b32::bench,
        bench_basicarray::u32::b64::bench,
        bench_basicarray::u32::b128::bench,
        bench_basicarray::u32::b256::bench,
        bench_basicarray::u32::b512::bench,
        bench_basicarray::u32::b1024::bench,
        bench_basicarray::u32::b2048::bench,
        bench_basicarray::u32::b4096::bench,
        bench_basicarray::u64::b8::bench,
        bench_basicarray::u64::b16::bench,
        bench_basicarray::u64::b32::bench,
        bench_basicarray::u64::b64::bench,
        bench_basicarray::u64::b128::bench,
        bench_basicarray::u64::b256::bench,
        bench_basicarray::u64::b512::bench,
        bench_basicarray::u64::b1024::bench,
        bench_basicarray::u64::b2048::bench,
        bench_basicarray::u64::b4096::bench,
        bench_basicarray::u128::b8::bench,
        bench_basicarray::u128::b16::bench,
        bench_basicarray::u128::b32::bench,
        bench_basicarray::u128::b64::bench,
        bench_basicarray::u128::b128::bench,
        bench_basicarray::u128::b256::bench,
        bench_basicarray::u128::b512::bench,
        bench_basicarray::u128::b1024::bench,
        bench_basicarray::u128::b2048::bench,
        bench_basicarray::u128::b4096::bench,
    );
    */

    #[cfg(feature="basic-array-u8")]   mod basicarray_u8   { use fixed_width_nonnegative::basicarray_u8::*;   include!("bench/bench-impl.inc.rs"); }
    #[cfg(feature="basic-array-u16")]  mod basicarray_u16  { use fixed_width_nonnegative::basicarray_u16::*;  include!("bench/bench-impl.inc.rs"); }
    #[cfg(feature="basic-array-u32")]  mod basicarray_u32  { use fixed_width_nonnegative::basicarray_u32::*;  include!("bench/bench-impl.inc.rs"); }
    #[cfg(feature="basic-array-u64")]  mod basicarray_u64  { use fixed_width_nonnegative::basicarray_u64::*;  include!("bench/bench-impl.inc.rs"); }
    #[cfg(feature="basic-array-u128")] mod basicarray_u128 { use fixed_width_nonnegative::basicarray_u128::*; include!("bench/bench-impl.inc.rs"); }
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
        (   8) => { test_bits2!(    8 ); };
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

    pub(crate) mod cryptobigint {
        use fixed_width_nonnegative::cryptobigint::*;
        #[cfg(feature="bits-256")] pub(crate) mod b256 {
            const FUNCTION_ID: &'static str = "b256-cryptobigint";
            include!("bench/bench-impl-n.inc.rs"); }
        #[cfg(feature="bits-4096")] pub(crate) mod b4096 {
            const FUNCTION_ID: &'static str = "b4096-cryptobigint";
            include!("bench/bench-impl-n.inc.rs"); }
    }
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

    #[cfg(all(feature="hacl-rs", feature="hacl-rs-u32"))] pub(crate) mod haclrs_u32 {
        use fixed_width_nonnegative::haclrs_u32::*;
        #[cfg(feature="bits-256" )] pub(crate) mod  b256 { const FUNCTION_ID: &'static str =  "b256-haclrs-u32"; include!("bench/bench-impl-n.inc.rs"); }
        #[cfg(feature="bits-4096")] pub(crate) mod b4096 { const FUNCTION_ID: &'static str = "b4096-haclrs-u32"; include!("bench/bench-impl-n.inc.rs"); }
    }

    #[cfg(all(feature="hacl-rs", feature="hacl-rs-u64"))] pub(crate) mod haclrs_u64 {
        use fixed_width_nonnegative::haclrs_u64::*;
        #[cfg(feature="bits-256" )] pub(crate) mod  b256 { const FUNCTION_ID: &'static str =  "b256-haclrs-u64"; include!("bench/bench-impl-n.inc.rs"); }
        #[cfg(feature="bits-4096")] pub(crate) mod b4096 { const FUNCTION_ID: &'static str = "b4096-haclrs-u64"; include!("bench/bench-impl-n.inc.rs"); }
    }
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
        (    8 ) => { test_bits2!(    8 ); };
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

    /*
    mod bench_numbigint {
        #[cfg(feature = "num-bigint")] use fixed_width_nonnegative::numbigint::*;
        #[cfg(feature = "num-bigint")] include!("bench/bench-impl.inc.rs");
    }
    //#[cfg(feature = "num-bigint")] criterion_group!(benches_numbigint, bench_numbigint::b256::bench, bench_numbigint::b4096::bench);
    */

    mod numbigint { use fixed_width_nonnegative::numbigint::*; include!("bench/bench-impl.inc.rs"); }
} } // if cfg_if!

//=================================================================================================|

cfg_if! { if #[cfg(all( feature="bits-256",  feature="crypto-bigint"                  ))] { criterion_group!(  b256, cryptobigint ::  b256 :: bench ); } }
cfg_if! { if #[cfg(all( feature="bits-256",  feature="hacl-rs", feature="hacl-rs-u32" ))] { criterion_group!(  b256, haclrs_u32   ::  b256 :: bench ); } }
cfg_if! { if #[cfg(all( feature="bits-256",  feature="hacl-rs", feature="hacl-rs-u64" ))] { criterion_group!(  b256, haclrs_u64   ::  b256 :: bench ); } }
cfg_if! { if #[cfg(all( feature="bits-4096", feature="crypto-bigint"                  ))] { criterion_group!( b4096, cryptobigint :: b4096 :: bench ); } }
cfg_if! { if #[cfg(all( feature="bits-4096", feature="hacl-rs", feature="hacl-rs-u32" ))] { criterion_group!( b4096, haclrs_u32   :: b4096 :: bench ); } }
cfg_if! { if #[cfg(all( feature="bits-4096", feature="hacl-rs", feature="hacl-rs-u64" ))] { criterion_group!( b4096, haclrs_u64   :: b4096 :: bench ); } }
// */

fn main() -> Result<()> {
    /*
    #[cfg(feature="bits-256" )]  b256();
    #[cfg(feature="bits-4096")] b4096();
    // */
    Ok(())
}
