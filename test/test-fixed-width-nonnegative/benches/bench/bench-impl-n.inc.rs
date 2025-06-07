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


// NOTE: This file is intended to be include!()ed, in a specific context and not built directly.

use super::*;
use criterion::{black_box, BatchSize, Criterion};
use bench_util::CheapPrng;
//? type FwnnN = Fwnn::<BENCH_REPR_BITS>;

pub(crate) fn bench(c: &mut Criterion) {
    /*
    let bench_param_s = format!("Fwnn<{}>", FwnnN::BITS     );
    let bench_function_id = format!("{}::{bench_param_s}", FwnnN::UNDERLYING_BIGNUM_IMPLEMENTATION);

    let test_data = create_data(&bench_param_s);

    c.bench_function(
        &bench_function_id,
        move |b| {
            b.iter_batched(
                || test_data.clone(),
                TestData::bench_function,
                BatchSize::SmallInput
            )
        });
    // */
    let bench_function_id = "bench_function_id_todo";
    c.bench_function(
        bench_function_id,
        move |b| {
            b.iter(|| black_box(black_box(3_u128)*17_u128))
        });
    }
/*

fn create_data(bench_param_s: &str) -> TestData {
    let prng = CheapPrng_new(&bench_param_s);

    let cnt_n = 1000_usize;
    let cnt_n = 5_usize;

    let cnt_passes = 1000_usize;
    let cnt_passes = 10_usize;

    //? TODO initialize randomly
    let v = vec![FwnnN::zero(); cnt_n];

    let v_ix: Vec<usize> = Vec::with_capacity(3);

    TestData {
        prng,    
        cnt_passes,
        v,
    }
}

fn some_dupes(a: &[usize]) -> bool {
    use std::collections::HashSet;
    let mut hs = HashSet::new();
    for ix in a {
        let newly_inserted = hs.insert(ix);
        if !newly_inserted {
            return true;
        }
    }
    false        
}

#[derive(Clone)]
struct TestData {
    prng: CheapPrng,
    cnt_passes: usize,
    v: Vec<FwnnN>,
}

#[allow(unused_mut)]
impl TestData {
    fn bench_function(mut self) {
        //FwnnN::add(black_box(1), black_box(20));

        let cnt_n = self.v.len();

        let mut a_ix = [0; 3];

        for pass_n in 0..self.cnt_passes {
            //eprintln!("============================================= pass_n: {pass_n}");
            for ix0 in 0..cnt_n {
                a_ix[0] = ix0;
                Self::pick_indices(&mut self.prng, 1, &mut a_ix, cnt_n);
                //eprintln!("indices: {:?}", a_ix);

                //self.fwnn_op(a_ix);

                let (ix0, ix1, ix2) = a_ix.into();
                self.fwnn_op(ix0, ix1, ix2);

                /* let r0 = &mut v[ar0];
                let r1 = &mut v[ar1];
                let r2 = &mut v[ar2];
                Self::fwnn_op(r0, r1, r2) */
            }
        }
    }

    fn fwnn_op(&mut self, ix0: usize, ix1: usize, ix2: usize) {
        let r1 = self.v[ix1].clone();
        let r2 = self.v[ix2].clone();
        self.v[ix0] = r1 + r2;
    }

    /* fn fwnn_op(r0: &mut FwnnN, r1: &mut FwnnN, r2: &mut FwnnN) {
        *r0 = *r1 + *r2;
    } */

    fn pick_indices<const CNT_IX: usize>(prng: &mut CheapPrng, cnt_filled: usize, a_ix: &mut [usize; CNT_IX], cnt_n: usize) {
        let mut cf = cnt_filled;

        while cf < CNT_IX {
            let (sl_f, sl_uf) = a_ix.split_at_mut(cf);

            let mut cnt_iters = 0_usize;
            let mut ix = usize::MAX;
            loop {
                let ix2 = prng.gen_range(0..(cnt_n as u64)) as usize;
                if !sl_f.contains(&ix2) {
                    ix = ix2;
                    break;
                }
                cnt_iters += 1;
                assert!(cnt_iters < 10_000_000, "This will break if you ask for all the indices in a huge container. If this happens, get a better algorithm.");
            }
            sl_uf[0] = ix;
            cf += 1;
        }

        assert!(!some_dupes(&a_ix[..]), "duplicate indices found");
        assert!(a_ix.iter().all(|&ix| ix < cnt_n), "indices out of range");
    }
}
*/
