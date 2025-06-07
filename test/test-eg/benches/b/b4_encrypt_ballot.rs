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
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code

use std::borrow::Borrow;
use std::mem::{align_of, size_of};

use anyhow::{anyhow, bail, ensure, Context, Result};
use criterion::*;
use criterion::{black_box, Bencher, Criterion};
use crypto_bigint::modular::Retrieve;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use rand_core::RngCore;
use rayon::prelude::*;
use static_assertions::{assert_eq_size, const_assert, const_assert_eq};

use eg::election_manifest::{ContestIndex, ContestOptionIndex};
use eg::election_parameters;
use eg::fixed_parameters::FixedParameters;
use eg::hash::HValueByteArray;
use eg::hashes_ext::HashesExt;
use eg::index::Index;
use eg::joint_election_public_key::JointElectionPublicKey;
use eg::nonce::BallotNonce;
use eg::vec1::{HasIndexTypeMarker, Vec1};
use eg_artifacts_dir::{
    load_election_parameters, load_hashes_ext, load_joint_election_public_key, ArtifactsDir,
};
use util::csprng::Csprng;

use bench_util::*;

use crate::b::*;

// "Standard" ballot for benchmarking purposes
const STANDARD_BALLOT_CNT_CONTESTS: usize = 12;
const STANDARD_BALLOT_CNT_CONTEST_FIELDS: usize = 4;

const PASS_BENCHFN_CNT_BALLOTS: usize = 48; // 100
const BALLOT_TOTAL_CNT_FIELDS: usize =
    STANDARD_BALLOT_CNT_CONTESTS * STANDARD_BALLOT_CNT_CONTEST_FIELDS;
const PASS_BENCHFN_TOTAL_CNT_FIELDS: usize = PASS_BENCHFN_CNT_BALLOTS * BALLOT_TOTAL_CNT_FIELDS;
const PASS_BENCHFN_TOTAL_CNT_MODEXPS: usize = PASS_BENCHFN_TOTAL_CNT_FIELDS * 2;

type bau64_Nonnegative_4096 = fixed_width_nonnegative::basicarray_u64::Nonnegative_4096;
type bau64_Montgomery_4096 = fixed_width_nonnegative::basicarray_u64::Montgomery_4096;
type bau64_MontgomeryPrecomputation_4096 = fixed_width_nonnegative::basicarray_u64::MontgomeryPrecomputation_4096;
type crybi_Nonnegative_256 = fixed_width_nonnegative::cryptobigint::Nonnegative_256;
type crybi_Nonnegative_4096 = fixed_width_nonnegative::cryptobigint::Nonnegative_4096;
type numbi_Nonnegative_256 = fixed_width_nonnegative::numbigint::Nonnegative_256;
type numbi_Nonnegative_4096 = fixed_width_nonnegative::numbigint::Nonnegative_4096;

fn numbigint_to_nonnegative256<T: std::borrow::Borrow<BigUint>>(b: &T) -> Result<crybi_Nonnegative_256> {
    let n: numbi_Nonnegative_256 = b.borrow().try_into()?;
    Ok(n.into())
}

fn numbigint_to_nonnegative4096<T: std::borrow::Borrow<BigUint>>(
    b: &T,
) -> Result<crybi_Nonnegative_4096> {
    let n: numbi_Nonnegative_4096 = b.borrow().try_into()?;
    Ok(n.into())
}

#[rustfmt::skip]
pub fn bench(c: &mut Criterion) {
    let bench_function_id = format!("b4 enc {PASS_BENCHFN_CNT_BALLOTS} ballots");

    eprintln!("\n================================================================ Bench: {bench_function_id}\n");

    let min_cnt_threads = 8;
    eprintln!("min_cnt_threads: {min_cnt_threads}");

    let max_cnt_threads = rayon::max_num_threads();
    eprintln!("Rayon max_cnt_threads: {max_cnt_threads}");

    let csprng = Csprng::new(bench_function_id.as_ref());

    let mut bench_data = BenchData::new(csprng);

    let vfns: Vec<(&str, Box<dyn Fn(&mut BenchData)>)> = vec![
        //("encrypt_ballots_st", Box::new(|bd: &mut BenchData| encrypt_ballots_st(bd))),
        //("encrypt_ballots_mt", Box::new(|bd: &mut BenchData| encrypt_ballots_mt(bd))),
        ("encrypt_ballots_mt_mg", Box::new(|bd: &mut BenchData| encrypt_ballots_mt_mg(bd))),
        ("encrypt_ballots_mt_mg_et", Box::new(|bd: &mut BenchData| encrypt_ballots_mt_mg_et(bd))),
    ];

    let over_fn_cnt = (1 < vfns.len()).then(|| format!(", each over {} functions", vfns.len()))
        .unwrap_or_default();

    let v_group_pass_infos = group_pass_infos();
    for (group_n, group_pass_info) in v_group_pass_infos.iter().enumerate() {
        let group_name = format!("{bench_function_id} g{group_n}");
        let cnt_passes = group_pass_info.cnt_passes;
        let pass_digits = format!("{cnt_passes}").len();

        eprintln!("\n================================================ Group {group_n} of {}", v_group_pass_infos.len());
        eprintln!("\n{group_pass_info:#?}");

        eprintln!("\nRunning {cnt_passes:0wid$} passes{over_fn_cnt}.", wid=pass_digits);

        let mut group = c.benchmark_group(group_name);
        group_pass_info.opt_warm_up_time_s.map(|s| group.warm_up_time(std::time::Duration::from_secs(s)));
        group_pass_info.opt_target_measurement_time_s.map(|s| group.measurement_time(std::time::Duration::from_secs(s)));
        group.sample_size(group_pass_info.sample_size);

        group.throughput(Throughput::Elements(PASS_BENCHFN_CNT_BALLOTS as u64));

        for pass_n in 1 ..= cnt_passes {
            let str_pn = (cnt_passes != 1).then(|| format!(" p{pass_n:0wid$}", wid=pass_digits))
                .unwrap_or_default();

            eprintln!("\n============================== Pass {pass_n} of {cnt_passes}{over_fn_cnt}");

            for (fn_ch, bx_fn) in &vfns {
                //let diff_cnt_threads = max_cnt_threads.saturating_sub(min_cnt_threads).max(1);
                //let cnt_threads = min_cnt_threads + (pass_n as usize % diff_cnt_threads);
                let cnt_threads = PASS_BENCHFN_CNT_BALLOTS/4;

                let benchfn_id = format!("{fn_ch}{str_pn}_{cnt_threads}th");

                eprintln!("\n------------------------- bench fn {benchfn_id}\n");
                
                eprintln!("cnt_threads: {cnt_threads}");

                group.bench_function(benchfn_id, |b| {
                    b.iter(|| {
                        bench_data.v_ballot_encryption_results.clear();
                        bench_data.v_ballot_encryption_results.reserve(PASS_BENCHFN_CNT_BALLOTS);
                        bench_data.cnt_threads = cnt_threads;

                        bx_fn(black_box(&mut bench_data))
                    })
                });
            }
        }

        group.finish();
        eprintln!("\n[group finish]");
    }

    eprintln!("\n[bench finish]");
}

//=================================================================================================|

struct BallotStyle {
    ballot_style_ix: BallotStyleIndex,
    ballot_contest_field_indices: [(ContestIndex, ContestOptionIndex); BALLOT_TOTAL_CNT_FIELDS],
}
type BallotStyleIndex = Index<BallotStyle>;

impl BallotStyle {
    pub fn new_standard(ballot_style_ix: BallotStyleIndex) -> BallotStyle {
        let mut bcfis = [(ContestIndex::MIN, ContestOptionIndex::MIN); BALLOT_TOTAL_CNT_FIELDS];

        let mut bfci_ix = 0_usize;
        for contest_ix in 1..=STANDARD_BALLOT_CNT_CONTESTS {
            let i = ContestIndex::from_one_based_index(contest_ix.try_into().unwrap()).unwrap();

            for contest_field_ix in 1..=STANDARD_BALLOT_CNT_CONTEST_FIELDS {
                let j =
                    ContestOptionIndex::from_one_based_index(contest_field_ix.try_into().unwrap())
                        .unwrap();

                bcfis[bfci_ix] = (i, j);
                bfci_ix += 1;
            }
        }

        BallotStyle {
            ballot_style_ix,
            ballot_contest_field_indices: bcfis,
        }
    }
}

impl HasIndexTypeMarker for BallotStyle {}

lazy_static! {
    static ref BALLOT_STYLES: Vec1<BallotStyle> = Vec1::try_from([BallotStyle::new_standard(
        BallotStyleIndex::from_one_based_index_const(1).unwrap()
    ),])
    .unwrap();
}

struct BenchData {
    csprng: Csprng,
    fixed_parameters: FixedParameters,
    p: crybi_Nonnegative_4096,
    q: crybi_Nonnegative_256,
    g: crybi_Nonnegative_4096,
    h_ext: HashesExt,
    joint_election_public_key: JointElectionPublicKey,
    ballot_style_ix: BallotStyleIndex,
    selectioned_ballots: [SelectionedBallot; PASS_BENCHFN_CNT_BALLOTS],
    cnt_threads: usize,
    v_ballot_encryption_results: Vec<BallotEncryptionResult>,
}
impl BenchData {
    pub fn new(csprng: Csprng) -> BenchData {
        let mut csprng = csprng;

        let artifacts_dir = ArtifactsDir::new().unwrap();

        let election_parameters = load_election_parameters(&artifacts_dir, &mut csprng).unwrap();
        let fixed_parameters = election_parameters.fixed_parameters.clone();

        let p = numbigint_to_nonnegative4096(fixed_parameters.p()).unwrap();
        //eprintln!("\np={p:X}");

        let q = numbigint_to_nonnegative256(fixed_parameters.q()).unwrap();
        //eprintln!("\nq={q:X}");

        let g = numbigint_to_nonnegative4096(fixed_parameters.g()).unwrap();
        //eprintln!("\ng={g:X}");

        let h_ext = load_hashes_ext(&artifacts_dir).unwrap();

        let joint_election_public_key =
            load_joint_election_public_key(&artifacts_dir, &election_parameters).unwrap();
        eprintln!(
            "joint_election_public_key: {} bits",
            joint_election_public_key.joint_election_public_key.as_biguint().bits()
        );
        assert!(4000 < joint_election_public_key.joint_election_public_key.as_biguint().bits());

        eprintln!("PASS_BENCHFN_CNT_BALLOTS: {PASS_BENCHFN_CNT_BALLOTS} ballots per bench pass - these are reported as 'elems' e.g 'Kelem/s");
        eprintln!(
            "STANDARD_BALLOT_CNT_CONTESTS: {STANDARD_BALLOT_CNT_CONTESTS} contests per ballot"
        );
        eprintln!("STANDARD_BALLOT_CNT_CONTEST_FIELDS: {STANDARD_BALLOT_CNT_CONTEST_FIELDS} fields per contest");
        eprintln!("STANDARD_BALLOT_TOTAL_CNT_FIELDS_IMPLIED: {BALLOT_TOTAL_CNT_FIELDS} total fields per ballot");
        eprintln!("PASS_BENCHFN_TOTAL_CNT_FIELDS {PASS_BENCHFN_TOTAL_CNT_FIELDS} fields per bench pass, total");
        eprintln!("PASS_BENCHFN_TOTAL_CNT_MODEXPS: {PASS_BENCHFN_TOTAL_CNT_MODEXPS} modular exponentiations per bench pass");

        let ballot_style_ix = BallotStyleIndex::MIN;
        let _ballot_style: &'static BallotStyle = &BALLOT_STYLES.get(ballot_style_ix).unwrap();

        let selectioned_ballots =
            std::array::from_fn(|_ix| SelectionedBallot::new(&mut csprng, ballot_style_ix));

        BenchData {
            csprng,
            fixed_parameters,
            p,
            q,
            g,
            h_ext,
            joint_election_public_key,
            ballot_style_ix,
            selectioned_ballots,
            cnt_threads: 1,
            v_ballot_encryption_results: Vec::with_capacity(PASS_BENCHFN_CNT_BALLOTS),
        }
    }
}

struct SelectionedBallot {
    ballot_style_ix: BallotStyleIndex,
    ballot_contest_field_values: [u8; BALLOT_TOTAL_CNT_FIELDS],
}

impl SelectionedBallot {
    pub fn new(csprng: &mut Csprng, ballot_style_ix: BallotStyleIndex) -> Self {
        let _ballot_style: &BallotStyle = &BALLOT_STYLES.get(ballot_style_ix).unwrap();

        let mut ballot_contest_field_values = [0; BALLOT_TOTAL_CNT_FIELDS];

        for bcfv in ballot_contest_field_values.iter_mut() {
            *bcfv = csprng.next_bool().into();
        }

        SelectionedBallot {
            ballot_style_ix,
            ballot_contest_field_values,
        }
    }
}

struct FieldCiphertext {
    // Compare to: eg::joint_election_public_key::Ciphertext
    pub alpha: crybi_Nonnegative_4096,
    pub beta: crybi_Nonnegative_4096,
}

struct EncryptedBallot {
    ballot_style_ix: BallotStyleIndex,
    encryptions: [FieldCiphertext; BALLOT_TOTAL_CNT_FIELDS],
}

//? TODO replace with some kind of fill_random support on Nonnegative types
fn random_nn_256(csprng: &mut Csprng) -> crybi_Nonnegative_256 {
    let mut aby = [0_u8; crybi_Nonnegative_256::BYTES];
    csprng.fill_bytes(&mut aby);
    crybi_Nonnegative_256::from_be_bytes_arr(aby)
}

fn encrypt_ballots_st(data: &mut BenchData) {
    //eprintln!("encrypt_ballots_st");

    assert_eq!(data.selectioned_ballots.len(), PASS_BENCHFN_CNT_BALLOTS);
    assert!(data.v_ballot_encryption_results.is_empty());

    /*std::array::from_fn(|ix| {
        let selectioned_ballot = &data.selectioned_ballots[ix];
        BallotEncryptionResult::from_selectioned_ballot(&mut data.csprng, &data.h_ext, selectioned_ballot)
    });// */

    let it = data.selectioned_ballots.iter().map(|selectioned_ballot| {
        BallotEncryptionResult::from_selectioned_ballot(
            &mut data.csprng,
            &data.fixed_parameters,
            &data.h_ext,
            &data.joint_election_public_key,
            selectioned_ballot,
            "encrypt_ballots_st",
        )
    });

    data.v_ballot_encryption_results.extend(it);
}

fn encrypt_ballots_mt(data: &mut BenchData) {
    encrypt_ballots_bc(data, "encrypt_ballots_mt");
}

fn encrypt_ballots_mt_mg(data: &mut BenchData) {
    encrypt_ballots_bc(data, "encrypt_ballots_mt_mg");
}

fn encrypt_ballots_mt_mg_et(data: &mut BenchData) {
    encrypt_ballots_bc(data, "encrypt_ballots_mt_mg_et");
}

fn encrypt_ballots_bc(data: &mut BenchData, fn_name: &str) {
    //eprintln!("{name}");

    assert_eq!(data.selectioned_ballots.len(), PASS_BENCHFN_CNT_BALLOTS);
    assert!(data.v_ballot_encryption_results.is_empty());

    let cnt_threads = data.cnt_threads.min(rayon::max_num_threads());

    //eprintln!("Creating pool for {cnt_threads} threads.");
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cnt_threads)
        .build()
        .unwrap();

    pool.install(|| {
        data.selectioned_ballots
            .par_iter()
            .map_init(
                || {
                    let ti = rayon::current_thread_index().unwrap_or(usize::MAX);
                    let aby_seed = ti.to_be_bytes();
                    Csprng::new(&aby_seed)
                },
                |csprng: &mut Csprng, selectioned_ballot| {
                    BallotEncryptionResult::from_selectioned_ballot(
                        csprng,
                        &data.fixed_parameters,
                        &data.h_ext,
                        &data.joint_election_public_key,
                        selectioned_ballot,
                        fn_name,
                    )
                },
            )
            .collect_into_vec(&mut data.v_ballot_encryption_results);
    });

    assert_eq!(data.selectioned_ballots.len(), PASS_BENCHFN_CNT_BALLOTS);
    assert_eq!(
        data.v_ballot_encryption_results.len(),
        PASS_BENCHFN_CNT_BALLOTS
    );
}

struct BallotEncryptionResult {
    ballot_nonce: crybi_Nonnegative_256,
    encrypted_ballot: EncryptedBallot,
}

impl BallotEncryptionResult {
    pub fn from_selectioned_ballot(
        csprng: &mut Csprng,
        fixed_parameters: &FixedParameters,
        h_ext: &HashesExt,
        joint_election_public_key: &JointElectionPublicKey,
        selectioned_ballot: &SelectionedBallot,
        fn_name: &str,
    ) -> Self {
        let ballot_style_ix = selectioned_ballot.ballot_style_ix;
        let ballot_style: &BallotStyle = &BALLOT_STYLES.get(ballot_style_ix).unwrap();

        let ballot_nonce: crybi_Nonnegative_256 = random_nn_256(csprng);
        let ballot_nonce_eg = eg::nonce::BallotNonce(ballot_nonce.to_be_bytes_arr());

        // Standard parameter 'p' in different formats.

        let p_bau64_Nonnegative_4096: bau64_Nonnegative_4096 = standard_parameter_p().into();
        let p_crybi_Nonnegative_4096: crybi_Nonnegative_4096 = (&p_bau64_Nonnegative_4096).into();
        let p_crybi_u4096: &::crypto_bigint::U4096 = p_crybi_Nonnegative_4096.as_ref();
        let p_bits = p_crybi_u4096.bits();
        assert_eq!(p_bits, 4096);

        let p_numbi_Nonnegative_4096: numbi_Nonnegative_4096 = numbi_Nonnegative_4096::from(&p_bau64_Nonnegative_4096);
        let p_numbi_biguint: &num_bigint::BigUint = p_numbi_Nonnegative_4096.borrow();
        assert_eq!(p_numbi_biguint.bits(), p_bits as u64);

        let short_circuit = false; //????
        if short_circuit {
            return BallotEncryptionResult {
                ballot_nonce,
                encrypted_ballot: EncryptedBallot {
                    ballot_style_ix,
                    encryptions: std::array::from_fn(|_| {
                        let alpha = p_crybi_Nonnegative_4096.clone(); //?
                        let beta = p_crybi_Nonnegative_4096.clone(); //?
                        FieldCiphertext { alpha, beta }}),
                },
            }
        };

        // Standard parameter 'g' in different formats.

        let g_bau64_Nonnegative_4096: bau64_Nonnegative_4096 = standard_parameter_g().into();
        let g_crybi_Nonnegative_4096: crybi_Nonnegative_4096 = (&g_bau64_Nonnegative_4096).into();
        let g_crybi_u4096: &::crypto_bigint::U4096 = g_crybi_Nonnegative_4096.as_ref();
        let g_bits = g_crybi_u4096.bits();
        assert_eq!(g_bits, 4096);

        let g_numbi_Nonnegative_4096: numbi_Nonnegative_4096 = g_bau64_Nonnegative_4096.into();
        let g_numbi_biguint: &num_bigint::BigUint = g_numbi_Nonnegative_4096.borrow();
        assert_eq!(g_numbi_biguint.bits(), g_bits as u64);

        let jepk_numbi_biguint: &num_bigint::BigUint = joint_election_public_key.joint_election_public_key.as_biguint();

        let encryptions = if fn_name == "encrypt_ballots_st" || fn_name == "encrypt_ballots_mt" {
            // don't use_crybi_dynresidue
            //eprintln_here();

            std::array::from_fn(|ballot_field_ix| {
                let (i, j) = ballot_style.ballot_contest_field_indices[ballot_field_ix];

                let cof_nonce_eg =
                BallotNonce::derive_contest_option_field_nonce(&ballot_nonce_eg, &h_ext, i, j);
                let cof_nonce = crybi_Nonnegative_256::from_be_bytes_arr(cof_nonce_eg.0);
                let cof_nonce_nb: numbi_Nonnegative_256 = cof_nonce.into();

                let alpha_bu = g_numbi_biguint.modpow(
                    cof_nonce_nb.borrow(), p_numbi_biguint);
                assert!(alpha_bu.bits() <= 4096);
                let alpha_nb: numbi_Nonnegative_4096 = alpha_bu.try_into().unwrap();
                let alpha = crybi_Nonnegative_4096::from(&alpha_nb);

                let field_value = selectioned_ballot.ballot_contest_field_values[ballot_field_ix];

                let cofn_plus_field_value_nb = cof_nonce_nb.wrapping_add_u8(field_value);

                let beta_bu = jepk_numbi_biguint.modpow(
                    cofn_plus_field_value_nb.borrow(),
                    p_numbi_biguint,
                );
                assert!(beta_bu.bits() <= 4096);
                let beta_nb: numbi_Nonnegative_4096 = beta_bu.try_into().unwrap();
                let beta: crybi_Nonnegative_4096 = beta_nb.into();

                FieldCiphertext { alpha, beta }
            })
        } else if fn_name == "encrypt_ballots_mt_mg" {
            // use_crybi_dynresidue
            //eprintln_there();

            let p_crypbi_dynresidueparams = standard_parameter_p_dynresidueparams_cloned();
            let g_crybi_dynresidue = standard_parameter_g_dynresidue_mod_p();

            let jepk_numbi_nn_4096: numbi_Nonnegative_4096 = jepk_numbi_biguint.try_into().unwrap();
    
            //let jepk_bau64_nn_4096 = bau64_Nonnegative_4096::from(jepk_numbi_nn_4096);
            let jepk_crybi_nn_4096 = crybi_Nonnegative_4096::from(jepk_numbi_nn_4096);
            let jepk_crybi: &::crypto_bigint::U4096 = jepk_crybi_nn_4096.as_ref();
            let jepk_crybi_dynresidue = crybi_DynResidue_4096::new(&jepk_crybi, p_crypbi_dynresidueparams);

            std::array::from_fn(|ballot_field_ix| {
                let (i, j) = ballot_style.ballot_contest_field_indices[ballot_field_ix];

                let cof_nonce_eg =
                    BallotNonce::derive_contest_option_field_nonce(&ballot_nonce_eg, &h_ext, i, j);
                let cof_nonce = crybi_Nonnegative_256::from_be_bytes_arr(cof_nonce_eg.0);
                //let cof_nonce_nb: numbi_Nonnegative_256 = cof_nonce.into();
                let cof_nonce_crybi = cof_nonce.into_inner();

                let alpha = g_crybi_dynresidue.pow(&cof_nonce_crybi);
                let alpha: crybi_Nonnegative_4096 = alpha.retrieve().into();

                // Beta

                let field_value = selectioned_ballot.ballot_contest_field_values[ballot_field_ix];

                //let cofn_plus_field_value_nb = cof_nonce_nb.wrapping_add_u8(field_value);
                let field_value = ::crypto_bigint::U256::from(field_value);
                let cofn_plus_field_value_crybi = cof_nonce_crybi.adc(&field_value, crypto_bigint::Limb(0)).0;

                let beta = jepk_crybi_dynresidue.pow(&cofn_plus_field_value_crybi);
                let beta: crybi_Nonnegative_4096 = beta.retrieve().into();

                FieldCiphertext { alpha, beta }
            })
        } else if fn_name == "encrypt_ballots_mt_mg_et" {
            // use_crybi_dynresidue
            //eprintln_there();

            let p_crypbi_dynresidueparams = standard_parameter_p_dynresidueparams_cloned();
            let g_crybi_dynresidue = standard_parameter_g_dynresidue_mod_p();

            let jepk_numbi_nn_4096: numbi_Nonnegative_4096 = jepk_numbi_biguint.try_into().unwrap();

            //let jepk_bau64_nn_4096 = bau64_Nonnegative_4096::from(jepk_numbi_nn_4096);
            let jepk_crybi_nn_4096 = crybi_Nonnegative_4096::from(jepk_numbi_nn_4096);

            let p_exptable = standard_parameter_exptable_g_p_4();
            let jepk_exptable = ExpTable4096::new(
                jepk_crybi_nn_4096,
                standard_parameter_p_dynresidueparams_cloned(),
                4 ).unwrap();

            std::array::from_fn(|ballot_field_ix| {
                let (i, j) = ballot_style.ballot_contest_field_indices[ballot_field_ix];

                let cof_nonce_eg =
                    BallotNonce::derive_contest_option_field_nonce(&ballot_nonce_eg, &h_ext, i, j);
                let cof_nonce = crybi_Nonnegative_256::from_be_bytes_arr(cof_nonce_eg.0);
                //let cof_nonce_nb: numbi_Nonnegative_256 = cof_nonce.into();
                let cof_nonce_crybi = cof_nonce.into_inner();

                let alpha = p_exptable.pow(cof_nonce_crybi).unwrap();
                let alpha: crybi_Nonnegative_4096 = alpha.retrieve().into();

                // Beta

                let field_value = selectioned_ballot.ballot_contest_field_values[ballot_field_ix];

                //let cofn_plus_field_value_nb = cof_nonce_nb.wrapping_add_u8(field_value);
                let field_value = ::crypto_bigint::U256::from(field_value);
                let cofn_plus_field_value_crybi = cof_nonce_crybi.adc(&field_value, crypto_bigint::Limb(0)).0;

                let beta = jepk_exptable.pow(cofn_plus_field_value_crybi).unwrap();
                let beta: crybi_Nonnegative_4096 = beta.retrieve().into();

                FieldCiphertext { alpha, beta }
            })
        } else {
            assert_eq!(fn_name, "didn't match");
            todo!();
        };

        BallotEncryptionResult {
            ballot_nonce,
            encrypted_ballot: EncryptedBallot {
                ballot_style_ix,
                encryptions,
            },
        }
    }
}
