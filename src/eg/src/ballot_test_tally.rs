// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(clippy::assertions_on_constants)]
#![allow(clippy::expect_used)] // This is `cfg(test)` code
#![allow(clippy::manual_assert)] // This is `cfg(test)` code
#![allow(clippy::new_without_default)] // This is `cfg(test)` code
#![allow(clippy::panic)] // This is `cfg(test)` code
#![allow(clippy::unwrap_used)] // This is `cfg(test)` code
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::collections::BTreeMap;
use std::iter::zip;
use std::ops::DerefMut;
use std::rc::Rc;
use std::time::{Duration, Instant};

use strum::{EnumCount, VariantArray};
use util::{algebra::FieldElement, csrng::Csrng, index::Index, uint53::Uint53, vec1::Vec1};

use crate::errors::EgError;
use crate::{
    ballot::Ballot,
    ballot::BallotNonce_xi_B,
    chaining_mode::ChainingField,
    ciphertext::Ciphertext,
    contest_data_fields_plaintexts::ContestDataFieldIndex,
    contest_data_fields_tallies::{ContestDataFieldTally, ContestTallies},
    contest_option_fields::ContestOptionFieldsPlaintexts,
    eg::{Eg, EgConfig},
    election_manifest::ContestIndex,
    election_parameters::ElectionParameters,
    election_tallies::ElectionTallies,
    errors::EgResult,
    guardian::GuardianKeyPurpose,
    guardian_public_key::GuardianPublicKey,
    guardian_secret_key::GuardianSecretKey,
    guardian_share::{GuardianEncryptedShare, GuardianSecretKeyShare},
    hash::HValue,
    pre_voting_data::PreVotingData,
    validatable::Validated,
    verifiable_decryption::{
        CombinedDecryptionShare, DecryptionProof, DecryptionShare, VerifiableDecryption,
    },
    voter_selections_plaintext::VoterSelectionsPlaintext,
    voting_device::{VotingDeviceInformation, VotingDeviceInformationHash},
};

/// This function takes an iterator over encrypted ballots and tallies up the
/// votes on each option in each contest. The result is map from `ContestIndex`
/// to `Vec<Ciphertext>` that given a contest index gives the encrypted result
/// for the contest, namely a vector of encrypted tallies; one for each option
/// in the contest.
pub fn tally_ballots(
    encrypted_ballots: impl IntoIterator<Item = crate::ballot_scaled::BallotScaled>,
    pre_voting_data: &PreVotingData,
) -> Option<BTreeMap<ContestIndex, Vec<Ciphertext>>> {
    let mut result = BallotTallyBuilder::new(pre_voting_data);

    for ballot in encrypted_ballots {
        if !result.update(ballot) {
            return None;
        }
    }
    Some(result.finalize())
}

/// A builder to contest_tallies_encrypted ballots incrementally.
pub struct BallotTallyBuilder<'a> {
    pre_voting_data: &'a PreVotingData,
    state: BTreeMap<ContestIndex, Vec<Ciphertext>>,
}

impl<'a> BallotTallyBuilder<'a> {
    pub fn new(pre_voting_data: &'a PreVotingData) -> Self {
        Self {
            pre_voting_data,
            state: BTreeMap::new(),
        }
    }

    /// Conclude the tallying and get the result.
    pub fn finalize(self) -> BTreeMap<ContestIndex, Vec<Ciphertext>> {
        self.state
    }

    /// Update the contest_tallies_encrypted with a new ballot. Returns whether the
    /// new ballot was compatible with the contest_tallies_encrypted. If `false` is returned then
    /// the contest_tallies_encrypted is not updated.
    pub fn update(&mut self, ballot: crate::ballot_scaled::BallotScaled) -> bool {
        let group = self
            .pre_voting_data
            .election_parameters()
            .fixed_parameters()
            .group();
        for (idx, contest) in ballot.contests {
            let Some(manifest_contest) =
                self.pre_voting_data.election_manifest().contests().get(idx)
            else {
                return false;
            };

            if contest.selection.len() != manifest_contest.contest_options.len() {
                return false;
            }

            if let Some(v) = self.state.get_mut(&idx) {
                for (j, encryption) in contest.selection.iter().enumerate() {
                    v[j].alpha = v[j].alpha.mul(&encryption.alpha, group);
                    v[j].beta = v[j].beta.mul(&encryption.beta, group);
                }
            } else {
                self.state.insert(idx, contest.selection);
            }
        }
        true
    }
}

// This test is too expensive to run in non --release builds, but requiring `not(debug_assertions)`
// disables it in `rust-analyzer` too. Allowing 'miri' seems to keep it visible in the code editor.
#[cfg(test)]
//x TODO figure this out #[cfg(any(not(debug_assertions), miri))]
//x TODO figure this out #[cfg(target_pointer_width = "16")]
#[allow(non_snake_case)]
fn test_check_verify_ballot() -> EgResult<()> {
    let varying_parameter_n = 5;
    let varying_parameter_k = 3;

    let eg = &{
        let mut config = EgConfig::new();
        config.use_insecure_deterministic_csprng_seed_str(
            "eg::guardian_share::test::test_encryption_decryption",
        );
        config.enable_test_data_generation_n_k(varying_parameter_n, varying_parameter_k)?;
        Eg::from(config)
    };

    let election_manifest = eg.election_manifest()?;
    let election_manifest = election_manifest.as_ref();

    let election_parameters = eg.election_parameters()?;
    let election_parameters = election_parameters.as_ref();

    let extended_base_hash = eg.extended_base_hash()?;
    let h_e = extended_base_hash.h_e().clone();

    let vdi = VotingDeviceInformation::new_empty();

    let h_di = VotingDeviceInformationHash::compute_from_voting_device_information(eg, &vdi)?;

    let ballot_style_ix = 1.try_into()?;

    let ballot_style = election_manifest.get_ballot_style_validate_ix(ballot_style_ix)?;
    assert_eq!(ballot_style.get_ballot_style_ix()?, ballot_style_ix);

    let contests_option_fields_plaintexts = BTreeMap::from([
        // Voting Ballot style 1 has 1 contest: 1
        (
            1.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 1]).unwrap(),
        ),
    ]);

    let csrng = eg.csrng();

    for pregenerate_ballot_nonce in [false, true] {
        let voter_selections_plaintext = VoterSelectionsPlaintext::try_validate_from(
            crate::voter_selections_plaintext::VoterSelectionsPlaintextInfo {
                h_e: h_e.clone(),
                ballot_style_ix,
                contests_option_fields_plaintexts: contests_option_fields_plaintexts.clone(),
            },
            eg,
        )?;

        assert_eq!(
            voter_selections_plaintext.ballot_style_ix(),
            ballot_style_ix
        );

        let opt_ballot_nonce_xi_B =
            pregenerate_ballot_nonce.then(|| BallotNonce_xi_B::generate_random(csrng));

        let chaining_field_B_C = ChainingField::new_no_chaining_mode(&h_di).unwrap();

        // This validates the ballot proofs.
        let ballot = Ballot::try_new(
            eg,
            voter_selections_plaintext,
            &chaining_field_B_C,
            opt_ballot_nonce_xi_B,
        )?;
        assert_eq!(ballot_style_ix, ballot.ballot_style_ix());

        // Verify the ballot proofs again to exercise this possibly-different code path.
        Ballot::validate_contests_data_fields_ciphertexts_to_ballot_style(
            eg,
            ballot_style,
            ballot.contests_data_fields_ciphertexts(),
            Some(ballot_style_ix),
        )?;
    }

    Ok(())
}

#[derive(Clone, Default, derive_more::AddAssign)]
struct OpDurations {
    combine: Duration,
    gen_resp: Duration,
    comb_proof: Duration,
    verif_dec: Duration,
}

fn decryption_helper(
    eg: &Eg,
    key_purpose: GuardianKeyPurpose,
    contest_ix: ContestIndex,
    contest_data_field_ix: ContestDataFieldIndex,
    key_shares: &[GuardianSecretKeyShare],
    ciphertext: &Ciphertext,
    guardian_public_keys: &[&GuardianPublicKey],
) -> EgResult<(VerifiableDecryption, OpDurations)> {
    let mut inst_start = Instant::now();

    let pre_voting_data = eg.pre_voting_data()?;
    let pre_voting_data = pre_voting_data.as_ref();
    let election_parameters = pre_voting_data.election_parameters();
    let fixed_parameters = election_parameters.fixed_parameters();

    // Scope for where we take ownership of the (necessarily mutable) csprng from
    // eg and then make shared borrows on it.
    let (dec_shares, combined_dec_share, com_shares, com_states, combine) = {
        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|ks| DecryptionShare::from(fixed_parameters, ks, ciphertext))
            .collect();

        let combined_dec_share =
            CombinedDecryptionShare::combine(election_parameters, &dec_shares).unwrap();

        let combine = inst_start.elapsed();
        inst_start = Instant::now();

        let mut com_shares = vec![];
        let mut com_states = vec![];
        for ks in key_shares.iter() {
            let (share, state) = DecryptionProof::generate_commit_share(
                eg.csrng(),
                fixed_parameters,
                ciphertext,
                ks.guardian_ix,
            );
            com_shares.push(share);
            com_states.push(state);
        }

        (
            dec_shares,
            combined_dec_share,
            com_shares,
            com_states,
            combine,
        )
    };

    // Scope for shared borrows into `eg`.
    let rsp_shares: Vec<_> = {
        com_states
            .iter()
            .zip(key_shares)
            .map(|(state, key_share)| {
                DecryptionProof::generate_response_share(
                    eg,
                    contest_ix,
                    contest_data_field_ix,
                    ciphertext,
                    &combined_dec_share,
                    &com_shares,
                    state,
                    key_share,
                )
                .unwrap()
            })
            .collect()
    };

    let gen_resp = inst_start.elapsed();
    inst_start = Instant::now();

    let proof = DecryptionProof::combine_proof(
        eg,
        contest_ix,
        contest_data_field_ix,
        ciphertext,
        &dec_shares,
        &com_shares,
        &rsp_shares,
        guardian_public_keys,
    )
    .unwrap();

    let comb_proof = inst_start.elapsed();
    inst_start = Instant::now();

    let verif_dec = VerifiableDecryption::new(
        fixed_parameters,
        pre_voting_data.jvepk_k(),
        ciphertext,
        &combined_dec_share,
        &proof,
    )
    .unwrap();

    Ok((
        verif_dec,
        OpDurations {
            combine,
            gen_resp,
            comb_proof,
            verif_dec: inst_start.elapsed(),
        },
    ))
}

/// Testing that encrypted tallies decrypt the expected result
#[test]
//x TODO figure this out #[cfg(any(not(debug_assertions), miri))]
#[allow(non_snake_case)]
#[allow(unreachable_code)]
fn test_tally_ballots() -> EgResult<()> {
    use std::thread;

    use anyhow::{anyhow, bail, Context};

    let mut inst_start = Instant::now();

    let eg = &Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
        "eg::ballot_test_tally::test_tally_ballots",
    );

    let pre_voting_data = eg.pre_voting_data()?;
    let pre_voting_data = pre_voting_data.as_ref();
    let election_parameters = pre_voting_data.election_parameters();
    let fixed_parameters = election_parameters.fixed_parameters();
    let group = fixed_parameters.group();
    let field = fixed_parameters.field();
    let election_manifest = pre_voting_data.election_manifest();
    let h_e = pre_voting_data.h_e();

    let csrng = eg.csrng();

    let xi_B_1 = BallotNonce_xi_B::generate_random(csrng);
    let xi_B_2 = BallotNonce_xi_B::generate_random(csrng);
    let xi_B_3 = BallotNonce_xi_B::generate_random(csrng);

    use GuardianKeyPurpose::*;

    // Get the each of the guardian public keys.

    let gdns_pubkeys_encr_ballot_votes =
        eg.guardian_public_keys(Encrypt_Ballot_NumericalVotesAndAdditionalDataFields)?;
    let gdns_pubkeys_encr_ballot_votes = gdns_pubkeys_encr_ballot_votes.map_into(Rc::as_ref);

    //let gdns_pubkeys_encr_ballot_addldata = eg.guardian_public_keys(Encrypt_Ballot_AdditionalFreeFormData)?;
    //let gdns_pubkeys_encr_ballot_addldata = gdns_pubkeys_encr_ballot_addldata.map_into(Rc::as_ref);

    //let gdns_pubkeys_encr_interguardiancomms = eg.guardian_public_keys(Encrypt_InterGuardianCommunication)?;
    //let gdns_pubkeys_encr_interguardiancomms = gdns_pubkeys_encr_interguardiancomms.map_into(Rc::as_ref);

    // Get the each of the guardian public keys.

    let gdns_seckeys_encr_ballot_votes =
        eg.guardians_secret_keys(Encrypt_Ballot_NumericalVotesAndAdditionalDataFields)?;
    let gdns_seckeys_encr_ballot_votes = gdns_seckeys_encr_ballot_votes.map_into(Rc::as_ref);

    //let gdns_seckeys_encr_ballot_addldata = eg.guardians_secret_keys(Encrypt_Ballot_AdditionalFreeFormData)?;
    //let gdns_seckeys_encr_ballot_addldata = gdns_seckeys_encr_ballot_addldata.map_into(Rc::as_ref);

    //let gdns_seckeys_encr_interguardiancomms = eg.guardians_secret_keys(Encrypt_InterGuardianCommunication)?;
    //let gdns_seckeys_encr_interguardiancomms = gdns_seckeys_encr_interguardiancomms.map_into(Rc::as_ref);

    let vdi = VotingDeviceInformation::new_empty();

    let h_di = VotingDeviceInformationHash::compute_from_voting_device_information(eg, &vdi)?;

    eprintln!(
        "\npre ballot creation: {:.3} s",
        inst_start.elapsed().as_secs_f64()
    );
    inst_start = Instant::now();

    let ballot_1 = {
        // Voting Ballot style 15 has 2 contests: 1 and 3
        let ballot_style_ix = 15.try_into()?;
        let vspt = VoterSelectionsPlaintext::try_validate_from(
            crate::voter_selections_plaintext::VoterSelectionsPlaintextInfo {
                h_e: h_e.clone(),
                ballot_style_ix,
                contests_option_fields_plaintexts: BTreeMap::from([
                    (
                        1.try_into()?,
                        ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0]).unwrap(),
                    ),
                    (
                        3.try_into()?,
                        ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0, 1, 0]).unwrap(),
                    ),
                ]),
            },
            eg,
        )?;

        let chaining_field_B_C = ChainingField::new_no_chaining_mode(&h_di).unwrap();

        // This validates the ballot proofs.
        let ballot = Ballot::try_new(eg, vspt, &chaining_field_B_C, Some(xi_B_1))?;

        // Verify the ballot proofs again to exercise this possibly-different code path.
        Ballot::validate_contests_data_fields_ciphertexts_to_ballot_style(
            eg,
            election_manifest.get_ballot_style_validate_ix(ballot_style_ix)?,
            ballot.contests_data_fields_ciphertexts(),
            Some(ballot_style_ix),
        )?;

        ballot
    };

    eprintln!(
        "ballot 1 creation: {:.3} s",
        inst_start.elapsed().as_secs_f64()
    );
    inst_start = Instant::now();

    let ballot_2 = {
        // Voting Ballot style 16 has 2 contests: 2 and 3
        let ballot_style_ix = 16.try_into()?;
        let vspt = VoterSelectionsPlaintext::try_validate_from(
            crate::voter_selections_plaintext::VoterSelectionsPlaintextInfo {
                h_e: h_e.clone(),
                ballot_style_ix,
                contests_option_fields_plaintexts: BTreeMap::from([
                    (
                        2.try_into()?,
                        ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0, 1]).unwrap(),
                    ),
                    (
                        3.try_into()?,
                        ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0, 0, 0]).unwrap(),
                    ),
                ]),
            },
            eg,
        )?;

        let chaining_field_B_C = ChainingField::new_no_chaining_mode(&h_di).unwrap();

        // This validates the ballot proofs.
        let ballot = Ballot::try_new(eg, vspt, &chaining_field_B_C, Some(xi_B_2))?;

        // Verify the ballot proofs again to exercise this possibly-different code path.
        Ballot::validate_contests_data_fields_ciphertexts_to_ballot_style(
            eg,
            eg.election_manifest()?
                .get_ballot_style_validate_ix(ballot_style_ix)?,
            ballot.contests_data_fields_ciphertexts(),
            Some(ballot_style_ix),
        )?;

        ballot
    };

    eprintln!(
        "ballot 2 creation: {:.3} s",
        inst_start.elapsed().as_secs_f64()
    );
    inst_start = Instant::now();

    let ballot_3 = {
        // Voting Ballot style 17 has 3 contests: 1, 2, and 3
        let ballot_style_ix = 17.try_into()?;
        let vspt = VoterSelectionsPlaintext::try_validate_from(
            crate::voter_selections_plaintext::VoterSelectionsPlaintextInfo {
                h_e: h_e.clone(),
                ballot_style_ix,
                contests_option_fields_plaintexts: BTreeMap::from([
                    (
                        1.try_into()?,
                        ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0]).unwrap(),
                    ),
                    (
                        2.try_into()?,
                        ContestOptionFieldsPlaintexts::try_new_from([0_u8, 1, 0]).unwrap(),
                    ),
                    (
                        3.try_into()?,
                        ContestOptionFieldsPlaintexts::try_new_from([0_u8, 1, 0, 0]).unwrap(),
                    ),
                ]),
            },
            eg,
        )?;

        let chaining_field_B_C = ChainingField::new_no_chaining_mode(&h_di).unwrap();

        // This validates the ballot proofs.
        let ballot = Ballot::try_new(eg, vspt, &chaining_field_B_C, Some(xi_B_3))?;

        // Verify the ballot proofs again to exercise this possibly-different code path.
        Ballot::validate_contests_data_fields_ciphertexts_to_ballot_style(
            eg,
            eg.election_manifest()?
                .get_ballot_style_validate_ix(ballot_style_ix)?,
            ballot.contests_data_fields_ciphertexts(),
            Some(ballot_style_ix),
        )?;

        ballot
    };

    eprintln!(
        "ballot 3 creation: {:.3} s",
        inst_start.elapsed().as_secs_f64()
    );
    inst_start = Instant::now();

    let scaled_ballots = {
        let scale_factor = FieldElement::from(1u8, field);
        vec![
            ballot_1.scale(fixed_parameters, &scale_factor),
            ballot_2.scale(fixed_parameters, &scale_factor),
            ballot_3.scale(fixed_parameters, &scale_factor),
        ]
    };

    let cnt_ballots = scaled_ballots.len();
    eprintln!(
        "scale {cnt_ballots} ballots: {:.3} s",
        inst_start.elapsed().as_secs_f64()
    );
    inst_start = Instant::now();

    let contest_tallies_encrypted = tally_ballots(scaled_ballots, pre_voting_data).unwrap();

    eprintln!(
        "contest_tallies_encrypted {cnt_ballots} ballots: {:.3} s",
        inst_start.elapsed().as_secs_f64()
    );
    inst_start = Instant::now();

    // Decryption
    let share_vecs: Vec<Vec<GuardianEncryptedShare>> = gdns_pubkeys_encr_ballot_votes
        .iter()
        .map(|&pk| {
            gdns_seckeys_encr_ballot_votes
                .iter()
                .map(|&dealer_sk| {
                    GuardianEncryptedShare::encrypt(csrng, election_parameters, dealer_sk, pk)
                        .unwrap()
                        .ciphertext
                })
                .collect::<Vec<GuardianEncryptedShare>>()
        })
        .collect();

    let cnt_share_vecs = share_vecs.len();
    eprintln!(
        "share encrypt from {cnt_share_vecs} guardians: {:.3} s",
        inst_start.elapsed().as_secs_f64()
    );

    let key_shares: Vec<GuardianSecretKeyShare> =
        zip(gdns_seckeys_encr_ballot_votes.iter(), &share_vecs)
            .map(|(&sk, shares)| {
                GuardianSecretKeyShare::generate(
                    eg,
                    gdns_pubkeys_encr_ballot_votes.as_slice(),
                    shares,
                    sk,
                )
                .unwrap()
            })
            .collect();

    eprintln!(
        "compute {} key shares: {:.3} s",
        key_shares.len(),
        inst_start.elapsed().as_secs_f64()
    );

    let mut cnt_contests = 0_usize;
    let mut cnt_ciphertexts = 0_usize;
    let mut decryption_dur = Duration::ZERO;
    let mut verification_dur = Duration::ZERO;
    let mut op_dur = OpDurations::default();

    let mut contest_tallies = ContestTallies::vec1_for_all_contests_zeroed(election_manifest)?;

    let inst_start_clock = Instant::now();

    for (contest_ix, contest_tally_encrypted) in contest_tallies_encrypted {
        cnt_contests += 1;

        let contest_tally = contest_tallies
            .get_mut(contest_ix)
            .ok_or_else(|| anyhow::anyhow!("Contest tallies missing entry for {contest_ix}"))?;

        for (data_field_ix0, contest_data_field_tally_ciphertext) in
            contest_tally_encrypted.iter().enumerate()
        {
            let contest_data_field_ix =
                ContestDataFieldIndex::try_from_zero_based_index(data_field_ix0)?;

            cnt_ciphertexts += 1;

            let inst_start_dec = Instant::now();

            let (dec, op_durations) = decryption_helper(
                eg,
                Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
                contest_ix,
                contest_data_field_ix,
                &key_shares,
                contest_data_field_tally_ciphertext,
                gdns_pubkeys_encr_ballot_votes.as_slice(),
            )?;
            let dec_dur = inst_start_dec.elapsed();
            eprintln!(
                "decrypt contest {contest_ix} data field {contest_data_field_ix}: {:.3} s",
                dec_dur.as_secs_f64()
            );
            decryption_dur += dec_dur;
            op_dur += op_durations;

            let inst_start_ver = Instant::now();
            assert!(dec.verify(
                fixed_parameters,
                pre_voting_data.h_e(),
                pre_voting_data.jvepk_k(),
                contest_ix,
                contest_data_field_ix,
                contest_data_field_tally_ciphertext
            ));

            let dec_plain_text_field_element = &dec.plaintext;
            assert!(dec_plain_text_field_element.is_valid(
                pre_voting_data
                    .election_parameters()
                    .fixed_parameters()
                    .field()
            ));

            let data_field_tally_u64 = u64::try_from(dec_plain_text_field_element)?;
            let data_field_tally_u53 = Uint53::try_from(data_field_tally_u64)?;
            let data_field_tally = ContestDataFieldTally::from(data_field_tally_u53);

            let ver_dur = inst_start_ver.elapsed();
            eprintln!(
                "verify decryption contest {contest_ix} data field {contest_data_field_ix}: {:.3} s",
                ver_dur.as_secs_f64()
            );
            verification_dur += ver_dur;

            let refmut_data_field_tally: &mut ContestDataFieldTally = contest_tally
                .get_mut(contest_data_field_ix)
                .ok_or_else(|| anyhow::anyhow!("Contest tallies contest {contest_ix} missing entry for data field {contest_data_field_ix}"))?;
            assert_eq!(Uint53::from(*refmut_data_field_tally), Uint53::zero());

            *refmut_data_field_tally = data_field_tally_u64.try_into()?;
        }
    }

    {
        let clock_total = inst_start_clock.elapsed();
        let clock_total_s = clock_total.as_secs_f64();
        let clock_contest_avg_s = clock_total
            .checked_div(cnt_contests as u32)
            .unwrap_or_default()
            .as_secs_f64();
        eprintln!(
            "decrypted and verified {cnt_contests} contests in {clock_total_s:.3} s, avg {clock_contest_avg_s:.3} s each"
        );

        let decryption_total_s = decryption_dur.as_secs_f64();
        let decryption_avg_s = decryption_dur
            .checked_div(cnt_ciphertexts as u32)
            .unwrap_or_default()
            .as_secs_f64();
        let verification_total_s = verification_dur.as_secs_f64();
        let verification_avg_s = verification_dur
            .checked_div(cnt_ciphertexts as u32)
            .unwrap_or_default()
            .as_secs_f64();
        eprintln!(
            "decrypt {cnt_ciphertexts} ciphertexts: {decryption_total_s:.3} s, avg {decryption_avg_s:.3} s each"
        );
        eprintln!(
            "verify {cnt_ciphertexts} decryptions: {verification_total_s:.3} s, avg {verification_avg_s:.3} s each"
        );
    }

    /*
    let expected_results: Vec1<ContestTallies> = vec![
        Vec1::<ContestDataFieldTally>::try_from([2_u8, 0])?.into(),
        //Vec1::ContestTallies::try_from_iter([0_u8, 1, 1])?.into(),
        //Vec1::ContestTallies::try_from_iter([1_u8, 1, 1, 0])?.into(),
    ]
    .try_into()?;
    */

    /*
    //let v1_u53: Vec1<Uint53> = [2, 0].try_into()?;
    let v1_cdft: Vec1<ContestDataFieldTally> = [2, 0].try_into()?; // v1_u53.into();
    let ct: ContestTallies = v1_cdft.into();
    let v1: Vec1<ContestTallies> = [
        [2, 0].try_into()?,
        [0, 1, 1].try_into()?,
    ].try_into()?;
    let expected_election_tallies: ElectionTallies = v1.into();
    // */

    eprintln!("vvvvvvvv contest tallies vvvvvvvv");
    for (contest_ix, contest_tallies) in contest_tallies.enumerate() {
        //let opt_expected_data_field_values: Option<ContestTallies> = expected_results.get(contest_ix);

        eprintln!("contest {contest_ix}:");
        for (data_field_ix, &data_field_value) in contest_tallies.enumerate() {
            eprintln!("    data field {data_field_ix}: {data_field_value}");
        }
    }
    eprintln!("^^^^^^^^ contest tallies ^^^^^^^^");

    Ok(())
}
