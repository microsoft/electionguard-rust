// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(clippy::expect_used)] // This is `cfg(test)` code
#![allow(clippy::manual_assert)] // This is `cfg(test)` code
#![allow(clippy::new_without_default)] // This is `cfg(test)` code
#![allow(clippy::panic)] // This is `cfg(test)` code
#![allow(clippy::unwrap_used)] // This is `cfg(test)` code
#![allow(clippy::assertions_on_constants)]
#![allow(non_snake_case)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::collections::BTreeMap;

use util::csrng::{self, Csrng};

use crate::{
    ballot::Ballot,
    ballot::BallotNonce_xi_B,
    ballot_style::BallotStyleIndex,
    chaining_mode::ChainingField,
    contest_option_fields::ContestOptionFieldsPlaintexts,
    eg::Eg,
    election_manifest::ContestIndex,
    errors::{EgError, EgResult},
    hash::HValue,
    validatable::Validated,
    voter_selections_plaintext::{VoterSelectionsPlaintext, VoterSelectionsPlaintextInfo},
    voting_device::{VotingDeviceInformation, VotingDeviceInformationHash},
    zk::ZkProofRangeError,
};

fn test_verify_ballot_common(
    csprng_seed_str: &str,
    ballot_style_ix: BallotStyleIndex,
    contests_option_fields_plaintexts: BTreeMap<ContestIndex, ContestOptionFieldsPlaintexts>,
) -> EgResult<()> {
    let eg =
        &Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(csprng_seed_str);

    let election_manifest = eg.election_manifest()?;
    let election_manifest = election_manifest.as_ref();

    let ballot_style = election_manifest.get_ballot_style_validate_ix(ballot_style_ix)?;

    let h_e = eg.extended_base_hash()?.h_e().clone();

    let voter_selections_plaintext = VoterSelectionsPlaintext::try_validate_from(
        VoterSelectionsPlaintextInfo {
            h_e,
            ballot_style_ix,
            contests_option_fields_plaintexts,
        },
        eg,
    )?;

    let vdi = VotingDeviceInformation::new_empty();

    let h_di = VotingDeviceInformationHash::compute_from_voting_device_information(eg, &vdi)?;

    let chaining_field_B_C = ChainingField::new_no_chaining_mode(&h_di).unwrap();

    let ballot_nonce_xi_B = BallotNonce_xi_B::generate_random(eg.csrng());

    // This validates the ballot proofs.
    let ballot = Ballot::try_new(
        eg,
        voter_selections_plaintext,
        &chaining_field_B_C,
        Some(ballot_nonce_xi_B),
    )?;

    // Verify the ballot proofs again to exercise this possibly-different code path.
    Ballot::validate_contests_data_fields_ciphertexts_to_ballot_style(
        eg,
        ballot_style,
        ballot.contests_data_fields_ciphertexts(),
        Some(ballot_style_ix),
    )?;

    Ok(())
}

#[test]
fn test_verify_ballotstyle1_contest1_votes_0_0() -> EgResult<()> {
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle1_contest1_votes_0_0",
        1.try_into()?,
        [(
            1.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle1_contest1_votes_0_1() -> EgResult<()> {
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle1_contest1_votes_0_1",
        1.try_into()?,
        [(
            1.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 1])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle1_contest1_votes_1_0() -> EgResult<()> {
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle1_contest1_votes_1_0",
        1.try_into()?,
        [(
            1.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle1_contest1_votes_1_1() -> EgResult<()> {
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle1_contest1_votes_1_1",
        1.try_into()?,
        [(
            1.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle5_contest5_votes_0_0_0_0_0_0() -> EgResult<()> {
    let ballot_style_ix = 5.try_into()?;
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle5_contest5_votes_0_0_0_0_0_0",
        ballot_style_ix,
        [(
            5.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0, 0, 0, 0, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle5_contest5_votes_0_0_0_0_0_1() -> EgResult<()> {
    let ballot_style_ix = 5.try_into()?;
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle5_contest5_votes_0_0_0_0_0_1",
        ballot_style_ix,
        [(
            5.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0, 0, 0, 0, 1])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle5_contest5_votes_0_0_0_0_1_0() -> EgResult<()> {
    let ballot_style_ix = 5.try_into()?;
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle5_contest5_votes_0_0_0_0_1_0",
        ballot_style_ix,
        [(
            5.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0, 0, 0, 1, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle5_contest5_votes_0_0_0_1_0_0() -> EgResult<()> {
    let ballot_style_ix = 5.try_into()?;
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle5_contest5_votes_0_0_0_1_0_0",
        ballot_style_ix,
        [(
            5.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0, 0, 1, 0, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle5_contest5_votes_0_0_1_0_0_0() -> EgResult<()> {
    let ballot_style_ix = 5.try_into()?;
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle5_contest5_votes_0_0_1_0_0_0",
        ballot_style_ix,
        [(
            5.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0, 1, 0, 0, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle5_contest5_votes_0_1_0_0_0_0() -> EgResult<()> {
    let ballot_style_ix = 5.try_into()?;
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle5_contest5_votes_0_1_0_0_0_0",
        ballot_style_ix,
        [(
            5.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 1, 0, 0, 0, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle5_contest5_votes_1_0_0_0_0_0() -> EgResult<()> {
    let ballot_style_ix = 5.try_into()?;
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle5_contest5_votes_1_0_0_0_0_0",
        ballot_style_ix,
        [(
            5.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0, 0, 0, 0, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle5_contest5_votes_1_0_0_0_0_1_range_proof_error() -> EgResult<()> {
    let ballot_style_ix = 5.try_into()?;
    let result = test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle5_contest5_votes_1_0_0_0_0_1_range_proof_error",
        ballot_style_ix,
        [(
            5.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0, 0, 0, 0, 1])?,
        )]
        .into(),
    );
    assert!(matches!(
        result,
        Err(EgError::ProofError(ZkProofRangeError::RangeNotSatisfied {
            small_l: 2,
            big_l: 1
        }))
    ));
    Ok(())
}

#[test]
fn test_verify_ballotstyle6_contest6_votes_0_0() -> EgResult<()> {
    let ballot_style_ix = 6.try_into()?;
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle6_contest6_votes_0_0",
        ballot_style_ix,
        [(
            6.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle6_contest6_votes_0_1() -> EgResult<()> {
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle6_contest6_votes_0_1",
        6.try_into()?,
        [(
            6.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([0_u8, 1])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle6_contest6_votes_1_0() -> EgResult<()> {
    let ballot_style_ix = 6.try_into()?;
    test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle6_contest6_votes_1_0",
        ballot_style_ix,
        [(
            6.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle6_contest6_votes_1_1_range_proof_error() {
    let result = test_verify_ballot_common(
        "eg::ballot_test_verify::test_verify_ballotstyle6_contest6_votes_1_1_range_proof_error",
        6.try_into().unwrap(),
        [(
            6.try_into().unwrap(),
            ContestOptionFieldsPlaintexts::try_new_from([1_u8, 1]).unwrap(),
        )]
        .into(),
    );
    assert!(matches!(
        result,
        Err(EgError::ProofError(ZkProofRangeError::RangeNotSatisfied {
            small_l: 2,
            big_l: 1
        }))
    ));
}
