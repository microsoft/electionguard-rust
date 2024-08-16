// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(clippy::expect_used)] // This is `cfg(test)` code
#![allow(clippy::manual_assert)] // This is `cfg(test)` code
#![allow(clippy::new_without_default)] // This is `cfg(test)` code
#![allow(clippy::panic)] // This is `cfg(test)` code
#![allow(clippy::unwrap_used)] // This is `cfg(test)` code
#![allow(clippy::assertions_on_constants)]
#![allow(non_snake_case)]

use std::collections::BTreeMap;

use crate::{
    ballot::BallotEncrypted, ballot_style::BallotStyleIndex,
    contest_option_fields::ContestOptionFieldsPlaintexts, election_manifest::ContestIndex,
    election_parameters::ElectionParameters, errors::*,
    example_election_manifest::example_election_manifest,
    example_election_parameters::example_election_parameters,
    guardian_secret_key::GuardianSecretKey, hash::HValue, index::Index,
    pre_voting_data::PreVotingData, voter_selections_plaintext::VoterSelectionsPlaintext,
};

use util::csprng::Csprng;

//=================================================================================================|

fn g_key(election_parameters: &ElectionParameters, i: u32) -> GuardianSecretKey {
    let mut seed = Vec::new();
    let customization_data = format!("GuardianSecretKeyGenerate({})", i.clone());
    seed.extend_from_slice(&(customization_data.as_bytes().len() as u64).to_be_bytes());
    seed.extend_from_slice(customization_data.as_bytes());

    let mut csprng = Csprng::new(&seed);

    GuardianSecretKey::generate(
        &mut csprng,
        election_parameters,
        Index::from_one_based_index_const(i).unwrap(),
        None,
    )
}

fn test_verify_ballot_common(
    ballot_style_ix: BallotStyleIndex,
    contests_option_fields_plaintexts: BTreeMap<ContestIndex, ContestOptionFieldsPlaintexts>,
) -> EgResult<()> {
    let election_parameters = example_election_parameters();

    let sk1 = g_key(&election_parameters, 1);
    let sk2 = g_key(&election_parameters, 2);
    let sk3 = g_key(&election_parameters, 3);
    let sk4 = g_key(&election_parameters, 4);
    let sk5 = g_key(&election_parameters, 5);

    let pk1 = sk1.make_public_key();
    let pk2 = sk2.make_public_key();
    let pk3 = sk3.make_public_key();
    let pk4 = sk4.make_public_key();
    let pk5 = sk5.make_public_key();

    let guardian_public_keys = vec![pk1, pk2, pk3, pk4, pk5];

    let pre_voting_data = PreVotingData::try_from_parameters_manifest_gpks(
        election_parameters,
        example_election_manifest(),
        &guardian_public_keys,
    )?;

    let seed = b"electionguard-rust/src/eg/src/ballot_test_verify";
    let csprng = &mut Csprng::new(seed);

    let ballot_nonce_xi_B = HValue::from_csprng(csprng);

    let voter_selections_plaintext = VoterSelectionsPlaintext::try_new(
        &pre_voting_data,
        ballot_style_ix,
        contests_option_fields_plaintexts,
    )?;

    let ballot_from_selections = BallotEncrypted::try_from_ballot_selection_data_plaintext(
        &pre_voting_data,
        voter_selections_plaintext,
        Some(ballot_nonce_xi_B),
        csprng,
    )?;

    // Let's verify the ballot proofs.
    ballot_from_selections.verify(&pre_voting_data)?;

    Ok(())
}

#[test]
fn test_verify_ballotstyle1_contest1_votes_0_0() -> EgResult<()> {
    test_verify_ballot_common(
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
        ballot_style_ix,
        [(
            5.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0, 0, 0, 0, 1])?,
        )]
        .into(),
    );
    assert_eq!(
        result,
        Err(EgError::ProofError(ZkProofRangeError::RangeNotSatisfied {
            small_l: 2,
            big_l: 1
        }))
    );
    Ok(())
}

#[test]
fn test_verify_ballotstyle6_contest6_votes_0_0() -> EgResult<()> {
    let ballot_style_ix = 6.try_into()?;
    test_verify_ballot_common(
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
        ballot_style_ix,
        [(
            6.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0])?,
        )]
        .into(),
    )
}

#[test]
fn test_verify_ballotstyle6_contest6_votes_1_1_range_proof_error() -> EgResult<()> {
    let result = test_verify_ballot_common(
        6.try_into()?,
        [(
            6.try_into()?,
            ContestOptionFieldsPlaintexts::try_new_from([1_u8, 1])?,
        )]
        .into(),
    );
    assert_eq!(
        result,
        Err(EgError::ProofError(ZkProofRangeError::RangeNotSatisfied {
            small_l: 2,
            big_l: 1
        }))
    );
    Ok(())
}
