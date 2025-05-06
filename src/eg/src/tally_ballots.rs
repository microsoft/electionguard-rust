// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(clippy::assertions_on_constants)]
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

use std::{collections::BTreeMap, sync::Arc};

use crate::algebra::Group;

use crate::{ciphertext::Ciphertext, contest::ContestIndex, election_manifest::ElectionManifest};

//=================================================================================================|

/// Takes an iterator over encrypted ballots and tallies up the
/// votes on each option in each contest. The result is map from `ContestIndex`
/// to `Vec<Ciphertext>` that given a contest index gives the encrypted result
/// for the contest, namely a vector of encrypted tallies; one for each option
/// in the contest.
pub fn tally_ballots(
    encrypted_ballots: impl IntoIterator<Item = crate::ballot_scaled::BallotScaled>,
    election_manifest: &ElectionManifest,
    group: &Group,
) -> Option<BTreeMap<ContestIndex, Vec<Ciphertext>>> {
    let mut tally_builder = BallotTallyBuilder::new(election_manifest, group);

    for ballot in encrypted_ballots {
        if !tally_builder.update(ballot) {
            return None;
        }
    }

    Some(tally_builder.finalize())
}

/// A builder to contest_tallies_encrypted ballots incrementally.
pub struct BallotTallyBuilder<'a> {
    election_manifest: &'a ElectionManifest,
    group: &'a Group,
    state: BTreeMap<ContestIndex, Vec<Ciphertext>>,
}

impl<'a> BallotTallyBuilder<'a> {
    pub fn new(election_manifest: &'a ElectionManifest, group: &'a Group) -> Self {
        Self {
            election_manifest,
            group,
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
        //? TODO perform Ballot verifications?

        for (idx, contest) in ballot.contests {
            let Some(manifest_contest) = self.election_manifest.contests().get(idx) else {
                return false;
            };

            if contest.selection.len() != manifest_contest.contest_options.len() {
                return false;
            }

            if let Some(v) = self.state.get_mut(&idx) {
                for (j, encryption) in contest.selection.iter().enumerate() {
                    v[j].alpha = v[j].alpha.mul(&encryption.alpha, self.group);
                    v[j].beta = v[j].beta.mul(&encryption.beta, self.group);
                }
            } else {
                self.state.insert(idx, contest.selection);
            }
        }
        true
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::expect_used)] // This is `cfg(test)` code
#[allow(clippy::manual_assert)] // This is `cfg(test)` code
#[allow(clippy::new_without_default)] // This is `cfg(test)` code
#[allow(clippy::panic)] // This is `cfg(test)` code
#[allow(clippy::unwrap_used)] // This is `cfg(test)` code
mod t {
    use std::{
        iter::zip,
        time::{Duration, Instant},
    };

    use anyhow::{Context, Error, Result, anyhow, bail, ensure};
    use fut_lite::FutureExt;
    use futures_lite::{future as fut_lite, prelude::*, stream};
    use tracing::{
        debug, error, field::display as trace_display, info, info_span, instrument, trace,
        trace_span, warn,
    };
    use util::uint53::Uint53;

    use crate::{
        algebra::FieldElement,
        ballot::{Ballot, BallotNonce_xi_B},
        ballot_style::BallotStyleTrait,
        chaining_mode::ChainingField,
        ciphertext::Ciphertext,
        contest::ContestIndex,
        contest_data_fields::ContestDataFieldIndex,
        contest_data_fields_tallies::{ContestDataFieldTally, ContestTallies},
        contest_option_fields::ContestOptionFieldsPlaintexts,
        eg::{Eg, EgConfig},
        errors::EgResult,
        fixed_parameters::{FixedParametersTrait, FixedParametersTraitExt},
        guardian::{GuardianIndex, GuardianKeyPartId},
        guardian_public_key::GuardianPublicKey,
        guardian_public_key_trait::GuardianKeyInfoTrait,
        //?interguardian_share::{InterguardianShare, GuardianSecretKeyShare},
        key::{AsymmetricKeyPart, KeyPurpose},
        resource::{ProduceResource, ProduceResourceExt},
        resource_id::{
            ElectionDataObjectId as EdoId, ResourceFormat, ResourceId, ResourceIdFormat,
        },
        validatable::Validated,
        verifiable_decryption::{
            CombinedDecryptionShare, DecryptionProof, DecryptionProofResponseShare,
            DecryptionShare, VerifiableDecryption,
        },
        voter_selections_plaintext::VoterSelectionsPlaintext,
        voting_device::{VotingDeviceInformation, VotingDeviceInformationHash},
    };

    use super::*;

    // This test is too expensive to run in non --release builds, but requiring `not(debug_assertions)`
    // disables it in `rust-analyzer` too. Allowing 'miri' seems to keep it visible in the code editor.
    #[allow(non_snake_case)]
    fn test_check_verify_ballot() {
        async_global_executor::block_on(test_check_verify_ballot_async());
    }

    async fn test_check_verify_ballot_async() {
        let varying_parameter_n = 5;
        let varying_parameter_k = 3;

        let eg = {
            let mut config = EgConfig::new();
            config.use_insecure_deterministic_csprng_seed_str(
                "eg::interguardian_share::test::test_encryption_decryption",
            );
            config
                .enable_test_data_generation_n_k(varying_parameter_n, varying_parameter_k)
                .unwrap();
            Eg::from_config(config)
        };
        let eg = eg.as_ref();

        let election_manifest = eg.election_manifest().await.unwrap();
        let election_manifest = election_manifest.as_ref();

        //? let election_parameters = produce_resource.election_parameters().await.unwrap();
        //? let election_parameters = election_parameters.as_ref();

        let extended_base_hash = eg.extended_base_hash().await.unwrap();
        let h_e = extended_base_hash.h_e().clone();

        let vdi = VotingDeviceInformation::new_empty();

        let h_di = VotingDeviceInformationHash::compute_from_voting_device_information(eg, &vdi)
            .await
            .unwrap();

        let ballot_style_ix = 1.try_into().unwrap();

        let ballot_style = election_manifest
            .get_ballot_style_validate_ix(ballot_style_ix)
            .unwrap();
        assert_eq!(ballot_style.get_ballot_style_ix().unwrap(), ballot_style_ix);

        let contests_option_fields_plaintexts = BTreeMap::from([
            // Voting Ballot style 1 has 1 contest: 1
            (
                1.try_into().unwrap(),
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
            )
            .unwrap();

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
            )
            .await
            .unwrap();
            assert_eq!(ballot_style_ix, ballot.ballot_style_ix());

            // Verify the ballot proofs again to exercise this possibly-different code path.
            ballot_style
                .validate_contests_data_fields_ciphertexts(
                    eg,
                    ballot.contests_data_fields_ciphertexts(),
                    Some(ballot_style_ix),
                )
                .await
                .unwrap();
        }
    }

    #[derive(Clone, Default, derive_more::AddAssign)]
    struct OpDurations {
        combine: Duration,
        gen_resp: Duration,
        comb_proof: Duration,
        verif_dec: Duration,
    }

    /*
    async fn decryption_helper(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        _key_purpose: GuardianKeyPurpose,
        contest_ix: ContestIndex,
        contest_data_field_ix: ContestDataFieldIndex,
        secret_key_shares: &[GuardianSecretKeyShare],
        ciphertext: &Ciphertext,
        guardian_public_keys: &[&GuardianPublicKey],
    ) -> EgResult<(VerifiableDecryption, OpDurations)> {
        let mut inst_start = Instant::now();

        let election_parameters = produce_resource.election_parameters().await.unwrap();
        let election_parameters = election_parameters.as_ref();

        let fixed_parameters = produce_resource.fixed_parameters().await.unwrap();
        let fixed_parameters = fixed_parameters.as_ref();

        let dec_shares: Vec<_> = secret_key_shares
            .iter()
            .map(|ks| DecryptionShare::from(fixed_parameters, ks, ciphertext))
            .collect();

        let combined_dec_share =
            CombinedDecryptionShare::combine(election_parameters, &dec_shares).unwrap();

        let combine = inst_start.elapsed();
        inst_start = Instant::now();

        let mut decr_proof_commit_shares = vec![];
        let mut decr_proof_state_shares = vec![];
        for ks in secret_key_shares.iter() {
            let (share, state) = DecryptionProof::generate_commit_share(
                produce_resource.csrng(),
                fixed_parameters,
                ciphertext,
                ks.guardian_ix,
            );
            decr_proof_commit_shares.push(share);
            decr_proof_state_shares.push(state);
        }

        let mut rsp_shares: Vec<DecryptionProofResponseShare> =
            Vec::with_capacity(decr_proof_state_shares.len());
        for (state, key_share) in decr_proof_state_shares.iter().zip(secret_key_shares) {
            let rsp_share = DecryptionProof::generate_response_share(
                produce_resource,
                contest_ix,
                contest_data_field_ix,
                ciphertext,
                &combined_dec_share,
                &decr_proof_commit_shares,
                state,
                key_share,
            )
            .await
            .unwrap();
            rsp_shares.push(rsp_share);
        }

        let gen_resp = inst_start.elapsed();
        inst_start = Instant::now();

        let proof = DecryptionProof::combine_proof(
            produce_resource,
            contest_ix,
            contest_data_field_ix,
            ciphertext,
            &dec_shares,
            &decr_proof_commit_shares,
            &rsp_shares,
            guardian_public_keys,
        )
        .await
        .unwrap();

        let comb_proof = inst_start.elapsed();
        inst_start = Instant::now();

        let verif_dec =
            VerifiableDecryption::new(produce_resource, ciphertext, &combined_dec_share, &proof)
                .await
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
    // */

    // Testing that encrypted tallies decrypt to the expected result.
    #[test_log::test]
    #[ignore]
    fn t1_tally_ballots() {
        info!("test_tally_ballots() started");
        async_global_executor::block_on(async {
            use KeyPurpose::*;

            let mut inst_start = Instant::now();

            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::ballot_test_tally::test_tally_ballots",
            );
            let eg = eg.as_ref();

            let fixed_parameters = eg.fixed_parameters().await.unwrap();
            let fixed_parameters = fixed_parameters.as_ref();

            let varying_parameters = eg.varying_parameters().await.unwrap();
            let varying_parameters = varying_parameters.as_ref();

            let n: GuardianIndex = varying_parameters.n();

            let election_parameters = eg.election_parameters().await.unwrap();
            let election_parameters = election_parameters.as_ref();

            let csrng = eg.csrng();

            let group = fixed_parameters.group();
            //debug!("group {group:?}");

            let field = fixed_parameters.field();
            //debug!("field {field:?}");

            // Get the Joint Public Key, Guardian Public Keys, and Guardian Secret Keys used for encrypting votes.

            fn gkp(guardian_key_purpose: KeyPurpose) -> &'static str {
                match guardian_key_purpose {
                    KeyPurpose::Ballot_Votes => "Vote Encryption",
                    KeyPurpose::Ballot_OtherData => "Ballot Data Encryption",
                    KeyPurpose::InterGuardianCommunication => "Guardian Communication",
                }
            }

            for guardian_ix in GuardianIndex::iter_range_inclusive(GuardianIndex::one(), n) {
                //println!(
                //    "\nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv Guardian {guardian_ix}  vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
                //);

                for guardian_key_purpose in [
                    KeyPurpose::Ballot_Votes,
                    KeyPurpose::Ballot_OtherData,
                    KeyPurpose::InterGuardianCommunication,
                ] {
                    let gk_purpose: &'static str = gkp(guardian_key_purpose);

                    //println!("=================== {gk_purpose} ========================== ");

                    for asymmetric_key_part in
                        [AsymmetricKeyPart::Secret, AsymmetricKeyPart::Public]
                    {
                        //println!(
                        //    "\nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv Guardian {guardian_ix} {gk_purpose} {asymmetric_key_part} Key vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
                        //);

                        let key_part_id = GuardianKeyPartId {
                            guardian_ix,
                            key_purpose: guardian_key_purpose,
                            asymmetric_key_part,
                        };
                        //println!("key_part_id: {key_part_id:#?}");

                        let edo_id = EdoId::GuardianKeyPart(key_part_id);
                        //println!("edo_id: {edo_id:#?}");

                        let ridfmt = edo_id.validated_type_ridfmt();
                        println!("ridfmt: {ridfmt:#?}");

                        match asymmetric_key_part {
                            AsymmetricKeyPart::Secret => {
                                let secret_key = eg
                                .produce_resource_downcast_no_src::<crate::guardian_secret_key::GuardianSecretKey>(
                                    &ridfmt,
                                )
                                .await
                                .unwrap();
                                //println!("secret_key: {secret_key:#?}");
                            }
                            AsymmetricKeyPart::Public => {
                                let public_key = eg
                                .produce_resource_downcast_no_src::<crate::guardian_public_key::GuardianPublicKey>(
                                    &ridfmt,
                                )
                                .await
                                .unwrap();
                                //println!("public_key: {public_key:#?}");
                            }
                        }

                        //println!(
                        //    "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Guardian {guardian_ix} {gk_purpose} {asymmetric_key_part} Key ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
                        //);
                    }
                }

                //println!(
                //    "\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Guardian {guardian_ix}  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
                //);
            }

            for guardian_key_purpose in [KeyPurpose::Ballot_Votes, KeyPurpose::Ballot_OtherData] {
                let gk_purpose: &'static str = gkp(guardian_key_purpose);

                //println!(
                //    "\nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv {gk_purpose} Joint Public Key vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
                //);

                let edo_id = EdoId::JointPublicKey(guardian_key_purpose);
                //println!("edo_id: {edo_id:#?}");

                let ridfmt = edo_id.validated_type_ridfmt();
                //println!("ridfmt: {ridfmt:#?}");

                let joint_public_key = eg
                    .produce_resource_downcast_no_src::<crate::joint_public_key::JointPublicKey>(
                        &ridfmt,
                    )
                    .await
                    .unwrap();
                //println!("joint_public_key: {joint_public_key:#?}");

                //println!(
                //    "\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ {gk_purpose} Joint Public Key ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
                //);
            }

            let guardian_key_purpose = KeyPurpose::Ballot_Votes;
            let gk_purpose: &'static str = gkp(guardian_key_purpose);

            //println!("\n");
            let gsks = eg
                .guardians_secret_keys(guardian_key_purpose)
                .await
                .unwrap();
            let gsks = gsks.iter_map_into(Arc::as_ref);
            //for gsk in gsks {
            //    println!(
            //        "vvvvvvvvvvvvvvvv Guardian {} {gk_purpose} Secret Key vvvvvvvvvvvvvvvv",
            //        gsk.guardian_index()
            //    );
            //    println!("guardian_secret_key {gsk:?}");
            //    println!(
            //        "^^^^^^^^^^^^^^^^ Guardian {} {gk_purpose} Secret Key ^^^^^^^^^^^^^^^^",
            //        gsk.guardian_index()
            //    );
            //}

            println!("\n");
            let gpks = eg.guardian_public_keys(guardian_key_purpose).await.unwrap();
            let gpks = gpks.iter_map_into(Arc::as_ref);
            //for gpk in gpks {
            //    println!(
            //        "vvvvvvvvvvvvvvvv Guardian {} {gk_purpose} Public Key vvvvvvvvvvvvvvvv",
            //        gpk.guardian_index()
            //    );
            //    println!("guardian_public_key {guardian_key_purpose}: {gpk:?}");
            //    println!(
            //        "^^^^^^^^^^^^^^^^ Guardian {} {gk_purpose} Public Key ^^^^^^^^^^^^^^^^",
            //        gpk.guardian_index()
            //    );
            //}

            let extended_base_hash = eg.extended_base_hash().await.unwrap();
            let extended_base_hash = extended_base_hash.as_ref();
            let h_e = extended_base_hash.h_e();
            //println!("\nh_e: {h_e:?}");

            let election_manifest = eg.election_manifest().await.unwrap();
            let election_manifest = election_manifest.as_ref();
            //println!("\nelection_manifest: done");

            let joint_vote_encryption_public_key_k =
                eg.joint_vote_encryption_public_key_k().await.unwrap();
            //println!("\njoint_vote_encryption_public_key_k: {joint_vote_encryption_public_key_k:#?}");

            let joint_ballot_data_encryption_public_key_k_hat = eg
                .joint_ballot_data_encryption_public_key_k_hat()
                .await
                .unwrap();
            //println!(
            //    "\njoint_ballot_data_encryption_public_key_k_hat: {joint_ballot_data_encryption_public_key_k_hat:#?}"
            //);

            let gdns_seckeys_encr_ballot_votes = eg
                .guardians_secret_keys(guardian_key_purpose)
                .await
                .unwrap();
            let gdns_seckeys_encr_ballot_votes =
                gdns_seckeys_encr_ballot_votes.iter_map_into(Arc::as_ref);
            //debug!("gdns_seckeys_encr_ballot_votes: {gdns_seckeys_encr_ballot_votes:?}");

            let gdns_pubkeys_encr_ballot_votes =
                eg.guardian_public_keys(Ballot_Votes).await.unwrap();
            let gdns_pubkeys_encr_ballot_votes =
                gdns_pubkeys_encr_ballot_votes.iter_map_into(Arc::as_ref);

            /*
            // Get the Guardian Public Keys and Guardian Secret Keys used for encrypting inter-Guardian communications.

            //use GuardianKeyPurpose::Encrypt_InterGuardianCommunication;
            //let gdns_pubkeys_encr_interguardian_comms = produce_resource.guardian_public_keys(Encrypt_InterGuardianCommunication).unwrap();
            //let gdns_pubkeys_encr_interguardian_comms = gdns_pubkeys_encr_interguardian_comms.map_into(Arc::as_ref);

            //let gdns_seckeys_encr_interguardian_comms = eg.guardians_secret_keys(Encrypt_InterGuardianCommunication).unwrap();
            //let gdns_seckeys_encr_interguardian_comms = gdns_seckeys_encr_interguardian_comms.map_into(Arc::as_ref);
            // */

            let xi_B_1 = BallotNonce_xi_B::generate_random(csrng);
            let xi_B_2 = BallotNonce_xi_B::generate_random(csrng);
            let xi_B_3 = BallotNonce_xi_B::generate_random(csrng);

            let vdi = VotingDeviceInformation::new_empty();
            //println!("\nvdi: done");

            let h_di =
                VotingDeviceInformationHash::compute_from_voting_device_information(eg, &vdi)
                    .await
                    .unwrap();
            //println!("\nh_di: {h_di:?}");

            //println!(
            //    "\npre ballot creation: {:.3} s",
            //    inst_start.elapsed().as_secs_f64()
            //);
            inst_start = Instant::now();

            let ballot_1 = {
                // Voting Ballot style 15 has 2 contests: 1 and 3
                let ballot_style_ix = 15.try_into().unwrap();
                let vspt = VoterSelectionsPlaintext::try_validate_from(
                    crate::voter_selections_plaintext::VoterSelectionsPlaintextInfo {
                        h_e: h_e.clone(),
                        ballot_style_ix,
                        contests_option_fields_plaintexts: BTreeMap::from([
                            (
                                1.try_into().unwrap(),
                                ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0]).unwrap(),
                            ),
                            (
                                3.try_into().unwrap(),
                                ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0, 1, 0])
                                    .unwrap(),
                            ),
                        ]),
                    },
                    eg,
                )
                .unwrap();

                let chaining_field_B_C = ChainingField::new_no_chaining_mode(&h_di).unwrap();

                // This validates the ballot proofs.
                let ballot = Ballot::try_new(eg, vspt, &chaining_field_B_C, Some(xi_B_1))
                    .await
                    .unwrap();

                // Verify the ballot proofs again to exercise this possibly-different code path.
                {
                    let ballot_style = election_manifest
                        .get_ballot_style_validate_ix(ballot_style_ix)
                        .unwrap();
                    ballot_style
                        .validate_contests_data_fields_ciphertexts(
                            eg,
                            ballot.contests_data_fields_ciphertexts(),
                            Some(ballot_style_ix),
                        )
                        .await
                        .unwrap();
                }

                ballot
            };

            //println!(
            //    "ballot 1 creation: {:.3} s",
            //    inst_start.elapsed().as_secs_f64()
            //);
            inst_start = Instant::now();

            let ballot_2 = {
                // Voting Ballot style 16 has 2 contests: 2 and 3
                let ballot_style_ix = 16.try_into().unwrap();
                let vspt = VoterSelectionsPlaintext::try_validate_from(
                    crate::voter_selections_plaintext::VoterSelectionsPlaintextInfo {
                        h_e: h_e.clone(),
                        ballot_style_ix,
                        contests_option_fields_plaintexts: BTreeMap::from([
                            (
                                2.try_into().unwrap(),
                                ContestOptionFieldsPlaintexts::try_new_from([0_u8, 0, 1]).unwrap(),
                            ),
                            (
                                3.try_into().unwrap(),
                                ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0, 0, 0])
                                    .unwrap(),
                            ),
                        ]),
                    },
                    eg,
                )
                .unwrap();

                let chaining_field_B_C = ChainingField::new_no_chaining_mode(&h_di).unwrap();

                // This validates the ballot proofs.
                let ballot = Ballot::try_new(eg, vspt, &chaining_field_B_C, Some(xi_B_2))
                    .await
                    .unwrap();

                // Verify the ballot proofs again to exercise this possibly-different code path.
                {
                    let ballot_style = election_manifest
                        .get_ballot_style_validate_ix(ballot_style_ix)
                        .unwrap();
                    ballot_style
                        .validate_contests_data_fields_ciphertexts(
                            eg,
                            ballot.contests_data_fields_ciphertexts(),
                            Some(ballot_style_ix),
                        )
                        .await
                        .unwrap();
                }

                ballot
            };

            //println!(
            //    "ballot 2 creation: {:.3} s",
            //    inst_start.elapsed().as_secs_f64()
            //);
            inst_start = Instant::now();

            let ballot_3 = {
                // Voting Ballot style 17 has 3 contests: 1, 2, and 3
                let ballot_style_ix = 17.try_into().unwrap();
                let vspt = VoterSelectionsPlaintext::try_validate_from(
                    crate::voter_selections_plaintext::VoterSelectionsPlaintextInfo {
                        h_e: h_e.clone(),
                        ballot_style_ix,
                        contests_option_fields_plaintexts: BTreeMap::from([
                            (
                                1.try_into().unwrap(),
                                ContestOptionFieldsPlaintexts::try_new_from([1_u8, 0]).unwrap(),
                            ),
                            (
                                2.try_into().unwrap(),
                                ContestOptionFieldsPlaintexts::try_new_from([0_u8, 1, 0]).unwrap(),
                            ),
                            (
                                3.try_into().unwrap(),
                                ContestOptionFieldsPlaintexts::try_new_from([0_u8, 1, 0, 0])
                                    .unwrap(),
                            ),
                        ]),
                    },
                    eg,
                )
                .unwrap();

                let chaining_field_B_C = ChainingField::new_no_chaining_mode(&h_di).unwrap();

                // This validates the ballot proofs.
                let ballot = Ballot::try_new(eg, vspt, &chaining_field_B_C, Some(xi_B_3))
                    .await
                    .unwrap();

                // Verify the ballot proofs again to exercise this possibly-different code path.
                let ballot_style = election_manifest
                    .get_ballot_style_validate_ix(ballot_style_ix)
                    .unwrap();
                ballot_style
                    .validate_contests_data_fields_ciphertexts(
                        eg,
                        ballot.contests_data_fields_ciphertexts(),
                        Some(ballot_style_ix),
                    )
                    .await
                    .unwrap();

                ballot
            };

            //println!(
            //    "ballot 3 creation: {:.3} s",
            //    inst_start.elapsed().as_secs_f64()
            //);
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
            //println!(
            //    "scale {cnt_ballots} ballots: {:.3} s",
            //    inst_start.elapsed().as_secs_f64()
            //);
            inst_start = Instant::now();

            let contest_tallies_encrypted =
                tally_ballots(scaled_ballots, election_manifest, group).unwrap();

            //println!(
            //    "contest_tallies_encrypted {cnt_ballots} ballots: {:.3} s",
            //    inst_start.elapsed().as_secs_f64()
            //);
            inst_start = Instant::now();

            assert!(false, "TODO rework for EGDS 2.1.0");
            /*

            // Decryption
            let share_vecs: Vec<Vec<InterguardianShare>> = gdns_pubkeys_encr_ballot_votes
                .iter()
                .map(|&pk| {
                    gdns_seckeys_encr_ballot_votes
                        .iter()
                        .map(|&sender_sk| {
                            InterguardianShare::encrypt(csrng, election_parameters, sender_sk, pk)
                                .unwrap()
                                .ciphertext
                        })
                        .collect::<Vec<InterguardianShare>>()
                })
                .collect();

            let cnt_share_vecs = share_vecs.len();
            //println!(
            //    "share encrypt from {cnt_share_vecs} guardians: {:.3} s",
            //    inst_start.elapsed().as_secs_f64()
            //);

            let mut secret_key_shares: Vec<GuardianSecretKeyShare> =
                Vec::with_capacity(gdns_seckeys_encr_ballot_votes.len());
            for (&sk, shares) in zip(gdns_seckeys_encr_ballot_votes.iter(), &share_vecs) {
                let gsk_share = GuardianSecretKeyShare::generate(
                    eg,
                    gdns_pubkeys_encr_ballot_votes.as_slice(),
                    shares,
                    sk,
                )
                .await
                .unwrap();
                secret_key_shares.push(gsk_share);
            }

            //println!(
            //    "compute {} key shares: {:.3} s",
            //    secret_key_shares.len(),
            //    inst_start.elapsed().as_secs_f64()
            //);

            let mut cnt_contests = 0_usize;
            let mut cnt_ciphertexts = 0_usize;
            let mut decryption_dur = Duration::ZERO;
            let mut verification_dur = Duration::ZERO;
            let mut op_dur = OpDurations::default();

            let mut contest_tallies =
                ContestTallies::vec1_for_all_contests_zeroed(election_manifest).unwrap();
            /*

            let inst_start_clock = Instant::now();

            for (contest_ix, contest_tally_encrypted) in contest_tallies_encrypted {
                cnt_contests += 1;

                let contest_tally = contest_tallies
                    .get_mut(contest_ix)
                    .ok_or_else(|| anyhow::anyhow!("Contest tallies missing entry for {contest_ix}"))
                    .unwrap();

                for (data_field_ix0, contest_data_field_tally_ciphertext) in
                    contest_tally_encrypted.iter().enumerate()
                {
                    let contest_data_field_ix =
                        ContestDataFieldIndex::try_from_zero_based_index(data_field_ix0).unwrap();

                    cnt_ciphertexts += 1;

                    let inst_start_dec = Instant::now();

                    let (dec, op_durations) = decryption_helper(
                        eg,
                        Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
                        contest_ix,
                        contest_data_field_ix,
                        &secret_key_shares,
                        contest_data_field_tally_ciphertext,
                        gdns_pubkeys_encr_ballot_votes.as_slice(),
                    )
                    .await
                    .unwrap();
                    let dec_dur = inst_start_dec.elapsed();
                    println!(
                        "decrypt contest {contest_ix} data field {contest_data_field_ix}: {:.3} s",
                        dec_dur.as_secs_f64()
                    );
                    decryption_dur += dec_dur;
                    op_dur += op_durations;

                    let inst_start_ver = Instant::now();
                    assert!(dec.verify(
                        fixed_parameters,
                        h_e,
                        joint_vote_encryption_public_key_k,
                        contest_ix,
                        contest_data_field_ix,
                        contest_data_field_tally_ciphertext
                    ));

                    let dec_plain_text_field_element = &dec.plaintext;
                    assert!(dec_plain_text_field_element.is_valid(field));

                    let data_field_tally_u64 = u64::try_from(dec_plain_text_field_element).unwrap();
                    let data_field_tally_u53 = Uint53::try_from(data_field_tally_u64).unwrap();
                    let data_field_tally = ContestDataFieldTally::from(data_field_tally_u53);

                    let ver_dur = inst_start_ver.elapsed();
                    println!(
                        "verify decryption contest {contest_ix} data field {contest_data_field_ix}: {:.3} s",
                        ver_dur.as_secs_f64()
                    );
                    verification_dur += ver_dur;

                    let refmut_data_field_tally: &mut ContestDataFieldTally = contest_tally
                        .get_mut(contest_data_field_ix)
                        .ok_or_else(|| anyhow::anyhow!("Contest tallies contest {contest_ix} missing entry for data field {contest_data_field_ix}")).unwrap();
                    assert_eq!(Uint53::from(*refmut_data_field_tally), Uint53::zero());

                    *refmut_data_field_tally = data_field_tally_u64.try_into().unwrap();
                }
            }

            {
                let clock_total = inst_start_clock.elapsed();
                let clock_total_s = clock_total.as_secs_f64();
                let clock_contest_avg_s = clock_total
                    .checked_div(cnt_contests as u32)
                    .unwrap_or_default()
                    .as_secs_f64();
                println!(
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
                println!(
                    "decrypt {cnt_ciphertexts} ciphertexts: {decryption_total_s:.3} s, avg {decryption_avg_s:.3} s each"
                );
                println!(
                    "verify {cnt_ciphertexts} decryptions: {verification_total_s:.3} s, avg {verification_avg_s:.3} s each"
                );
            }
            // */

            /*
            let expected_results: Vec1<ContestTallies> = vec![
                Vec1::<ContestDataFieldTally>::try_from([2_u8, 0]).unwrap().into(),
                //Vec1::ContestTallies::try_from_iter([0_u8, 1, 1]).unwrap().into(),
                //Vec1::ContestTallies::try_from_iter([1_u8, 1, 1, 0]).unwrap().into(),
            ]
            .try_into().unwrap();
            */

            /*
            //let v1_u53: Vec1<Uint53> = [2, 0].try_into().unwrap();
            let v1_cdft: Vec1<ContestDataFieldTally> = [2, 0].try_into().unwrap(); // v1_u53.into();
            let ct: ContestTallies = v1_cdft.into();
            let v1: Vec1<ContestTallies> = [
                [2, 0].try_into().unwrap(),
                [0, 1, 1].try_into().unwrap(),
            ].try_into().unwrap();
            let expected_election_tallies: ElectionTallies = v1.into();
            // */

            println!("vvvvvvvv contest tallies vvvvvvvv");
            for (contest_ix, contest_tallies) in contest_tallies.enumerate() {
                //let opt_expected_data_field_values: Option<ContestTallies> = expected_results.get(contest_ix);

                println!("contest {contest_ix}:");
                for (data_field_ix, &data_field_value) in contest_tallies.enumerate() {
                    println!("    data field {data_field_ix}: {data_field_value}");
                }
            }
            println!("^^^^^^^^ contest tallies ^^^^^^^^");
            // */
        });
        info!("test_tally_ballots() succeeded");
    }
}
