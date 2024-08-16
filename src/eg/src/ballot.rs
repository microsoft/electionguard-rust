// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use util::{algebra::FieldElement, csprng::Csprng};

use crate::{
    ballot_style::BallotStyleIndex,
    ciphertext::Ciphertext,
    confirmation_code::compute_confirmation_code,
    contest_data_fields::ContestDataFieldsPlaintexts,
    contest_encrypted::ContestDataFieldsCiphertexts,
    election_manifest::ContestIndex,
    errors::{EgError, EgResult},
    fixed_parameters::FixedParameters,
    hash::HValue,
    pre_voting_data::PreVotingData,
    serializable::{SerializableCanonical, SerializablePretty},
    voter_selections_plaintext::VoterSelectionsPlaintext,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BallotState {
    /// Voter selections are completed and present in encrypted form.
    /// The ballot has not yet been cast, challenged, or spoiled.
    VoterSelectionsEncrypted,

    /// Voter selections are completed and present in encrypted form.
    /// The ballot has been cast.
    /// Selections MUST be considered to express voter intent, so
    /// the ballot MUST NOT be decrypted.
    /// Selections MUST be included in the tally.
    /// This is a final state.
    Cast,

    /// Voter selections are completed and present in encrypted form.
    /// The ballot has been spoiled, it will NOT be cast.
    /// Selections MUST be considered as potentially expressing voter intent, so
    /// the ballot MUST NOT be decrypted.
    /// However, selections MUST NOT be included in the tally.
    /// This is a final state.
    Spoiled,

    /// Voter selections are completed and present in encrypted form.
    /// The ballot has been challenged, it will never been cast.
    /// Selections MUST NOT be interpreted as an expression of voter intent.
    /// The ballot SHOULD be decrypted for verification.
    /// Selections MUST NOT be included in the tally.
    Challenged,

    /// A challenged ballot in which voter selections have been decrypted.
    /// Voter selections are present in both encrypted and plaintext form.
    /// Selections MUST NOT be interpreted as an expression of voter intent.
    /// Selections MUST NOT be included in the tally.
    /// The challenged and decrypted ballot SHOULD be published.
    /// This is a final state.
    ChallengedDecrypted,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BallotEncrypted {
    /// The 1-based index of the [`BallotStyle`] within the [`ElectionManifest`].
    #[serde(rename = "ballot_style")]
    pub ballot_style_ix: BallotStyleIndex,

    /// The state of ballot.
    pub ballot_state: BallotState,

    /// ElectionGuard 2.1 Section 3.3.2 defines a
    /// Selection Encryption Identifier as 32 random bytes.
    /// For convenience, we'll use `HValue` for this.
    pub selection_encryption_identifier: HValue,

    /// Encrypted data fields for [`Contests`] reflecting voter selections and
    /// possibly additional contest data fields.
    pub contests_data_fields_ciphertexts: BTreeMap<ContestIndex, ContestDataFieldsCiphertexts>,

    /// Confirmation code.
    pub confirmation_code: HValue,

    /// Identifier of device that encrypted the voter selections to produce a ballot.
    /// Optional, can be empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device_id: String,

    /// The device may apply an identifier to the ballot. Optional, can be empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ballot_id: String,

    /// Date and time of ballot encryption.
    /// Optional, can be empty.
    /// Consider using [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339#section-5.8),
    /// AKA "ISO 8601" format for this.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub encryption_datetime: String,
}

impl BallotEncrypted {
    /// Create a new [`BallotEncrypted`] from a [`VoterSelectionsPlaintext`].
    ///
    /// If a nonce is not provided, a random nonce will be generated.
    #[allow(non_snake_case)]
    pub fn try_from_ballot_selection_data_plaintext(
        pre_voting_data: &PreVotingData,
        voter_selections_plaintext: VoterSelectionsPlaintext,
        opt_ballot_nonce_xi_B: Option<HValue>,
        csprng: &mut Csprng,
    ) -> EgResult<BallotEncrypted> {
        let (ballot_style_ix, _ballot_style) =
            voter_selections_plaintext.verify_against_pre_voting_data(pre_voting_data)?;

        let ballot_nonce_xi_B =
            opt_ballot_nonce_xi_B.unwrap_or_else(|| HValue::from_csprng(csprng));

        // Convert the plaintext contest option fields to plaintext contest data fields.
        let mut contests_data_fields_plaintexts: BTreeMap<
            ContestIndex,
            ContestDataFieldsPlaintexts,
        > = BTreeMap::new();
        for (contest_ix, contest_option_fields_plaintexts) in
            voter_selections_plaintext.contests_option_fields_plaintexts
        {
            let specific_contest_data_fields_plaintexts =
                ContestDataFieldsPlaintexts::try_from_option_fields(
                    pre_voting_data,
                    contest_ix,
                    contest_option_fields_plaintexts,
                )?;
            contests_data_fields_plaintexts
                .insert(contest_ix, specific_contest_data_fields_plaintexts);
        }

        // Encrypt the plaintext contest data fields to make the contest data fields ciphertexts.
        let mut contests_data_fields_ciphertexts: BTreeMap<
            ContestIndex,
            ContestDataFieldsCiphertexts,
        > = BTreeMap::new();
        for (contest_ix, contest_data_fields_plaintexts) in contests_data_fields_plaintexts {
            let contest_data_fields_ciphertexts =
                ContestDataFieldsCiphertexts::from_contest_data_fields_plaintexts(
                    pre_voting_data,
                    ballot_nonce_xi_B,
                    contest_ix,
                    contest_data_fields_plaintexts,
                    csprng,
                )?;

            contests_data_fields_ciphertexts.insert(contest_ix, contest_data_fields_ciphertexts);
        }

        let confirmation_code = compute_confirmation_code(
            pre_voting_data,
            contests_data_fields_ciphertexts.values(),
            None,
        );

        //? TODO Make these function parameters
        let device_id = "".to_owned();
        let ballot_id = "".to_owned();
        let encryption_datetime = "".to_owned();

        let ballot_state = BallotState::VoterSelectionsEncrypted;

        let selection_encryption_identifier = HValue::from_csprng(csprng);

        Ok(BallotEncrypted {
            ballot_style_ix,
            ballot_state,
            selection_encryption_identifier,
            contests_data_fields_ciphertexts,
            confirmation_code,
            device_id,
            ballot_id,
            encryption_datetime,
        })
    }

    /// Verify all of the [`ContestEncrypted`] in the [`Ballot`]. Given
    /// a ballot style it checks that all contests are voted on in the
    /// ballot style, and that all of the vote proofs are correct.
    pub fn verify(&self, pre_voting_data: &PreVotingData) -> EgResult<()> {
        let ballot_style_ix = self.ballot_style_ix;

        let ballot_style = pre_voting_data.manifest.get_ballot_style(ballot_style_ix)?;

        // Verify that every contest in the ballot style:
        // - is present in the manifest
        // - is present in this ballot's data fields ciphertexts.
        for &contest_ix in ballot_style.contests().iter() {
            if !pre_voting_data
                .manifest
                .contests()
                .contains_index(contest_ix)
            {
                return Err(EgError::BallotStyleClaimsNonExistentContest {
                    ballot_style_ix,
                    contest_ix,
                });
            }

            if !self
                .contests_data_fields_ciphertexts
                .contains_key(&contest_ix)
            {
                return Err(EgError::BallotMissingDataFieldsForContestInBallotStyle {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        // Verify that every contest present in the ballot:
        // - is present in the ballot style
        // - has valid proofs for all contest data fields.
        let mut verified_contests = BTreeSet::<ContestIndex>::new();
        for (&contest_ix, contest_fields_ciphertexts) in
            self.contests_data_fields_ciphertexts.iter()
        {
            if !ballot_style.contests().contains(&contest_ix) {
                return Err(EgError::BallotClaimsContestNonExistentInBallotStyle {
                    ballot_style_ix,
                    contest_ix,
                });
            }

            contest_fields_ciphertexts.verify(pre_voting_data)?;

            verified_contests.insert(contest_ix);
        }

        // Verify that we verified all contests in the ballot style.
        for &contest_ix in ballot_style.contests().iter() {
            if !verified_contests.contains(&contest_ix) {
                return Err(EgError::BallotContestNotVerified {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        // Verify that all contests we verified are in the ballot style.
        for &contest_ix in verified_contests.iter() {
            if !ballot_style.contests().contains(&contest_ix) {
                return Err(EgError::BallotContestVerifiedNotInBallotStyle {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        Ok(())
    }

    /// Scale the contest option values of a [`Ballot`] by a factor, producing a [`BallotScaled`].
    /// Each encrypted vote in the ballot gets scaled by the same factor.
    pub fn scale(
        &self,
        fixed_parameters: &FixedParameters,
        factor: &FieldElement,
    ) -> crate::ballot_scaled::BallotScaled {
        //? TODO move to `ballot_scaled.rs`
        let contests = self
            .contests_data_fields_ciphertexts
            .iter()
            .map(|(idx, ballot)| (*idx, ballot.scale(fixed_parameters, factor)))
            .collect();
        crate::ballot_scaled::BallotScaled { contests }
    }
}

impl SerializableCanonical for BallotEncrypted {}

impl SerializablePretty for BallotEncrypted {}

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

/// A builder to tally ballots incrementally.
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

    /// Update the tally with a new ballot. Returns whether the
    /// new ballot was compatible with the tally. If `false` is returned then
    /// the tally is not updated.
    pub fn update(&mut self, ballot: crate::ballot_scaled::BallotScaled) -> bool {
        let group = &self.pre_voting_data.parameters.fixed_parameters.group;
        for (idx, contest) in ballot.contests {
            let Some(manifest_contest) = self.pre_voting_data.manifest.contests().get(idx) else {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;

    use std::iter::zip;

    use util::csprng::Csprng;

    use crate::{
        ballot::BallotEncrypted,
        contest_option_fields::ContestOptionFieldsPlaintexts,
        election_parameters::ElectionParameters,
        errors::EgResult,
        example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters,
        guardian_public_key::GuardianPublicKey,
        guardian_secret_key::GuardianSecretKey,
        guardian_share::{GuardianEncryptedShare, GuardianSecretKeyShare},
        index::Index,
        pre_voting_data::PreVotingData,
        verifiable_decryption::{
            CombinedDecryptionShare, DecryptionProof, DecryptionShare, VerifiableDecryption,
        },
    };

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

    #[test]
    fn test_check_verify_ballot() -> EgResult<()> {
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

        let seed = b"electionguard-rust/src/eg/src/ballot::test::test_check_verify_ballot";
        let csprng = &mut Csprng::new(seed);

        #[allow(non_snake_case)]
        let xi_B = HValue::from_csprng(csprng);

        let vspt = VoterSelectionsPlaintext {
            h_e: pre_voting_data.hashes_ext.h_e,
            ballot_style_ix: 1.try_into()?,
            contests_option_fields_plaintexts: BTreeMap::from([
                // Voting Ballot style 1 has 1 contest: 1
                (
                    1.try_into()?,
                    ContestOptionFieldsPlaintexts::try_new_from([0_u8, 1]).unwrap(),
                ),
            ]),
        };

        let ballot = BallotEncrypted::try_from_ballot_selection_data_plaintext(
            &pre_voting_data,
            vspt,
            Some(xi_B),
            csprng,
        )?;

        // Let's verify the ballot proofs.
        ballot.verify(&pre_voting_data)
    }

    fn decryption_helper(
        key_shares: &[GuardianSecretKeyShare],
        csprng: &mut Csprng,
        pre_voting_data: &PreVotingData,
        ciphertext: &Ciphertext,
        guardian_public_keys: &[GuardianPublicKey],
    ) -> VerifiableDecryption {
        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|ks| {
                DecryptionShare::from(&pre_voting_data.parameters.fixed_parameters, ks, ciphertext)
            })
            .collect();

        let combined_dec_share =
            CombinedDecryptionShare::combine(&pre_voting_data.parameters, &dec_shares).unwrap();
        let mut com_shares = vec![];
        let mut com_states = vec![];

        for ks in key_shares.iter() {
            let (share, state) = DecryptionProof::generate_commit_share(
                csprng,
                &pre_voting_data.parameters.fixed_parameters,
                ciphertext,
                &ks.i,
            );
            com_shares.push(share);
            com_states.push(state);
        }

        let election_parameters = &pre_voting_data.parameters;
        let rsp_shares: Vec<_> = com_states
            .iter()
            .zip(key_shares)
            .map(|(state, key_share)| {
                DecryptionProof::generate_response_share(
                    pre_voting_data,
                    ciphertext,
                    &combined_dec_share,
                    &com_shares,
                    state,
                    key_share,
                )
                .unwrap()
            })
            .collect();

        let proof = DecryptionProof::combine_proof(
            election_parameters,
            &pre_voting_data.hashes_ext,
            ciphertext,
            &dec_shares,
            &com_shares,
            &rsp_shares,
            guardian_public_keys,
        )
        .unwrap();

        VerifiableDecryption::new(
            &election_parameters.fixed_parameters,
            &pre_voting_data.public_key,
            ciphertext,
            &combined_dec_share,
            &proof,
        )
        .unwrap()
    }

    /// Testing that encrypted tallies decrypt the expected result
    #[test]
    #[allow(non_snake_case)]
    fn test_tally_ballot() -> EgResult<()> {
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
        let guardian_secret_keys = vec![sk1, sk2, sk3, sk4, sk5];

        let pre_voting_data = PreVotingData::try_from_parameters_manifest_gpks(
            election_parameters,
            example_election_manifest(),
            &guardian_public_keys,
        )?;
        let fixed_parameters = &pre_voting_data.parameters.fixed_parameters;

        let seed = b"electionguard-rust/src/eg/src/ballot::test::test_tally_ballot";
        let csprng = &mut Csprng::new(seed);

        let xi_B_1 = HValue::from_csprng(csprng);
        let xi_B_2 = HValue::from_csprng(csprng);
        let xi_B_3 = HValue::from_csprng(csprng);

        let ballot_1 = {
            // Voting Ballot style 15 has 2 contests: 1 and 3
            let vspt = VoterSelectionsPlaintext {
                h_e: pre_voting_data.hashes_ext.h_e,
                ballot_style_ix: 15.try_into()?,
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
            };

            let ballot = BallotEncrypted::try_from_ballot_selection_data_plaintext(
                &pre_voting_data,
                vspt,
                Some(xi_B_1),
                csprng,
            )?;
            ballot.verify(&pre_voting_data)?;
            ballot
        };

        let ballot_2 = {
            // Voting Ballot style 16 has 2 contests: 2 and 3
            let vspt = VoterSelectionsPlaintext {
                h_e: pre_voting_data.hashes_ext.h_e,
                ballot_style_ix: 16.try_into()?,
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
            };

            let ballot = BallotEncrypted::try_from_ballot_selection_data_plaintext(
                &pre_voting_data,
                vspt,
                Some(xi_B_2),
                csprng,
            )?;
            ballot.verify(&pre_voting_data)?;
            ballot
        };

        let ballot_3 = {
            // Voting Ballot style 17 has 3 contests: 1, 2, and 3
            let vspt = VoterSelectionsPlaintext {
                h_e: pre_voting_data.hashes_ext.h_e,
                ballot_style_ix: 17.try_into()?,
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
            };

            let ballot = BallotEncrypted::try_from_ballot_selection_data_plaintext(
                &pre_voting_data,
                vspt,
                Some(xi_B_3),
                csprng,
            )?;
            ballot.verify(&pre_voting_data)?;
            ballot
        };

        let scaled_ballots = {
            let scale_factor = FieldElement::from(1u8, &fixed_parameters.field);
            vec![
                ballot_1.scale(fixed_parameters, &scale_factor),
                ballot_2.scale(fixed_parameters, &scale_factor),
                ballot_3.scale(fixed_parameters, &scale_factor),
            ]
        };

        let tally = tally_ballots(scaled_ballots, &pre_voting_data).unwrap();

        let result_contest_1 = tally.get(&(1.try_into()?)).unwrap();
        let result_contest_2 = tally.get(&(2.try_into()?)).unwrap();
        let result_contest_3 = tally.get(&(3.try_into()?)).unwrap();

        // Decryption
        let share_vecs = guardian_public_keys
            .iter()
            .map(|pk| {
                guardian_secret_keys
                    .iter()
                    .map(|dealer_sk| {
                        GuardianEncryptedShare::encrypt(
                            csprng,
                            &pre_voting_data.parameters,
                            dealer_sk,
                            pk,
                        )
                        .ciphertext
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let key_shares = zip(&guardian_secret_keys, share_vecs)
            .map(|(sk, shares)| {
                GuardianSecretKeyShare::compute(
                    &pre_voting_data,
                    &guardian_public_keys,
                    &shares,
                    sk,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let decryption_contest_1: Vec<_> = result_contest_1
            .iter()
            .map(|ct| {
                let dec = decryption_helper(
                    &key_shares,
                    csprng,
                    &pre_voting_data,
                    ct,
                    &guardian_public_keys,
                );
                assert!(dec.verify(
                    fixed_parameters,
                    &pre_voting_data.hashes_ext,
                    &pre_voting_data.public_key,
                    ct
                ));
                dec.plain_text
            })
            .collect();

        assert_eq!(
            decryption_contest_1,
            vec![
                FieldElement::from(2u8, &fixed_parameters.field),
                FieldElement::from(0u8, &fixed_parameters.field)
            ]
        );

        let decryption_contest_2: Vec<_> = result_contest_2
            .iter()
            .map(|ct| {
                let dec = decryption_helper(
                    &key_shares,
                    csprng,
                    &pre_voting_data,
                    ct,
                    &guardian_public_keys,
                );
                assert!(dec.verify(
                    fixed_parameters,
                    &pre_voting_data.hashes_ext,
                    &pre_voting_data.public_key,
                    ct
                ));
                dec.plain_text
            })
            .collect();

        assert_eq!(
            decryption_contest_2,
            vec![
                FieldElement::from(0u8, &fixed_parameters.field),
                FieldElement::from(1u8, &fixed_parameters.field),
                FieldElement::from(1u8, &fixed_parameters.field)
            ]
        );

        let decryption_contest_3: Vec<_> = result_contest_3
            .iter()
            .map(|ct| {
                let dec = decryption_helper(
                    &key_shares,
                    csprng,
                    &pre_voting_data,
                    ct,
                    &guardian_public_keys,
                );
                assert!(dec.verify(
                    fixed_parameters,
                    &pre_voting_data.hashes_ext,
                    &pre_voting_data.public_key,
                    ct
                ));
                dec.plain_text
            })
            .collect();
        assert_eq!(
            decryption_contest_3,
            vec![
                FieldElement::from(1u8, &fixed_parameters.field),
                FieldElement::from(1u8, &fixed_parameters.field),
                FieldElement::from(1u8, &fixed_parameters.field),
                FieldElement::from(0u8, &fixed_parameters.field)
            ]
        );

        Ok(())
    }
}
