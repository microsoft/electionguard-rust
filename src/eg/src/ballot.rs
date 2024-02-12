// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use util::{algebra::FieldElement, csprng::Csprng};

use crate::{
    ballot_style::BallotStyle,
    confirmation_code::confirmation_code,
    contest_encrypted::{ContestEncrypted, ScaledContestEncrypted},
    contest_selection::ContestSelection,
    device::Device,
    election_manifest::{ContestIndex, ElectionManifest},
    election_parameters::ElectionParameters,
    election_record::PreVotingData,
    fixed_parameters::FixedParameters,
    hash::HValue,
    index::Index,
    joint_election_public_key::Ciphertext,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BallotState {
    Uncast,
    Cast,
    Challenged,
}

/// An encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct BallotEncrypted {
    /// Contests in this ballot
    pub contests: BTreeMap<ContestIndex, ContestEncrypted>,

    /// Confirmation code
    pub confirmation_code: HValue,

    /// State of the ballot
    pub state: BallotState,

    /// Date (and time) of ballot generation
    pub date: String,

    /// Device that generated this ballot
    pub device: String,
    // TODO: Have an optional field to store election record data for pre-encrypted ballots
}

/// Scaled version of [`BallotEncrypted`]. This means that each encrypted vote in the ballot
/// has been scaled by factor. A [`ScaledBallotEncrypted`] does not contain any proofs.
pub struct ScaledBallotEncrypted {
    /// Contests in this ballot
    pub contests: BTreeMap<ContestIndex, ScaledContestEncrypted>,
}

impl BallotEncrypted {
    pub fn new(
        contests: &BTreeMap<ContestIndex, ContestEncrypted>,
        state: BallotState,
        confirmation_code: HValue,
        date: &str,
        device: &str,
    ) -> BallotEncrypted {
        BallotEncrypted {
            contests: contests.clone(),
            state,
            confirmation_code,
            date: date.to_string(),
            device: device.to_string(),
        }
    }

    pub fn new_from_selections(
        device: &Device,
        csprng: &mut Csprng,
        primary_nonce: &[u8],
        ctest_selections: &BTreeMap<ContestIndex, ContestSelection>,
    ) -> BallotEncrypted {
        let mut contests = BTreeMap::new();

        for (&c_idx, selection) in ctest_selections {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let contest_encrypted = ContestEncrypted::new(
                device,
                csprng,
                primary_nonce,
                device.header.manifest.contests.get(c_idx).unwrap(),
                c_idx,
                selection,
            );

            contests.insert(c_idx, contest_encrypted);
        }

        // for (i, selection) in selections.iter().enumerate() {
        //     contests.push(ContestEncrypted::new(
        //         device,
        //         csprng,
        //         primary_nonce,
        //         &device.header.manifest.contests.get(i).unwrap(),
        //         selection,
        //     ));
        // }
        let confirmation_code =
            confirmation_code(&device.header.hashes_ext.h_e, contests.values(), &[0u8; 32]);

        BallotEncrypted {
            contests,
            state: BallotState::Uncast,
            confirmation_code,
            date: device.header.parameters.varying_parameters.date.clone(),
            device: device.uuid.clone(),
        }
    }

    pub fn contests(&self) -> &BTreeMap<ContestIndex, ContestEncrypted> {
        &self.contests
    }

    pub fn confirmation_code(&self) -> &HValue {
        &self.confirmation_code
    }

    pub fn date(&self) -> &String {
        &self.date
    }

    pub fn device(&self) -> &String {
        &self.device
    }

    /// Verify all of the [`ContestEncrypted`] in the [`BallotEncrypted`]. Given
    /// a ballot style it checks that all contests are voted on in the
    /// ballot style, and that all of the vote proofs are correct.
    pub fn verify(&self, header: &PreVotingData, ballot_style_index: Index<BallotStyle>) -> bool {
        let Some(ballot_style) = header.manifest.ballot_styles.get(ballot_style_index) else {
            return false;
        };
        for contest_index in &ballot_style.contests {
            let Some(contest) = header.manifest.contests.get(*contest_index) else {
                return false;
            };
            let Some(contest_encrypted) = self.contests().get(contest_index) else {
                return false;
            };

            if !contest_encrypted.verify(header, contest.selection_limit) {
                return false;
            }
        }
        true
    }

    /// Writes a `BallotEncrypted` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .context("Error serializing voter selection")?;

        ser.into_inner()
            .write_all(b"\n")
            .context("Error writing serialized voter selection to file")
    }

    /// Scale a [`BallotEncrypted`] by a factor, producing a [`ScaledBallotEncrypted`].
    /// Each encrypted vote in the ballot gets scaled by the same factor.
    pub fn scale(
        &self,
        fixed_parameters: &FixedParameters,
        factor: &FieldElement,
    ) -> ScaledBallotEncrypted {
        let contests = self
            .contests
            .iter()
            .map(|(idx, ballot)| (*idx, ballot.scale(fixed_parameters, factor)))
            .collect();
        ScaledBallotEncrypted { contests }
    }
}

/// This function takes an iterator over encrypted ballots and tallies up the
/// votes on each option in each contest. The result is map from `ContestIndex`
/// to `Vec<Ciphertext>` that given a contest index gives the encrypted result
/// for the contest, namely a vector of encrypted tallies; one for each option
/// in the contest.
pub fn tally_ballots(
    encrypted_ballots: impl IntoIterator<Item = ScaledBallotEncrypted>,
    manifest: &ElectionManifest,
    parameters: &ElectionParameters,
) -> Option<BTreeMap<ContestIndex, Vec<Ciphertext>>> {
    let mut result = BallotTallyBuilder::new(manifest, parameters);

    for ballot in encrypted_ballots {
        if !result.update(ballot) {
            return None;
        }
    }
    Some(result.finalize())
}

/// A builder to tally ballots incrementally.
pub struct BallotTallyBuilder<'a> {
    manifest: &'a ElectionManifest,
    parameters: &'a ElectionParameters,
    state: BTreeMap<ContestIndex, Vec<Ciphertext>>,
}

impl<'a> BallotTallyBuilder<'a> {
    pub fn new(manifest: &'a ElectionManifest, parameters: &'a ElectionParameters) -> Self {
        Self {
            manifest,
            parameters,
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
    pub fn update(&mut self, ballot: ScaledBallotEncrypted) -> bool {
        let group = &self.parameters.fixed_parameters.group;
        for (idx, contest) in ballot.contests {
            let Some(manifest_contest) = self.manifest.contests.get(idx) else {
                return false;
            };
            if contest.selection.len() != manifest_contest.options.len() {
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
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        ballot::BallotEncrypted,
        contest_selection::ContestSelection,
        device::Device,
        election_manifest::{Contest, ContestOption},
        election_record::PreVotingData,
        example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters,
        guardian_public_key::GuardianPublicKey,
        guardian_secret_key::GuardianSecretKey,
        guardian_share::{GuardianEncryptedShare, GuardianSecretKeyShare},
        hashes::Hashes,
        hashes_ext::HashesExt,
        index::Index,
        joint_election_public_key::JointElectionPublicKey,
        verifiable_decryption::{
            CombinedDecryptionShare, DecryptionProof, DecryptionShare, VerifiableDecryption,
        },
    };
    use std::iter::zip;
    use util::csprng::Csprng;

    fn g_key(i: u32) -> GuardianSecretKey {
        let mut seed = Vec::new();
        let customization_data = format!("GuardianSecretKeyGenerate({})", i.clone());
        seed.extend_from_slice(&(customization_data.as_bytes().len() as u64).to_be_bytes());
        seed.extend_from_slice(customization_data.as_bytes());

        let mut csprng = Csprng::new(&seed);

        GuardianSecretKey::generate(
            &mut csprng,
            &example_election_parameters(),
            Index::from_one_based_index_const(i).unwrap(),
            None,
        )
    }

    #[test]
    fn test_verify_ballot() {
        let election_manifest = example_election_manifest();
        let election_parameters = example_election_parameters();

        let sk1 = g_key(1);
        let sk2 = g_key(2);
        let sk3 = g_key(3);
        let sk4 = g_key(4);
        let sk5 = g_key(5);

        let pk1 = sk1.make_public_key();
        let pk2 = sk2.make_public_key();
        let pk3 = sk3.make_public_key();
        let pk4 = sk4.make_public_key();
        let pk5 = sk5.make_public_key();

        let guardian_public_keys = vec![pk1, pk2, pk3, pk4, pk5];

        let joint_election_public_key =
            JointElectionPublicKey::compute(&election_parameters, guardian_public_keys.as_slice())
                .unwrap();

        let hashes = Hashes::compute(&election_parameters, &election_manifest).unwrap();

        let hashes_ext = HashesExt::compute(
            &election_parameters,
            &hashes,
            &joint_election_public_key,
        );

        let pre_voting_data = PreVotingData {
            manifest: election_manifest,
            parameters: election_parameters,
            hashes,
            hashes_ext,
            public_key: joint_election_public_key,
        };
        let device = Device::new("Some encryption device", pre_voting_data);
        let seed = vec![0, 1, 2, 3];
        let mut csprng = Csprng::new(&seed);
        let primary_nonce = vec![0, 1, 2, 2, 2, 2, 2, 2, 3];
        let selections = BTreeMap::from([
            (
                Index::from_one_based_index(1).unwrap(),
                ContestSelection { vote: vec![1, 0] },
            ),
            (
                Index::from_one_based_index(2).unwrap(),
                ContestSelection {
                    vote: vec![0, 1, 0, 0],
                },
            ),
            (
                Index::from_one_based_index(3).unwrap(),
                ContestSelection {
                    vote: vec![0, 0, 1],
                },
            ),
            (
                Index::from_one_based_index(4).unwrap(),
                ContestSelection {
                    vote: vec![1, 0, 0],
                },
            ),
            (
                Index::from_one_based_index(5).unwrap(),
                ContestSelection {
                    vote: vec![0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0],
                },
            ),
            (
                Index::from_one_based_index(6).unwrap(),
                ContestSelection { vote: vec![1, 0] },
            ),
            (
                Index::from_one_based_index(7).unwrap(),
                ContestSelection { vote: vec![0, 0] },
            ),
            (
                Index::from_one_based_index(8).unwrap(),
                ContestSelection { vote: vec![0, 1] },
            ),
            (
                Index::from_one_based_index(9).unwrap(),
                ContestSelection { vote: vec![1, 0] },
            ),
            (
                Index::from_one_based_index(11).unwrap(),
                ContestSelection { vote: vec![0, 1] },
            ),
        ]);

        let ballot_from_selections =
            BallotEncrypted::new_from_selections(&device, &mut csprng, &primary_nonce, &selections);

        // Let's verify the ballot proofs.

        let verify_result =
            ballot_from_selections.verify(&device.header, Index::from_one_based_index(2).unwrap());

        assert!(verify_result)
    }

    fn short_manifest() -> ElectionManifest {
        let contests = [
            // Contest index 1:
            Contest {
                label: "Minister of Arcane Sciences".to_string(),
                selection_limit: 2,
                options: [
                    ContestOption {
                        label: "Élyria Moonshadow\n(Crystâlheärt)".to_string(),
                    },
                    ContestOption {
                        label: "Archímedes Darkstone\n(Ætherwïng)".to_string(),
                    },
                    ContestOption {
                        label: "Seraphína Stormbinder\n(Independent)".to_string(),
                    },
                    ContestOption {
                        label: "Gávrïel Runëbørne\n(Stärsky)".to_string(),
                    },
                ]
                .try_into()
                .unwrap(),
            },
            // Contest index 2:
            Contest {
                label: "Minister of Elemental Resources".to_string(),
                selection_limit: 1,
                options: [
                    ContestOption {
                        label: "Tïtus Stormforge\n(Ætherwïng)".to_string(),
                    },
                    ContestOption {
                        label: "Fæ Willowgrove\n(Crystâlheärt)".to_string(),
                    },
                    ContestOption {
                        label: "Tèrra Stonebinder\n(Independent)".to_string(),
                    },
                ]
                .try_into()
                .unwrap(),
            },
            // Contest index 3:
            Contest {
                label: "Minister of Dance".to_string(),
                selection_limit: 1,
                options: [
                    ContestOption {
                        label: "Äeliana Sunsong\n(Crystâlheärt)".to_string(),
                    },
                    ContestOption {
                        label: "Thâlia Shadowdance\n(Ætherwïng)".to_string(),
                    },
                    ContestOption {
                        label: "Jasper Moonstep\n(Stärsky)".to_string(),
                    },
                ]
                .try_into()
                .unwrap(),
            },
        ]
        .try_into()
        .unwrap();

        let ballot_styles = [
            // Ballot style index 1:
            BallotStyle {
                label: "Smoothstone County Ballot".to_string(),
                contests: BTreeSet::from(
                    [1u32, 3].map(|ix1| ContestIndex::from_one_based_index(ix1).unwrap()),
                ),
            },
            // Ballot style index 2:
            BallotStyle {
                label: "Silvërspîre County Ballot".to_string(),
                contests: BTreeSet::from(
                    [2u32, 3].map(|ix1| ContestIndex::from_one_based_index(ix1).unwrap()),
                ),
            },
            // Ballot style index 3:
            BallotStyle {
                label: "Another County Ballot".to_string(),
                contests: BTreeSet::from(
                    [1, 2u32, 3].map(|ix1| ContestIndex::from_one_based_index(ix1).unwrap()),
                ),
            },
        ]
        .try_into()
        .unwrap();

        ElectionManifest {
            label: "General Election - The United Realms of Imaginaria".to_string(),
            contests,
            ballot_styles,
        }
    }

    fn decryption_helper(
        key_shares: &[GuardianSecretKeyShare],
        csprng: &mut Csprng,
        pre_voting_data: &PreVotingData,
        ciphertext: &Ciphertext,
        guardian_public_keys: &Vec<GuardianPublicKey>,
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
        let joint_election_public_key_clone = &pre_voting_data.public_key;
        let rsp_shares: Vec<_> = com_states
            .iter()
            .zip(key_shares)
            .map(|(state, key_share)| {
                DecryptionProof::generate_response_share(
                    &election_parameters.fixed_parameters,
                    &pre_voting_data.clone().hashes_ext,
                    joint_election_public_key_clone,
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
            &pre_voting_data.clone().hashes_ext,
            ciphertext,
            &dec_shares,
            &com_shares,
            &rsp_shares,
            guardian_public_keys,
        )
        .unwrap();

        VerifiableDecryption::new(
            &election_parameters.fixed_parameters,
            joint_election_public_key_clone,
            ciphertext,
            &combined_dec_share,
            &proof,
        )
        .unwrap()
    }

    /// Testing that encrypted tallies decrypt the expected result
    #[test]
    fn test_tally_ballot() {
        let election_manifest = short_manifest();
        let election_parameters = example_election_parameters();
        let fixed_parameters = &election_parameters.fixed_parameters;

        let sk1 = g_key(1);
        let sk2 = g_key(2);
        let sk3 = g_key(3);
        let sk4 = g_key(4);
        let sk5 = g_key(5);

        let pk1 = sk1.make_public_key();
        let pk2 = sk2.make_public_key();
        let pk3 = sk3.make_public_key();
        let pk4 = sk4.make_public_key();
        let pk5 = sk5.make_public_key();

        let guardian_secret_keys = vec![sk1, sk2, sk3, sk4, sk5];
        let guardian_public_keys = vec![pk1, pk2, pk3, pk4, pk5];

        let joint_election_public_key =
            JointElectionPublicKey::compute(&election_parameters, guardian_public_keys.as_slice())
                .unwrap();

        let hashes = Hashes::compute(&election_parameters, &election_manifest).unwrap();

        let hashes_ext = HashesExt::compute(
            &election_parameters,
            &hashes,
            &joint_election_public_key,
            guardian_public_keys.as_slice(),
        );

        let pre_voting_data = PreVotingData {
            manifest: election_manifest.clone(),
            parameters: election_parameters.clone(),
            hashes,
            hashes_ext,
            public_key: joint_election_public_key,
        };
        let device = Device::new("Some encryption device", pre_voting_data.clone());
        let seed = vec![0, 1, 2, 3];
        let mut csprng = Csprng::new(&seed);
        let primary_nonce = vec![0, 1, 2, 2, 2, 2, 2, 2, 3];
        let voter1 = BTreeMap::from([
            // Voting on 1 and 3 only, ballot style 1
            (
                Index::from_one_based_index(1).unwrap(),
                ContestSelection {
                    vote: vec![1, 1, 0, 0],
                },
            ),
            (
                Index::from_one_based_index(3).unwrap(),
                ContestSelection {
                    vote: vec![0, 1, 0],
                },
            ),
        ]);

        let voter2 = BTreeMap::from([
            // Voting on 2 and 3 only, ballot style 2
            (
                Index::from_one_based_index(2).unwrap(),
                ContestSelection {
                    vote: vec![0, 1, 0],
                },
            ),
            (
                Index::from_one_based_index(3).unwrap(),
                ContestSelection {
                    vote: vec![0, 1, 0],
                },
            ),
        ]);
        let voter3 = BTreeMap::from([
            // Voting on all three, ballot style 3
            (
                Index::from_one_based_index(1).unwrap(),
                ContestSelection {
                    vote: vec![1, 0, 0, 0],
                },
            ),
            (
                Index::from_one_based_index(2).unwrap(),
                ContestSelection {
                    vote: vec![1, 0, 0],
                },
            ),
            (
                Index::from_one_based_index(3).unwrap(),
                ContestSelection {
                    vote: vec![1, 0, 0],
                },
            ),
        ]);
        let ballot_voter1 =
            BallotEncrypted::new_from_selections(&device, &mut csprng, &primary_nonce, &voter1);
        let verify_result1 =
            ballot_voter1.verify(&device.header, Index::from_one_based_index(1).unwrap());
        assert!(verify_result1);
        let ballot_voter2 =
            BallotEncrypted::new_from_selections(&device, &mut csprng, &primary_nonce, &voter2);
        let verify_result2 =
            ballot_voter2.verify(&device.header, Index::from_one_based_index(2).unwrap());
        assert!(verify_result2);
        let ballot_voter3 =
            BallotEncrypted::new_from_selections(&device, &mut csprng, &primary_nonce, &voter3);
        let verify_result3 =
            ballot_voter3.verify(&device.header, Index::from_one_based_index(3).unwrap());
        assert!(verify_result3);

        let factor = FieldElement::from(1u8, &fixed_parameters.field);
        let encrypted_ballots = vec![
            ballot_voter1.scale(fixed_parameters, &factor),
            ballot_voter2.scale(fixed_parameters, &factor),
            ballot_voter3.scale(fixed_parameters, &factor),
        ];
        let tally =
            tally_ballots(encrypted_ballots, &election_manifest, &election_parameters).unwrap();

        let result_contest_1 = tally.get(&Index::from_one_based_index(1).unwrap()).unwrap();
        let result_contest_2 = tally.get(&Index::from_one_based_index(2).unwrap()).unwrap();
        let result_contest_3 = tally.get(&Index::from_one_based_index(3).unwrap()).unwrap();

        // Decryption
        let share_vecs = guardian_public_keys
            .iter()
            .map(|pk| {
                guardian_secret_keys
                    .iter()
                    .map(|dealer_sk| {
                        GuardianEncryptedShare::encrypt(
                            &mut csprng,
                            &election_parameters.clone(),
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
                    &election_parameters,
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
                    &mut csprng,
                    &pre_voting_data,
                    ct,
                    &guardian_public_keys,
                );
                assert!(dec.verify(
                    &pre_voting_data.parameters.fixed_parameters,
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
                FieldElement::from(1u8, &fixed_parameters.field),
                FieldElement::from(0u8, &fixed_parameters.field),
                FieldElement::from(0u8, &fixed_parameters.field)
            ]
        );
        let decryption_contest_2: Vec<_> = result_contest_2
            .iter()
            .map(|ct| {
                let dec = decryption_helper(
                    &key_shares,
                    &mut csprng,
                    &pre_voting_data,
                    ct,
                    &guardian_public_keys,
                );
                assert!(dec.verify(
                    &pre_voting_data.parameters.fixed_parameters,
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
                FieldElement::from(1u8, &fixed_parameters.field),
                FieldElement::from(1u8, &fixed_parameters.field),
                FieldElement::from(0u8, &fixed_parameters.field)
            ]
        );
        let decryption_contest_3: Vec<_> = result_contest_3
            .iter()
            .map(|ct| {
                let dec = decryption_helper(
                    &key_shares,
                    &mut csprng,
                    &pre_voting_data,
                    ct,
                    &guardian_public_keys,
                );
                assert!(dec.verify(
                    &pre_voting_data.parameters.fixed_parameters,
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
                FieldElement::from(2u8, &fixed_parameters.field),
                FieldElement::from(0u8, &fixed_parameters.field)
            ]
        );
    }
}
