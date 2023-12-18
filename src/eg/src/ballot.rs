// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use util::csprng::Csprng;

use crate::{
    ballot_style::BallotStyle,
    confirmation_code::confirmation_code,
    contest_encrypted::{tally_votes, ContestEncrypted},
    contest_selection::ContestSelection,
    device::Device,
    election_manifest::{ContestIndex, ElectionManifest},
    election_record::PreVotingData,
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

    /// Verify all of the [`ContestEncrypted`] in the [`BallotEncrypted`]. Given a ballot style it checks
    /// that all contests are voted on in the ballot style, and that all of the vote proofs are
    /// correct.
    pub fn verify(&self, header: &PreVotingData, ballot_style_index: Index<BallotStyle>) -> bool {
        let Some(ballot_style) = header.manifest.ballot_styles.get(ballot_style_index) else {return false};
        for contest_index in &ballot_style.contests {
            let Some(contest) = header.manifest.contests.get(*contest_index) else {return false};
            let Some(contest_encrypted) = self.contests().get(contest_index) else {return false};

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
}

pub fn tally_ballots1(
    encrypted_ballots: &[BallotEncrypted],
    manifest: &ElectionManifest,
) -> Option<BTreeMap<ContestIndex, Vec<Ciphertext>>> {
    let mut pre_result: BTreeMap<ContestIndex, Vec<ContestEncrypted>> = BTreeMap::new();

    for ballot in encrypted_ballots {
        for (idx, contest) in &ballot.contests {
            if let Some(v) = pre_result.get_mut(idx) {
                v.push(contest.clone());
            } else {
                pre_result.insert(*idx, vec![contest.clone()]);
            }
        }
    }

    let mut result = BTreeMap::new();

    for (k, v) in pre_result {
        let number_of_candidates = manifest.contests.get(k)?.options.len();
        result.insert(k, tally_votes(&v, number_of_candidates)?);
    }

    Some(result)
}

pub fn tally_ballots2(
    encrypted_ballots: &[BallotEncrypted],
    manifest: &ElectionManifest,
) -> Option<BTreeMap<ContestIndex, Vec<Ciphertext>>> {
    let mut result: BTreeMap<ContestIndex, Vec<Ciphertext>> = BTreeMap::new();

    for ballot in encrypted_ballots {
        for (idx, contest) in &ballot.contests {
            if contest.selection.len() != manifest.contests.get(*idx)?.options.len() {
                return None;
            }
            if let Some(v) = result.get_mut(idx) {
                for (j, encryption) in contest.selection.iter().enumerate() {
                    v[j].alpha = &v[j].alpha * &encryption.alpha;
                    v[j].beta = &v[j].beta * &encryption.beta;
                }
            } else {
                result.insert(*idx, contest.selection.clone());
            }
        }
    }
    Some(result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        ballot::BallotEncrypted, contest_selection::ContestSelection, device::Device,
        election_record::PreVotingData, example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters,
        guardian_secret_key::GuardianSecretKey, hashes::Hashes, hashes_ext::HashesExt,
        index::Index, joint_election_public_key::JointElectionPublicKey, election_manifest::{Contest, ContestOption},
    };
    use util::csprng::Csprng;

    fn g_key(i: u32) -> GuardianSecretKey {
        let mut seed = Vec::new();
        let customization_data = format!("GuardianSecretKeyGenerate({})", i.clone());
        seed.extend_from_slice(&(customization_data.as_bytes().len() as u64).to_be_bytes());
        seed.extend_from_slice(customization_data.as_bytes());

        let mut csprng = Csprng::new(&seed);

        let secret_key = GuardianSecretKey::generate(
            &mut csprng,
            &example_election_parameters(),
            Index::from_one_based_index_const(i).unwrap(),
            None,
        );
        secret_key
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
            guardian_public_keys.as_slice(),
        );

        let pre_voting_data = PreVotingData {
            manifest: election_manifest.clone(),
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
                selection_limit: 1,
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
                ].try_into().unwrap(),
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
                ].try_into().unwrap(),
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
                ].try_into().unwrap(),
            },
        ].try_into().unwrap();

        let ballot_styles = [
            // Ballot style index 1:
            BallotStyle {
                label: "Smoothstone County Ballot".to_string(),
                contests: BTreeSet::from(
                    [
                        1u32, 3,
                    ]
                    .map(|ix1| ContestIndex::from_one_based_index(ix1).unwrap()),
                ),
            },
            // Ballot style index 2:
            BallotStyle {
                label: "Silvërspîre County Ballot".to_string(),
                contests: BTreeSet::from(
                    [
                        2u32, 3
                    ]
                    .map(|ix1| ContestIndex::from_one_based_index(ix1).unwrap()),
                ),
            },
            // Ballot style index 3:
            BallotStyle {
                label: "Another County Ballot".to_string(),
                contests: BTreeSet::from(
                    [
                        1, 2u32, 3
                    ]
                    .map(|ix1| ContestIndex::from_one_based_index(ix1).unwrap()),
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


    #[test]
    fn test_tally_ballot() {
        let election_manifest = short_manifest();
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
            guardian_public_keys.as_slice(),
        );

        let pre_voting_data = PreVotingData {
            manifest: election_manifest.clone(),
            parameters: election_parameters,
            hashes,
            hashes_ext,
            public_key: joint_election_public_key,
        };
        let device = Device::new("Some encryption device", pre_voting_data);
        let seed = vec![0, 1, 2, 3];
        let mut csprng = Csprng::new(&seed);
        let primary_nonce = vec![0, 1, 2, 2, 2, 2, 2, 2, 3];
        let voter1 = BTreeMap::from([ // Voting on 1 and 3 only, ballot style 1
            (
                Index::from_one_based_index(1).unwrap(),
                ContestSelection { vote: vec![0, 1, 0, 0] },
            ),
            (
                Index::from_one_based_index(3).unwrap(),
                ContestSelection {
                    vote: vec![0, 1, 0],
                },
            ),
        ]);

        let voter2 = BTreeMap::from([ // Voting on 2 and 3 only, ballot style 2
            (
                Index::from_one_based_index(2).unwrap(),
                ContestSelection { vote: vec![0, 1, 0] },
            ),
            (
                Index::from_one_based_index(3).unwrap(),
                ContestSelection {
                    vote: vec![0, 1, 0],
                },
            ),
        ]);
        let voter3 = BTreeMap::from([ // Voting on all three, ballot style 3
            (
                Index::from_one_based_index(1).unwrap(),
                ContestSelection { vote: vec![1, 0, 0, 0] },
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

        let encrypted_ballots = vec![ballot_voter1, ballot_voter2, ballot_voter3];
        let tally1 = tally_ballots1(&encrypted_ballots, &election_manifest).unwrap();
        let tally2 = tally_ballots2(&encrypted_ballots, &election_manifest).unwrap();
        let eq = tally1 == tally2;
        assert!(eq);
    }
}
