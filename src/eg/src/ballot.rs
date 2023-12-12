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
    ballot_style::BallotStyle, confirmation_code::confirmation_code,
    contest_encrypted::ContestEncrypted, contest_selection::ContestSelection, device::Device,
    election_manifest::ContestIndex, election_record::PreVotingData, hash::HValue, index::Index,
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::{
        ballot::BallotEncrypted, contest_selection::ContestSelection, device::Device,
        election_record::PreVotingData, example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters,
        guardian_secret_key::GuardianSecretKey, hashes::Hashes, hashes_ext::HashesExt,
        index::Index, joint_election_public_key::JointElectionPublicKey,
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
}
