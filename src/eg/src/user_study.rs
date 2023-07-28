use std::collections::BTreeSet;

use util::csprng::Csprng;

use crate::{
    ballot_style::BallotStyle,
    election_manifest::{Contest, ContestIndex, ContestOption, ElectionManifest},
    election_parameters::ElectionParameters,
    election_record::PreVotingData,
    fixed_parameters::FixedParameters,
    guardian::GuardianIndex,
    guardian_secret_key::GuardianSecretKey,
    hashes::Hashes,
    hashes_ext::HashesExt,
    joint_election_public_key::JointElectionPublicKey,
    standard_parameters::STANDARD_PARAMETERS,
    varying_parameters::VaryingParameters,
};

pub fn user_study_manifest() -> ElectionManifest {
    let contests = [
        // Context index 1:
        Contest {
            label: "What is your favorite color?".to_string(),
            selection_limit: 1,
            options: [
                ContestOption {
                    label: "Red".to_string(),
                },
                ContestOption {
                    label: "Yellow".to_string(),
                },
                ContestOption {
                    label: "Blue".to_string(),
                },
                ContestOption {
                    label: "Green".to_string(),
                },
                ContestOption {
                    label: "Black".to_string(),
                },
                ContestOption {
                    label: "White".to_string(),
                },
                ContestOption {
                    label: "None of these".to_string(),
                },
            ]
            .try_into()
            .unwrap(),
        },
        // Context index 2:
        Contest {
            label: "What is your favorite ice-cream flavor?".to_string(),
            selection_limit: 1,
            options: [
                ContestOption {
                    label: "Chocolate Chip".to_string(),
                },
                ContestOption {
                    label: "Strawberry".to_string(),
                },
                ContestOption {
                    label: "Vanilla".to_string(),
                },
                ContestOption {
                    label: "Mint".to_string(),
                },
                ContestOption {
                    label: "Cookies and Cream".to_string(),
                },
                ContestOption {
                    label: "Salted Caramel".to_string(),
                },
                ContestOption {
                    label: "None of these".to_string(),
                },
            ]
            .try_into()
            .unwrap(),
        },
        // Context index 3:
        Contest {
            label: "What gift voucher should all study participants receive?".to_string(),
            selection_limit: 1,
            options: [
                ContestOption {
                    label: "Amazon".to_string(),
                },
                ContestOption {
                    label: "Starbucks".to_string(),
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
            label: "Default Ballot Style".to_string(),
            contests: BTreeSet::from(
                [1, 2, 3].map(|ix1| ContestIndex::from_one_based_index(ix1).unwrap()),
            ),
        },
    ]
    .try_into()
    .unwrap();

    ElectionManifest {
        label: "ElectionGuard User Study".to_string(),
        contests,
        ballot_styles,
    }
}

pub fn user_study_parameters() -> ElectionParameters {
    let fixed_parameters: FixedParameters = (*STANDARD_PARAMETERS).clone();

    let varying_parameters = VaryingParameters {
        n: GuardianIndex::from_one_based_index(1).unwrap(),
        k: GuardianIndex::from_one_based_index(1).unwrap(),
        date: "2023-08-01".to_string(),
        info: "ElectionGuard User Study".to_string(),
    };

    ElectionParameters {
        fixed_parameters,
        varying_parameters,
    }
}

pub fn pre_voting_data(seed: &[u8]) -> PreVotingData {
    let manifest = user_study_manifest();
    let parameters = user_study_parameters();
    let hashes = Hashes::compute(&parameters, &manifest).unwrap();
    let mut csprng = Csprng::new(seed);
    let gsk = GuardianSecretKey::generate(
        &mut csprng,
        &parameters,
        GuardianIndex::from_one_based_index(1).unwrap(),
        Some("User Study Guardian".to_string()),
    );
    let gpk = [gsk.make_public_key()];
    let public_key = JointElectionPublicKey::compute(&parameters, &gpk).unwrap();
    let hashes_ext = HashesExt::compute(&parameters, &hashes, &public_key, &gpk);

    PreVotingData::new(manifest, parameters, hashes, hashes_ext, public_key)
}
