// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::expect_used)] // This is `cfg(test)` code
#![allow(clippy::manual_assert)] // This is `cfg(test)` code
#![allow(clippy::new_without_default)] // This is `cfg(test)` code
#![allow(clippy::panic)] // This is `cfg(test)` code
#![allow(clippy::unwrap_used)] // This is `cfg(test)` code

use std::{collections::BTreeSet, sync::Arc};

use util::vec1::Vec1;

use crate::{
    ballot_style::{BallotStyle, BallotStyleInfo},
    election_manifest::{
        Contest, ContestIndex, ContestOption, ElectionManifest, ElectionManifestInfo,
    },
    errors::EgResult,
    resource::ProduceResource,
    selection_limits::{ContestSelectionLimit, OptionSelectionLimit},
    validatable::Validated,
    voting_device::VotingDeviceInformationSpec,
};

#[allow(clippy::useless_attribute)]
#[allow(unused_imports)]
use crate::resource::ProduceResourceExt;

pub fn example_election_manifest(
    produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
) -> EgResult<ElectionManifest> {
    let label = "General Election - The United Realms of Imaginaria".to_string();

    let referendum_options = Vec1::try_from(vec![
        ContestOption {
            opt_contest_ix: None,
            opt_contest_option_ix: None,
            label: "Prō".to_string(),
            selection_limit: OptionSelectionLimit::default(),
        },
        ContestOption {
            opt_contest_ix: None,
            opt_contest_option_ix: None,
            label: "Ĉontrá".to_string(),
            selection_limit: OptionSelectionLimit::default(),
        },
    ])?;

    let contests = Vec1::try_from(vec![
        // Contest index 1:
        Contest {
            opt_contest_ix: Some(1.try_into().unwrap()),
            label: "For President and Vice President of The United Realms of Imaginaria"
                .to_string(),
            selection_limit: ContestSelectionLimit::default(),
            contest_options: vec![
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label:
                        "Thündéroak, Vâlêriana D.\nËverbright, Ålistair R. Jr.\n(Ætherwïng)"
                            .to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Stârførge, Cássánder A.\nMøonfire, Célestïa L.\n(Crystâlheärt)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
            ].try_into()?,
        },
        // Contest 2
        Contest {
            opt_contest_ix: Some(2.try_into().unwrap()),
            label: "Minister of Elemental Resources".to_string(),
            selection_limit: ContestSelectionLimit::default(),
            contest_options: vec![
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Tïtus Stormforge\n(Ætherwïng)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Fæ Willowgrove\n(Crystâlheärt)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Tèrra Stonebinder\n(Independent)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ].try_into()?,
            },
        // Contest index 3:
        Contest {
            opt_contest_ix: Some(3.try_into().unwrap()),
            label: "Minister of Arcane Sciences".to_string(),
            selection_limit: ContestSelectionLimit::default(),
            contest_options: vec![
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Élyria Moonshadow\n(Crystâlheärt)".to_string(),
                    selection_limit: OptionSelectionLimit::LimitedOnlyByContest,
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Archímedes Darkstone\n(Ætherwïng)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Seraphína Stormbinder\n(Independent)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Gávrïel Runëbørne\n(Stärsky)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ].try_into()?,
            },
        // Contest index 4:
        Contest {
            opt_contest_ix: Some(4.try_into().unwrap()),
            label: "Minister of Dance".to_string(),
            selection_limit: ContestSelectionLimit::default(),
            contest_options: vec![
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Äeliana Sunsong\n(Crystâlheärt)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Thâlia Shadowdance\n(Ætherwïng)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Jasper Moonstep\n(Stärsky)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ].try_into()?,
            },
        Contest {
            opt_contest_ix: Some(5.try_into().unwrap()),
            label: "Gränd Cøuncil of Arcáne and Technomägical Affairs".to_string(),
            selection_limit: 1_u8.into(),
            contest_options: vec![
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Ìgnatius Gearsøul\n(Crystâlheärt)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Èlena Wîndwhisper\n(Technocrat)".to_string(),
                    selection_limit: 3_u8.into(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Bërnard Månesworn\n(Ætherwïng)".to_string(),
                    selection_limit: OptionSelectionLimit::LimitedOnlyByContest,
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Séraphine Lùmenwing\n(Stärsky)".to_string(),
                    selection_limit: 2_u8.into(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Nikólai Thunderstrîde\n(Independent)".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Lïliana Fîrestone\n(Pęacemaker)".to_string(),
                    selection_limit: OptionSelectionLimit::LimitedOnlyByContest,
                },
                ].try_into()?,
            },
        // Contest index 6:
        Contest {
            opt_contest_ix: Some(6.try_into().unwrap()),
            label: "Proposed Amendment No. 1\nEqual Representation for Technological and Magical Profeſsions".to_string(),
            selection_limit: ContestSelectionLimit::default(),
            contest_options: vec![
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "For".to_string(),
                    selection_limit: OptionSelectionLimit::LimitedOnlyByContest,
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Against".to_string(),
                    selection_limit: OptionSelectionLimit::default(),
                },
                ].try_into()?,
            },
        // Contest index 7:
        Contest {
            opt_contest_ix: Some(7.try_into().unwrap()),
            label: "Privacy Protection in Techno-Magical Communications Act".to_string(),
            selection_limit: ContestSelectionLimit::default(),
            contest_options: referendum_options.clone(),
        },
        // Contest index 8:
        Contest {
            opt_contest_ix: None,
            label: "Public Transport Modernization and Enchantment Proposal".to_string(),
            selection_limit: ContestSelectionLimit::default(),
            contest_options: referendum_options.clone(),
        },
        // Contest index 9:
        Contest {
            opt_contest_ix: Some(9.try_into().unwrap()),
            label: "Renewable Ætherwind Infrastructure Initiative".to_string(),
            selection_limit: ContestSelectionLimit::default(),
            contest_options: referendum_options,
        },
        // Contest index 10:
        Contest {
            opt_contest_ix: None,
            label: "For Librarian-in-Chief of Smoothstone County".to_string(),
            selection_limit: (i32::MAX as u32).try_into()?,
            contest_options: vec![
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Élise Planetes".to_string(),
                    selection_limit: OptionSelectionLimit::LimitedOnlyByContest,
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Théodoric Inkdrifter".to_string(),
                    selection_limit: (i32::MAX as u32).try_into()?,
                },
                ].try_into()?,
            },
        // Contest index 11:
        Contest {
            opt_contest_ix: Some(11.try_into().unwrap()),
            label: "Silvërspîre County Register of Deeds Sébastian Moonglôw to be retained"
                .to_string(),
            selection_limit: ContestSelectionLimit::default(),
            contest_options: vec![
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Retain".to_string(),
                    selection_limit: 375_u16.into(),
                },
                ContestOption {
                    opt_contest_ix: None,
                    opt_contest_option_ix: None,
                    label: "Remove".to_string(),
                    selection_limit: OptionSelectionLimit::LimitedOnlyByContest,
                },
                ].try_into()?,
            },
        // Some more names in the same style if more contest options are needed:
        //    label: "Èmeline Glîmmerwillow\n(Ætherwïng)".to_string(),
        //    label: "Émeric Crystálgaze\n(Førestmíst)".to_string(),
        //    label: "Rãfael Stëamheart\n(Ætherwïng)".to_string(),
        //    label: "Océane Tidecaller\n(Pęacemaker)".to_string(),
        //    label: "Elysêa Shadowbinder\n(Independent)".to_string(),
    ])?;

    let ballot_style_infos = Vec1::<BallotStyleInfo>::try_from(vec![
        BallotStyleInfo {
            opt_ballot_style_ix: Some(1.try_into()?),
            label: "Ballot style 1 has 1 contest: 1".to_string(),
            contests: BTreeSet::from(
                [
                    1u32 // It's important that this is 1, because the "simple" version just has one contest.
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(2.try_into()?),
            label: "Ballot style 2 has 1 contest: 2".to_string(),
            contests: BTreeSet::from(
                [
                    2u32
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(3.try_into()?),
            label: "Ballot style 3 has 1 contest: 3".to_string(),
            contests: BTreeSet::from(
                [
                    3u32
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(4.try_into()?),
            label: "Ballot style 4 has 1 contest: 4".to_string(),
            contests: BTreeSet::from(
                [
                    4u32
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(5.try_into()?),
            label: "Ballot style 5 has 1 contest: 5".to_string(),
            contests: BTreeSet::from(
                [
                    5u32
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(6.try_into()?),
            label: "Ballot style 6 has 1 contest: 6".to_string(),
            contests: BTreeSet::from(
                [
                    6u32
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(7.try_into()?),
            label: "Ballot style 7 has 1 contest: 7".to_string(),
            contests: BTreeSet::from(
                [
                    7u32
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(8.try_into()?),
            label: "Ballot style 8 has 1 contest: 8".to_string(),
            contests: BTreeSet::from(
                [
                    8u32
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(9.try_into()?),
            label: "Ballot style 9 has 1 contest: 9".to_string(),
            contests: BTreeSet::from(
                [
                    9u32
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(10.try_into()?),
            label: "Ballot style 10 has 1 contest: 10".to_string(),
            contests: BTreeSet::from(
                [
                    10u32
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(11.try_into()?),
            label: "Ballot style 11 has 1 contest: 11".to_string(),
            contests: BTreeSet::from(
                [
                    11u32
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(12.try_into()?),
            label: "Ballot style 12 has 2 contests: 1, 2".to_string(),
            contests: BTreeSet::from(
                [
                    1u32, 2
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(13.try_into()?),
            label: "Ballot style 13 (Smoothstone County Ballot) has 10 contests: 1 through 10".to_string(),
            contests: BTreeSet::from(
                [
                    1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(14.try_into()?),
            label: "Ballot style 14 (Silvërspîre County Ballot) has 10 contests: 1 through 11, skipping 10".to_string(),
            contests: BTreeSet::from(
                [
                    1u32, 2, 3, 4, 5, 6, 7, 8, 9, 11
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(15.try_into()?),
            label: "Ballot style 15 has 2 contests: 1 and 3".to_string(),
            contests: BTreeSet::from(
                [
                    1u32, 3
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(16.try_into()?),
            label: "Ballot style 16 has 2 contests: 2 and 3".to_string(),
            contests: BTreeSet::from(
                [
                    2u32, 3
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
        BallotStyleInfo {
            opt_ballot_style_ix: Some(17.try_into()?),
            label: "Ballot style 17 has 3 contests: 1, 2, and 3".to_string(),
            contests: BTreeSet::from(
                [
                    1u32, 2, 3
                ]
                .map(|i| ContestIndex::try_from_one_based_index_u32(i).unwrap()),
            ),
        },
    ])?;

    let mut ballot_styles: Vec1<BallotStyle> = Vec1::new();
    for bsi in ballot_style_infos {
        let bs = BallotStyle::try_validate_from(bsi, produce_resource)?;
        ballot_styles.try_push(bs)?;
    }

    let voting_device_information_spec = Arc::new(VotingDeviceInformationSpec::default());

    use either::Either::*;

    let election_manifest_info = ElectionManifestInfo {
        label,
        contests,
        ballot_styles: Right(ballot_styles),
        voting_device_information_spec,
    };

    ElectionManifest::try_validate_from(election_manifest_info, produce_resource)
}
