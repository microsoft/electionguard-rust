// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
// `unwrap()` is justified here because these values are fixed at compile time.
// It is hoped that someday Rust's const generics feature will have improved to
// the point that we can prove this at compile time, and implement `From` instead.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use crate::{
    ballot_style::BallotStyle,
    election_manifest::{Contest, ContestIndex, ContestOption, ElectionManifest},
    vec1::Vec1,
};

pub fn example_election_manifest() -> ElectionManifest {
    let referendum_options: Vec1<ContestOption> = [
        ContestOption {
            label: "Prō".to_string(),
        },
        ContestOption {
            label: "Ĉontrá".to_string(),
        },
    ]
    .try_into()
    .unwrap();

    let contests = [
        // Contest index 1:
        Contest {
            label: "For President and Vice President of The United Realms of Imaginaria"
                .to_string(),
            selection_limit: 1,
            options: [
                ContestOption {
                    label:
                        "Thündéroak, Vâlêriana D.\nËverbright, Ålistair R. Jr.\n(Ætherwïng)"
                            .to_string(),
                },
                ContestOption {
                    label: "Stârførge, Cássánder A.\nMøonfire, Célestïa L.\n(Crystâlheärt)".to_string(),
                },
            ].try_into().unwrap(),
        },
        // Contest index 2:
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
        // Contest index 3:
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
        // Contest index 4:
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
        // Contest index 5:
        Contest {
            label: "Gränd Cøuncil of Arcáne and Technomägical Affairs".to_string(),
            selection_limit: 3,
            options: [
                ContestOption {
                    label: "Ìgnatius Gearsøul\n(Crystâlheärt)".to_string(),
                },
                ContestOption {
                    label: "Èlena Wîndwhisper\n(Technocrat)".to_string(),
                },
                ContestOption {
                    label: "Bërnard Månesworn\n(Ætherwïng)".to_string(),
                },
                ContestOption {
                    label: "Èmeline Glîmmerwillow\n(Ætherwïng)".to_string(),
                },
                ContestOption {
                    label: "Nikólai Thunderstrîde\n(Independent)".to_string(),
                },
                ContestOption {
                    label: "Lïliana Fîrestone\n(Pęacemaker)".to_string(),
                },
                ContestOption {
                    label: "Émeric Crystálgaze\n(Førestmíst)".to_string(),
                },
                ContestOption {
                    label: "Séraphine Lùmenwing\n(Stärsky)".to_string(),
                },
                ContestOption {
                    label: "Rãfael Stëamheart\n(Ætherwïng)".to_string(),
                },
                ContestOption {
                    label: "Océane Tidecaller\n(Pęacemaker)".to_string(),
                },
                ContestOption {
                    label: "Elysêa Shadowbinder\n(Independent)".to_string(),
                },
            ].try_into().unwrap(),
        },
        // Contest index 6:
        Contest {
            label: "Proposed Amendment No. 1\nEqual Representation for Technological and Magical Profeſsions".to_string(),
            selection_limit: 1,
            options: [
                ContestOption {
                    label: "For".to_string(),
                },
                ContestOption {
                    label: "Against".to_string(),
                },
            ].try_into().unwrap(),
        },
        // Contest index 7:
        Contest {
            label: "Privacy Protection in Techno-Magical Communications Act".to_string(),
            selection_limit: 1,
            options: referendum_options.clone(),
        },
        // Contest index 8:
        Contest {
            label: "Public Transport Modernization and Enchantment Proposal".to_string(),
            selection_limit: 1,
            options: referendum_options.clone(),
        },
        // Contest index 9:
        Contest {
            label: "Renewable Ætherwind Infrastructure Initiative".to_string(),
            selection_limit: 1,
            options: referendum_options,
        },
        // Contest index 10:
        Contest {
            label: "For Librarian-in-Chief of Smoothstone County".to_string(),
            selection_limit: 1,
            options: [
                ContestOption {
                    label: "Élise Planetes".to_string(),
                },
                ContestOption {
                    label: "Théodoric Inkdrifter".to_string(),
                },
            ].try_into().unwrap(),
        },
        // Contest index 11:
        Contest {
            label: "Silvërspîre County Register of Deeds Sébastian Moonglôw to be retained"
                .to_string(),
            selection_limit: 1,
            options: [
                ContestOption {
                    label: "Retain".to_string(),
                },
                ContestOption {
                    label: "Remove".to_string(),
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
                    1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, // missing 11
                ]
                .map(|ix1| ContestIndex::from_one_based_index(ix1).unwrap()),
            ),
        },
        // Ballot style index 2:
        BallotStyle {
            label: "Silvërspîre County Ballot".to_string(),
            contests: BTreeSet::from(
                [
                    1u32, 2, 3, 4, 5, 6, 7, 8, 9, 11, // missing 10
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
