// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use crate::{
    contest::{BallotStyle, Contest, ContestOption},
    election_manifest::ElectionManifest,
};

/// Contains only a single 2-of-5 contest
pub fn example_election_manifest_small() -> ElectionManifest {
    ElectionManifest {
        contests: vec![Contest {
            ballot_style: BallotStyle("Ministerial Election".to_string()),
            label: "Minister of Elemental Resources".to_string(),
            selection_limit: 2,
            options: vec![
                ContestOption {
                    label: "Tïtus Stormforge\n(Ætherwïng)".to_string(),
                },
                ContestOption {
                    label: "Fæ Willowgrove\n(Crystâlheärt)".to_string(),
                },
                ContestOption {
                    label: "Tèrra Stonebinder\n(Independent)".to_string(),
                },
                ContestOption {
                    label: "Èlena Wîndwhisper\n(Technocrat)".to_string(),
                },
                ContestOption {
                    label: "Élyria Moonshadow\n(Crystâlheärt)".to_string(),
                },
            ],
        }],
    }
}

pub fn example_election_manifest() -> ElectionManifest {
    let referendum_options = vec![
        ContestOption {
            label: "Prō".to_string(),
        },
        ContestOption {
            label: "Ĉontrá".to_string(),
        },
    ];

    ElectionManifest {
            contests: vec![
                Contest {
                    ballot_style: BallotStyle("Presidential Election".to_string()),
                    label: "For President and Vice President of The United Realms of Imaginaria"
                        .to_string(),
                    selection_limit: 1,
                    options: vec![
                        ContestOption {
                            label:
                                "Thündéroak, Vâlêriana D.\nËverbright, Ålistair R. Jr.\n(Ætherwïng)"
                                    .to_string(),
                        },
                        ContestOption {
                            label: "Stârførge, Cássánder A.\nMøonfire, Célestïa L.\n(Crystâlheärt)".to_string(),
                        },
                    ],
                },
                Contest {
                    ballot_style: BallotStyle("Ministerial Election".to_string()),
                    label: "Minister of Arcane Sciences".to_string(),
                    selection_limit: 1,
                    options: vec![
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
                    ],
                },
                Contest {
                    ballot_style: BallotStyle("Ministerial Election".to_string()),
                    label: "Minister of Elemental Resources".to_string(),
                    selection_limit: 1,
                    options: vec![
                        ContestOption {
                            label: "Tïtus Stormforge\n(Ætherwïng)".to_string(),
                        },
                        ContestOption {
                            label: "Fæ Willowgrove\n(Crystâlheärt)".to_string(),
                        },
                        ContestOption {
                            label: "Tèrra Stonebinder\n(Independent)".to_string(),
                        },
                    ],
                },
                Contest {
                    ballot_style: BallotStyle("Ministerial Election".to_string()),
                    label: "Minister of Dance".to_string(),
                    selection_limit: 1,
                    options: vec![
                        ContestOption {
                            label: "Äeliana Sunsong\n(Crystâlheärt)".to_string(),
                        },
                        ContestOption {
                            label: "Thâlia Shadowdance\n(Ætherwïng)".to_string(),
                        },
                        ContestOption {
                            label: "Jasper Moonstep\n(Stärsky)".to_string(),
                        },
                    ],
                },
                Contest {
                    ballot_style: BallotStyle("Grand Council Election".to_string()),
                    label: "Gränd Cøuncil of Arcáne and Technomägical Affairs".to_string(),
                    selection_limit: 3,
                    options: vec![
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
                    ],
                },
                Contest {
                    ballot_style: BallotStyle("Amendment Referrendum".to_string()),
                    label: "Proposed Amendment No. 1\nEqual Representation for Technological and Magical Profeſsions".to_string(),
                    selection_limit: 1,
                    options: vec![
                        ContestOption {
                            label: "For".to_string(),
                        },
                        ContestOption {
                            label: "Against".to_string(),
                        },
                    ],
                },
                Contest {
                    ballot_style: BallotStyle("Ballot Proposal".to_string()),
                    label: "Privacy Protection in Techno-Magical Communications Act".to_string(),
                    selection_limit: 1,
                    options: referendum_options.clone(),
                },
                Contest {
                    ballot_style: BallotStyle("Ballot Proposal".to_string()),
                    label: "Public Transport Modernization and Enchantment Proposal".to_string(),
                    selection_limit: 1,
                    options: referendum_options.clone(),
                },
                Contest {
                    ballot_style: BallotStyle("Ballot Proposal".to_string()),
                    label: "Renewable Ætherwind Infrastructure Initiative".to_string(),
                    selection_limit: 1,
                    options: referendum_options,
                },
                Contest {
                    ballot_style: BallotStyle("Ballot Proposal".to_string()),
                    label: "Silvërspîre County Register of Deeds Sébastian Moonglôw to be retained"
                        .to_string(),
                    selection_limit: 1,
                    options: vec![
                        ContestOption {
                            label: "Retain".to_string(),
                        },
                        ContestOption {
                            label: "Remove".to_string(),
                        },
                    ],
                },
            ],
        }
}
