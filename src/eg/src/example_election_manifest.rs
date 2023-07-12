// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use crate::{
    ballot_style::BallotStyle,
    contest::{Contest, ContestOption},
    election_manifest::ElectionManifest,
};

/// Contains only a single 2-of-5 contest
pub fn example_election_manifest_small() -> ElectionManifest {
    ElectionManifest {
        ballot_styles: vec![],
        contests: vec![Contest {
            label: "Minister of Elemental Resources".to_string(),
            selection_limit: 2,
            options: vec![
                ContestOption {
                    label: "Tïtus Stormforge (Ætherwïng)".to_string(),
                },
                ContestOption {
                    label: "Fæ Willowgrove (Crystâlheärt)".to_string(),
                },
                ContestOption {
                    label: "Tèrra Stonebinder (Independent)".to_string(),
                },
                ContestOption {
                    label: "Èlena Wîndwhisper (Technocrat)".to_string(),
                },
                ContestOption {
                    label: "Élyria Moonshadow (Crystâlheärt)".to_string(),
                },
            ],
        }],
    }
}

pub fn example_election_manifest_2022_king_county() -> ElectionManifest {
    ElectionManifest {
        ballot_styles: vec![
            BallotStyle {
                label: "SEA-32-2153".to_string(), // 1	32	7	5
                contests: vec![1, 3, 6, 7, 8, 14, 15, 16, 17, 18, 19, 20],
            },
            BallotStyle {
                label: "RED-48-0948".to_string(), // 6	48	1
                contests: vec![1, 2, 11, 12, 13],
            },
            BallotStyle {
                label: "BEL-41-0011".to_string(), // 9	41	9
                contests: vec![1, 5, 9, 10],
            },
        ],
        contests: vec![
            Contest {
                label: "United States Senator".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Patty Murray (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Tiffany Smiley (Prefers Republican Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "United States Representative: Congressional District No. 1".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Suzan DelBene (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Vincent J Cavaleri (Prefers Republican Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "United States Representative: Congressional District No. 7".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Pramila Jayapal (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Cliff Moon (Prefers Republican Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "United States Representative Congressional District No. 8".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Kim Schrier (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Matt Larkin (Prefers Republican Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "United States Representative Congressional District No. 9".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Adam Smith (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Doug Basler (Prefers Republican Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "Legislative District 32, State Senator".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Jesse Salomon (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Patricia Weber (Prefers Democratic Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "Legislative District 32, State Representative Pos. 1".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Cindy Ryu (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Lori Theis (Prefers Election Integrity Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "Legislative District 32, State Representative Pos. 2".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Lauren Davis (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Anthony Hubbard (Prefers Republican Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "Legislative District 41, State Representative Pos. 1".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Tana Senn (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Mike Nykreim (Prefers Election Integrity Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "Legislative District 41, State Representative Pos. 2".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "My-Linh T. Thai (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Al Rosenthal (Prefers Republican Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "Legislative District 48, State Senator".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Patty Kuderer (Prefers Democratic Party)".to_string(),
                    },
                    ContestOption {
                        label: "Michelle Darnell (Prefers Republican Party)".to_string(),
                    },
                ],
            },
            Contest {
                label: "Legislative District 48, State Representative Pos. 1".to_string(),
                selection_limit: 1,
                options: vec![ContestOption {
                    label: "Vandana Slatter (Prefers Democratic Party)".to_string(),
                }],
            },
            Contest {
                label: "Legislative District 48, State Representative Pos. 2".to_string(),
                selection_limit: 1,
                options: vec![ContestOption {
                    label: "Amy Walen (Prefers Democratic Party)".to_string(),
                }],
            },
            Contest {
                label: "City of Seattle, Municipal Court Judge Position No. 1".to_string(),
                selection_limit: 1,
                options: vec![ContestOption {
                    label: "Cat McDowall".to_string(),
                }],
            },
            Contest {
                label: "City of Seattle, Municipal Court Judge Position No. 2".to_string(),
                selection_limit: 1,
                options: vec![ContestOption {
                    label: "Andrea Chin".to_string(),
                }],
            },
            Contest {
                label: "City of Seattle, Municipal Court Judge Position No. 3".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Adam Eisenberg".to_string(),
                    },
                    ContestOption {
                        label: "Pooja Vaddadi".to_string(),
                    },
                ],
            },
            Contest {
                label: "City of Seattle, Municipal Court Judge Position No. 4".to_string(),
                selection_limit: 1,
                options: vec![ContestOption {
                    label: "Anita Crawford-Willis".to_string(),
                }],
            },
            Contest {
                label: "City of Seattle, Municipal Court Judge Position No. 5".to_string(),
                selection_limit: 1,
                options: vec![ContestOption {
                    label: "Willie Gregory".to_string(),
                }],
            },
            Contest {
                label: "City of Seattle, Municipal Court Judge Position No. 6".to_string(),
                selection_limit: 1,
                options: vec![ContestOption {
                    label: "Faye R. Chess".to_string(),
                }],
            },
            Contest {
                label: "City of Seattle, Municipal Court Judge Position No. 7".to_string(),
                selection_limit: 1,
                options: vec![
                    ContestOption {
                        label: "Damon Shadid".to_string(),
                    },
                    ContestOption {
                        label: "Nyjat Rose-Akins".to_string(),
                    },
                ],
            },
        ],
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
        ballot_styles: vec![],
            contests: vec![
                Contest {
                    label: "For President and Vice President of The United Realms of Imaginaria"
                        .to_string(),
                    selection_limit: 1,
                    options: vec![
                        ContestOption {
                            label:
                                "Thündéroak, Vâlêriana D. Ëverbright, Ålistair R. Jr. (Ætherwïng)"
                                    .to_string(),
                        },
                        ContestOption {
                            label: "Stârførge, Cássánder A. Møonfire, Célestïa L. (Crystâlheärt)".to_string(),
                        },
                    ],
                },
                Contest {
                    label: "Minister of Arcane Sciences".to_string(),
                    selection_limit: 1,
                    options: vec![
                        ContestOption {
                            label: "Élyria Moonshadow (Crystâlheärt)".to_string(),
                        },
                        ContestOption {
                            label: "Archímedes Darkstone (Ætherwïng)".to_string(),
                        },
                        ContestOption {
                            label: "Seraphína Stormbinder (Independent)".to_string(),
                        },
                        ContestOption {
                            label: "Gávrïel Runëbørne (Stärsky)".to_string(),
                        },
                    ],
                },
                Contest {
                    label: "Minister of Elemental Resources".to_string(),
                    selection_limit: 1,
                    options: vec![
                        ContestOption {
                            label: "Tïtus Stormforge (Ætherwïng)".to_string(),
                        },
                        ContestOption {
                            label: "Fæ Willowgrove (Crystâlheärt)".to_string(),
                        },
                        ContestOption {
                            label: "Tèrra Stonebinder (Independent)".to_string(),
                        },
                    ],
                },
                Contest {
                    label: "Minister of Dance".to_string(),
                    selection_limit: 1,
                    options: vec![
                        ContestOption {
                            label: "Äeliana Sunsong (Crystâlheärt)".to_string(),
                        },
                        ContestOption {
                            label: "Thâlia Shadowdance (Ætherwïng)".to_string(),
                        },
                        ContestOption {
                            label: "Jasper Moonstep (Stärsky)".to_string(),
                        },
                    ],
                },
                Contest {
                    label: "Gränd Cøuncil of Arcáne and Technomägical Affairs".to_string(),
                    selection_limit: 3,
                    options: vec![
                        ContestOption {
                            label: "Ìgnatius Gearsøul (Crystâlheärt)".to_string(),
                        },
                        ContestOption {
                            label: "Èlena Wîndwhisper (Technocrat)".to_string(),
                        },
                        ContestOption {
                            label: "Bërnard Månesworn (Ætherwïng)".to_string(),
                        },
                        ContestOption {
                            label: "Èmeline Glîmmerwillow (Ætherwïng)".to_string(),
                        },
                        ContestOption {
                            label: "Nikólai Thunderstrîde (Independent)".to_string(),
                        },
                        ContestOption {
                            label: "Lïliana Fîrestone (Pęacemaker)".to_string(),
                        },
                        ContestOption {
                            label: "Émeric Crystálgaze (Førestmíst)".to_string(),
                        },
                        ContestOption {
                            label: "Séraphine Lùmenwing (Stärsky)".to_string(),
                        },
                        ContestOption {
                            label: "Rãfael Stëamheart (Ætherwïng)".to_string(),
                        },
                        ContestOption {
                            label: "Océane Tidecaller (Pęacemaker)".to_string(),
                        },
                        ContestOption {
                            label: "Elysêa Shadowbinder (Independent)".to_string(),
                        },
                    ],
                },
                Contest {
                    label: "Proposed Amendment No. 1 Equal Representation for Technological and Magical Profeſsions".to_string(),
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
                    label: "Privacy Protection in Techno-Magical Communications Act".to_string(),
                    selection_limit: 1,
                    options: referendum_options.clone(),
                },
                Contest {
                    label: "Public Transport Modernization and Enchantment Proposal".to_string(),
                    selection_limit: 1,
                    options: referendum_options.clone(),
                },
                Contest {
                    label: "Renewable Ætherwind Infrastructure Initiative".to_string(),
                    selection_limit: 1,
                    options: referendum_options,
                },
                Contest {
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
