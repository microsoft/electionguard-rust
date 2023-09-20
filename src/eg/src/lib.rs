// Copyright (C) Microsoft Corporation. All rights reserved.

//! The ElectionGuard 2.0 Reference Implenentation in Rust -- Core Library
//!
//! This library provides the core types and functions needed to use ElectionGuard 2.0 as part of
//! an actual system.
//!
//! Here are some links to some of the more central types.
//!
//! - [ElectionManifest](crate::election_manifest::ElectionManifest) The election manifest defines
//!   the basic parameters of the election, the contests, and the ballot styles.
//!
//!   - [ElectionParameters](crate::election_parameters::ElectionParameters) Election parameters
//!     consist of:
//!
//!     - [FixedParameters](crate::fixed_parameters::FixedParameters)
//!       The fixed parameters for the election.
//!       The parameters of their generation (e.g., size of primes p and q) are described by a
//!       [FixedParameterGenerationParameters](crate::fixed_parameters::FixedParameterGenerationParameters)
//!       structure.
//!       Typically, [STANDARD_PARAMETERS](static@crate::standard_parameters::STANDARD_PARAMETERS) will be used.
//!
//!     - [VaryingParameters](crate::varying_parameters::VaryingParameters) These are the parameters that
//!       may vary for an individual election, such as the number of guardians `n` and the guardian
//!       quorum threshold `k`.
//!   
//!   - [Contest](crate::election_manifest::Contest) A contest as defined in the `ElectionManifest`.
//!     A contest consists of zero or more `ContestOption`s.
//!     A contest may appear on zero or more ballot styles.
//!   
//!   - [ContestOption](crate::election_manifest::ContestOption) An option that may be selected
//!     (or specifically not-selected) by a voter. Some `Contests` may allow multiple selections.
//!
//!   - [BallotStyle](crate::ballot_style::BallotStyle) A ballot style, which defines the contest that appear
//!     on ballots of this style.
//!
//! - [HValue](crate::hash::HValue) Type which represents a hash output value of the ElectionGuard hash
//!   function 'H'. It is also the type used as the first parameter to the hash function.
//!
//! - [Hashes](crate::hashes::Hashes) The hash values which can be computed from the election parameters
//!   and election manifest. Namely, the parameter base hash `h_p`, the election manifest hash `h_m`,
//!   and the election base hash `h_b`.
//!
//! - [GuardianSecretKey](crate::guardian_secret_key::GuardianSecretKey) A guardian's secret key.
//!   Contains a [collection of](crate::guardian_secret_key::SecretCoefficients)
//!   [SecretCoefficient](crate::guardian_secret_key::SecretCoefficient)s.
//!
//! - [GuardianPublicKey](crate::guardian_public_key::GuardianPublicKey) A guardian's public key.
//!   Contains a [collection of](crate::guardian_secret_key::CoefficientCommitments) [coefficient commitment](crate::guardian_secret_key::CoefficientCommitment)s.
//!
//! - [JointElectionPublicKey](crate::joint_election_public_key::JointElectionPublicKey)
//!   The joint election public key.
//!
//! - [HashesExt](crate::hashes_ext::HashesExt) The extended base hash. This can only be computed
//!   after the joint election public key is known.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

pub mod ballot;
pub mod ballot_style;
pub mod confirmation_code;
pub mod contest_encrypted;
pub mod contest_hash;
pub mod contest_selection;
pub mod device;
pub mod election_manifest;
pub mod election_parameters;
pub mod election_record;
pub mod example_election_manifest;
pub mod example_election_parameters;
pub mod fixed_parameters;
pub mod guardian;
pub mod guardian_public_key;
pub mod guardian_public_key_info;
pub mod guardian_secret_key;
pub mod hash;
pub mod hashes;
pub mod hashes_ext;
pub mod index;
pub mod joint_election_public_key;
pub mod nonce;
pub mod standard_parameters;
pub mod varying_parameters;
pub mod vec1;
pub mod zk;
