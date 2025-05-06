// Copyright (C) Microsoft Corporation. All rights reserved.

//! The ElectionGuard 2.1 Reference Implementation in Rust -- Core Library
//!
//! This library provides the core types and functions needed to use ElectionGuard 2.1 as part of
//! an actual system.
//!
//! Here are some links to some of the more central types.
//!
//! - [ElectionManifest](crate::election_manifest::ElectionManifest) The election manifest defines
//!   the basic election_parameters of the election, the contests, and the ballot styles.
//!
//!   - [ElectionParameters](crate::election_parameters::ElectionParameters) Election election_parameters
//!     consist of:
//!
//!     - [FixedParameters](crate::fixed_parameters::FixedParameters) such as the *Design Specification*
//!       version, and the choice of primes `p` and `q`. The only supported values are the
//!       documented standard parameters documented in the Design Specification.
//!
//!     - [VaryingParameters](crate::varying_parameters::VaryingParameters) These election_parameters may
//!       vary for an individual election, such as the number of guardians `n` and the guardian
//!       quorum threshold `k`.
//!
//!   - [Contest](crate::election_manifest::Contest) A contest as defined in the `ElectionManifest`.
//!     A `Contest` is a collection of [`ContestOption`](crate::election_manifest::ContestOption)s.
//!     Each `Contest` may appear on zero or more ballot styles.
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
//!   and election manifest. Namely, the parameter base hash `h_p` and the election base hash `h_b`.
//!
//! - Guardians hold the keys to decrypt election results
//!
//!     - [GuardianSecretKey](crate::guardian_secret_key::GuardianSecretKey) A guardian's secret key.
//!       Contains a [collection of](crate::guardian_secret_key::SecretCoefficients)
//!       [SecretCoefficient](crate::guardian_secret_key::SecretCoefficient)s.
//!
//!     - [GuardianPublicKey](crate::guardian_public_key::GuardianPublicKey) A guardian's public key.
//!       Contains a [collection of](crate::guardian_secret_key::CoefficientCommitments) [coefficient commitment](crate::guardian_secret_key::CoefficientCommitment)s
//!       and a vector of [CoefficientProofs](crate::guardian_coeff_proof::CoefficientProof).
//!
//!
//! - [JointPublicKey](crate::joint_public_key::JointPublicKey)
//!   A joint public key, `K` or `K-hat`.
//!
//! - [ExtendedBaseHash](crate::extended_base_hash::ExtendedBaseHash) The extended base hash. This can only be computed
//!   after the joint election public key is known.
//!
//! - [VerifiableDecryption](crate::verifiable_decryption::VerifiableDecryption) A decrypted plain-text with a [proof of correct decryption](crate::verifiable_decryption::DecryptionProof)

// There's [an issue](https://github.com/rust-lang/rust/issues/46991) that causes unimplemented
// serde::Serialize/Deserialize traits to be reported in whatever namespace path that happens
// to use the derive macro first. Using them here once for a trivial struct ensures they're
// reported in a less confusing way.
#[derive(serde::Serialize, serde::Deserialize)]
struct _WorkaroundPleaseIgnore;

pub mod algebra;
pub mod algebra_utils;
pub mod ballot;
pub mod ballot_scaled;
pub mod ballot_style;
pub mod chaining_mode;
pub mod ciphertext;
pub mod contest;
pub mod contest_data_fields;
pub mod contest_data_fields_ciphertexts;
pub mod contest_data_fields_plaintexts;
pub mod contest_data_fields_tallies;
pub mod contest_hash;
pub mod contest_option;
pub mod contest_option_fields;

// This is just a template to copy-and-paste to get started with new EDO types.
// It's enabled in test builds just to verify that it compiles.
#[cfg(any(feature = "eg-allow-test-data-generation", test))]
pub mod edo_template;

pub mod eg;
pub mod eg_config;
pub mod egds_version;
pub mod el_gamal;
pub mod election_manifest;
pub mod election_parameters;
pub mod election_record;
pub mod election_tallies;
pub mod errors;
#[cfg(any(feature = "eg-allow-test-data-generation", test))]
pub mod example_election_parameters;
#[cfg(any(feature = "eg-allow-test-data-generation", test))]
pub mod example_pre_voting_data;
pub mod extended_base_hash;
pub mod fixed_parameters;
pub mod guardian;
pub mod guardian_coeff_proof;
pub mod guardian_public_key;
pub mod guardian_public_key_trait;
pub mod guardian_secret_key;
pub mod hash;
pub mod hashes;
pub mod ident;
pub mod interguardian_share;
pub mod joint_public_key;
pub mod key;
pub mod label;
pub mod loadable;
pub mod nonce;
#[macro_use]
pub mod macros;
pub mod pre_voting_data;
pub mod preencrypted_ballots;
pub mod resource;
pub mod resource_category;
pub mod resource_id;
pub mod resource_path;
pub mod resource_persistence;
pub mod resource_producer;
pub mod resource_producer_registry;
pub mod resource_production;
pub mod resource_production_rules;
pub mod resource_production_rules_cost;
pub mod resource_slicebytes;
pub mod resourceproducer_egdsversion;
pub mod resourceproducer_electionparameters;
#[cfg(any(feature = "eg-allow-test-data-generation", test))]
pub mod resourceproducer_exampledata;
pub mod resourceproducer_pubfromsecretkey;
pub mod resourceproducer_slicebytesfromvalidated;
pub mod resourceproducer_specific;
pub mod resourceproducer_validatetoedo;
pub mod resources;
pub mod secret_coefficient;
pub mod secret_coefficients;
pub mod selection_limits;
pub mod serializable;
#[macro_use]
pub mod standard_parameters;
pub mod tally_ballots;
pub mod validatable;
pub mod varying_parameters;
pub mod verifiable_decryption;
pub mod voter_selections_plaintext;
pub mod voting_device;
pub mod zk;

use cfg_if::cfg_if;

#[rustfmt::skip]
static_assertions::assert_cfg!(
    not( all( feature = "eg-allow-insecure-deterministic-csprng",
              feature = "eg-forbid-insecure-deterministic-csprng" ) ),
    r##"Can't have both features `eg-allow-insecure-deterministic-csprng` and
 `eg-forbid-insecure-deterministic-csprng` active at the same time. You may need
 to specify `default-features = false, features = [\"only\",\"specifically\",\"desired\",\"features\"]`
 in `Cargo.toml`, and/or `--no-default-features --features only,specifically,desired,features`
 on the cargo command line. In VSCode, configure the `rust-analyzer.cargo.noDefaultFeatures` and
 `rust-analyzer.cargo.features` settings."##
);

#[rustfmt::skip]
static_assertions::assert_cfg!(
    not( all( feature = "eg-allow-test-data-generation",
              feature = "eg-forbid-test-data-generation" ) ),
    r##"Can't have both features `eg-allow-test-data-generation` and
 `eg-forbid-test-data-generation` active at the same time. You may need
 to specify `default-features = false, features = [\"only\",\"specifically\",\"desired\",\"features\"]`
 in `Cargo.toml`, and/or `--no-default-features --features only,specifically,desired,features`
 on the cargo command line. In VSCode, configure the `rust-analyzer.cargo.noDefaultFeatures` and
 `rust-analyzer.cargo.features` settings."##
);

#[rustfmt::skip]
static_assertions::assert_cfg!( not( any(
    all( feature =      "eg-forbid-reduced-params",
         any( feature = "eg-use-toy-params-q7p16",
              feature = "eg-use-toy-params-q16p32",
              feature = "eg-use-toy-params-q16p48",
              feature = "eg-use-toy-params-q24p64",
              feature = "eg-use-toy-params-q32p96",
              feature = "eg-use-toy-params-q32p128",
              feature = "eg-use-toy-params-q48p192",
              feature = "eg-use-toy-params-q64p256",
              feature = "eg-use-reduced-params-q256p3072",
              feature = "eg-use-standard-params-256q4096p" ) ),
    all( feature =      "eg-use-toy-params-q7p16",
         any( feature = "eg-use-toy-params-q16p32",
              feature = "eg-use-toy-params-q16p48",
              feature = "eg-use-toy-params-q24p64",
              feature = "eg-use-toy-params-q32p96",
              feature = "eg-use-toy-params-q32p128",
              feature = "eg-use-toy-params-q48p192",
              feature = "eg-use-toy-params-q64p256",
              feature = "eg-use-reduced-params-q256p3072",
              feature = "eg-use-standard-params-256q4096p" ) ),
    all( feature =      "eg-use-toy-params-q16p32",
         any( feature = "eg-use-toy-params-q16p48",
              feature = "eg-use-toy-params-q24p64",
              feature = "eg-use-toy-params-q32p96",
              feature = "eg-use-toy-params-q32p128",
              feature = "eg-use-toy-params-q48p192",
              feature = "eg-use-toy-params-q64p256",
              feature = "eg-use-reduced-params-q256p3072",
              feature = "eg-use-standard-params-256q4096p" ) ),
    all( feature =      "eg-use-toy-params-q16p48",
         any( feature = "eg-use-toy-params-q24p64",
              feature = "eg-use-toy-params-q32p96",
              feature = "eg-use-toy-params-q32p128",
              feature = "eg-use-toy-params-q48p192",
              feature = "eg-use-toy-params-q64p256",
              feature = "eg-use-reduced-params-q256p3072",
              feature = "eg-use-standard-params-256q4096p" ) ),
    all( feature =      "eg-use-toy-params-q24p64",
         any( feature = "eg-use-toy-params-q32p96",
              feature = "eg-use-toy-params-q32p128",
              feature = "eg-use-toy-params-q48p192",
              feature = "eg-use-toy-params-q64p256",
              feature = "eg-use-reduced-params-q256p3072",
              feature = "eg-use-standard-params-256q4096p" ) ),
    all( feature =      "eg-use-toy-params-q32p96",
         any( feature = "eg-use-toy-params-q32p128",
              feature = "eg-use-toy-params-q48p192",
              feature = "eg-use-toy-params-q64p256",
              feature = "eg-use-reduced-params-q256p3072",
              feature = "eg-use-standard-params-256q4096p" ) ),
    all( feature =      "eg-use-toy-params-q32p128",
         any( feature = "eg-use-toy-params-q48p192",
              feature = "eg-use-toy-params-q64p256",
              feature = "eg-use-reduced-params-q256p3072",
              feature = "eg-use-standard-params-256q4096p" ) ),
    all( feature =      "eg-use-toy-params-q48p192",
         any( feature = "eg-use-toy-params-q64p256",
              feature = "eg-use-reduced-params-q256p3072",
              feature = "eg-use-standard-params-256q4096p" ) ),
    all( feature =      "eg-use-toy-params-q64p256",
         any( feature = "eg-use-reduced-params-q256p3072",
              feature = "eg-use-standard-params-256q4096p" ) ),
    all( feature =      "eg-use-reduced-params-q256p3072",
         any( feature = "eg-use-standard-params-256q4096p" ) ),
    ) ),
    r##"Can't have multiple features `eg-forbid-reduced-params` and any `eg-use-(toy|reduced)-params-*`
 active at the same time. You may need to specify `default-features = false,
 features = [\"only\",\"specifically\",\"desired\",\"features\"]` in `Cargo.toml`, and/or
 `--no-default-features --features only,specifically,desired,features` on the cargo command
 line. In VSCode, configure the `rust-analyzer.cargo.noDefaultFeatures` and
 `rust-analyzer.cargo.features` settings."##
);

#[rustfmt::skip]
static_assertions::assert_cfg!(
    not( all( feature = "eg-allow-nonstandard-egds-version",
              feature = "eg-forbid-nonstandard-egds-version" ) ),
    r##"Can't have both features `eg-allow-nonstandard-egds-version` and
 `eg-forbid-nonstandard-egds-version` active at the same time. You may need
 to specify `default-features = false, features = [\"only\",\"specifically\",\"desired\",\"features\"]`
 in `Cargo.toml`, and/or `--no-default-features --features only,specifically,desired,features`
 on the cargo command line. In VSCode, configure the `rust-analyzer.cargo.noDefaultFeatures` and
 `rust-analyzer.cargo.features` settings."##
);

#[rustfmt::skip]
static_assertions::assert_cfg!(
    not( all( feature = "eg-allow-unsafe-code",
              feature = "eg-forbid-unsafe-code" ) ),
    r##"Can't have both features `eg-allow-unsafe-code` and `eg-forbid-unsafe-code` active at the
 same time. You may need to specify `default-features = false, features =
 [\"only\",\"specifically\",\"desired\",\"features\"]` in `Cargo.toml`, and/or
 `--no-default-features --features only,specifically,desired,features` on the cargo command
 line. In VSCode, configure the `rust-analyzer.cargo.noDefaultFeatures` and
 `rust-analyzer.cargo.features` settings."##
);

cfg_if! {
    if #[cfg( any(
        feature = "eg-use-toy-params-q7p16",
        feature = "eg-use-toy-params-q16p32",
        feature = "eg-use-toy-params-q16p48",
        feature = "eg-use-toy-params-q24p64",
        feature = "eg-use-toy-params-q32p96",
        feature = "eg-use-toy-params-q32p128",
        feature = "eg-use-toy-params-q48p192",
        feature = "eg-use-toy-params-q64p256" ) )]
    {
        static FIXEDPARAMETERS_KIND: crate::egds_version::ElectionGuard_FixedParameters_Kind =
            crate::egds_version::ElectionGuard_FixedParameters_Kind::Toy_Parameters;
    }
    else if #[cfg( feature = "eg-use-reduced-params-q256p3072" )]
    {
        static FIXEDPARAMETERS_KIND: crate::egds_version::ElectionGuard_FixedParameters_Kind =
            crate::egds_version::ElectionGuard_FixedParameters_Kind::Reduced_Security_Parameters;
    }
    else {
        use static_assertions::const_assert_eq;

        const_assert_eq!(cfg_parameter!(q_bits_total), 256);
        const_assert_eq!(cfg_parameter!(p_bits_total), 4096);

        static FIXEDPARAMETERS_KIND: crate::egds_version::ElectionGuard_FixedParameters_Kind =
            crate::egds_version::ElectionGuard_FixedParameters_Kind::Standard_Parameters;
    }
}

/// The version of the ElectionGuard Design Specification implemented by this code.
pub static EGDS_VERSION: &crate::egds_version::ElectionGuard_DesignSpecification_Version =
    &crate::egds_version::ElectionGuard_DesignSpecification_Version {
        version_number: [2, 1],
        qualifier: crate::egds_version::ElectionGuard_DesignSpecification_Version_Qualifier::Released_Specification_Version,
        fixed_parameters_kind: FIXEDPARAMETERS_KIND,
    };

/*
/// The version of the ElectionGuard Design Specification implemented by this code.
pub static EGDS_RELEASED_V2_1_WITH_STANDARD_PARAMS: crate::egds_version::ElectionGuard_DesignSpecification_Version =
    crate::egds_version::ElectionGuard_DesignSpecification_Version {
        version_number: [2, 1],
        qualifier: crate::egds_version::ElectionGuard_DesignSpecification_Version_Qualifier::Released_Specification_Version,
        fixed_parameters_kind: ,
    };

/// The version of the ElectionGuard Design Specification implemented by this code.
pub static EGDS_VERSION: &crate::egds_version::ElectionGuard_DesignSpecification_Version =
    &EGDS_RELEASED_V2_1_WITH_STANDARD_PARAMS;
// */
