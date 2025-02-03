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
//!         Contains a [collection of](crate::guardian_secret_key::SecretCoefficients)
//!         [SecretCoefficient](crate::guardian_secret_key::SecretCoefficient)s.
//!
//!     - [GuardianPublicKey](crate::guardian_public_key::GuardianPublicKey) A guardian's public key.
//!         Contains a [collection of](crate::guardian_secret_key::CoefficientCommitments) [coefficient commitment](crate::guardian_secret_key::CoefficientCommitment)s
//!         and a vector of [CoefficientProofs](crate::guardian_coeff_proof::CoefficientProof).
//!
//!
//! - [JointPublicKey](crate::joint_public_key::JointPublicKey)
//!   A joint public key, `K` or `K-hat`.
//!
//! - [ExtendedBaseHash](crate::extended_base_hash::ExtendedBaseHash) The extended base hash. This can only be computed
//!   after the joint election public key is known.
//!
//! - [VerifiableDecryption](crate::verifiable_decryption::VerifiableDecryption) A decrypted plain-text with a [proof of correct decryption](crate::verifiable_decryption::DecryptionProof)

pub mod ballot;
pub mod ballot_scaled;
pub mod ballot_style;
#[cfg(test)]
mod ballot_test_tally;
#[cfg(test)]
mod ballot_test_verify;
pub mod chaining_mode;
pub mod ciphertext;
pub mod contest_data_fields_ciphertexts;
pub mod contest_data_fields_plaintexts;
pub mod contest_data_fields_tallies;
pub mod contest_hash;
pub mod contest_option_fields;
pub mod eg;
pub mod eg_config;
pub mod el_gamal;
pub mod election_manifest;
pub mod election_parameters;
pub mod election_record;
pub mod election_tallies;
pub mod errors;
#[cfg(any(feature = "eg-allow-test-data-generation", test))]
pub mod example_election_manifest;
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
pub mod guardian_share;
pub mod hash;
pub mod hashes;
pub mod joint_public_key;
pub mod loadable;
pub mod nonce;
pub mod pre_voting_data;
pub mod resource;
pub mod resource_category;
pub mod resource_csrng;
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
pub mod resourceproducer_specific;
pub mod resourceproducer_validatetoedo;
pub mod selection_limits;
pub mod serializable;
pub mod standard_parameters;
pub mod validatable;
pub mod varying_parameters;
pub mod verifiable_decryption;
pub mod voter_selections_plaintext;
pub mod voting_device;
pub mod zk;

static_assertions::assert_cfg!(
    not(all(
        feature = "eg-allow-insecure-deterministic-csprng",
        feature = "eg-forbid-insecure-deterministic-csprng"
    )),
    r##"Can't have both features `eg-allow-insecure-deterministic-csprng` and
 `eg-forbid-insecure-deterministic-csprng` active at the same time. You may need
 to specify `default-features = false, features = [\"only\",\"specifically\",\"desired\",\"features\"]`
 in `Cargo.toml`, and/or `--no-default-features --features only,the,specifically,desired,features`
 on the cargo command line. In VSCode, configure the `rust-analyzer.cargo.noDefaultFeatures` and
 `rust-analyzer.cargo.features` settings."##
);

static_assertions::assert_cfg!(
    not(all(
        feature = "eg-allow-test-data-generation",
        feature = "eg-forbid-test-data-generation"
    )),
    r##"Can't have both features `eg-allow-test-data-generation` and
 `eg-forbid-test-data-generation` active at the same time. You may need
 to specify `default-features = false, features = [\"only\",\"specifically\",\"desired\",\"features\"]`
 in `Cargo.toml`, and/or `--no-default-features --features only,the,specifically,desired,features`
 on the cargo command line. In VSCode, configure the `rust-analyzer.cargo.noDefaultFeatures` and
 `rust-analyzer.cargo.features` settings."##
);

static_assertions::assert_cfg!(
    not(all(
        feature = "eg-allow-toy-parameters",
        feature = "eg-forbid-toy-parameters"
    )),
    r##"Can't have both features `eg-allow-toy-parameters` and
 `eg-forbid-toy-parameters` active at the same time. You may need
 to specify `default-features = false, features = [\"only\",\"specifically\",\"desired\",\"features\"]`
 in `Cargo.toml`, and/or `--no-default-features --features only,the,specifically,desired,features`
 on the cargo command line. In VSCode, configure the `rust-analyzer.cargo.noDefaultFeatures` and
 `rust-analyzer.cargo.features` settings."##
);

/// The version of the ElectionGuard Design Specification implemented by this code.
pub static EGDS_VERSION: crate::fixed_parameters::ElectionGuardDesignSpecificationVersion =
    crate::fixed_parameters::ElectionGuardDesignSpecificationVersion { number: [2, 1] };

/// Implements [`KnowsFriendlyTypeName`](crate::loadable::KnowsFriendlyTypeName).
#[macro_export]
macro_rules! impl_knows_friendly_type_name {
    { $src:ident } => {
        impl $crate::loadable::KnowsFriendlyTypeName for $src {
            fn friendly_type_name() -> std::borrow::Cow<'static, str> {
                std::stringify!($src).into()
            }
        }
    };
}

/// Implements [`MayBeResource`](crate::resource::MayBeResource) for types that do not
/// implement [`Resource`](crate::resource::Resource) (which has a blanket implementation).
#[macro_export]
macro_rules! impl_MayBeResource_for_non_Resource {
    { $src:ident } => {
        impl $crate::resource::MayBeResource for $src {
            fn opt_as_resource(&self) -> Option<&dyn $crate::resource::Resource> {
                None
            }
            fn opt_as_resource_mut(&mut self) -> Option<&mut dyn $crate::resource::Resource> {
                None
            }
        }
    };
}

#[macro_export]
macro_rules! impl_Resource_for_simple_ResourceId_type {
    { $resource_type:path, $resource_id:ident, $resource_fmt:ident } => {
        impl $crate::resource::HasStaticResourceIdFormat for $resource_type {
            fn static_ridfmt(&self) -> &'static $crate::resource::ResourceIdFormat {
                static RIDFMT: $crate::resource::ResourceIdFormat = $crate::resource::ResourceIdFormat {
                    rid: $crate::resource::ResourceId::$resource_id,
                    fmt: $crate::resource::ResourceFormat::$resource_fmt,
                };
                &RIDFMT
            }
        }
    };
}

#[macro_export]
macro_rules! impl_Resource_for_simple_ElectionDataObjectId_type {
    { $concrete_dr_type:path, $edoid:ident, $memfn:ident } => {
        impl $crate::resource::HasStaticResourceIdFormat for $concrete_dr_type {
            fn static_ridfmt(&self) -> &'static $crate::resource::ResourceIdFormat {
                static RIDFMT: $crate::resource::ResourceIdFormat =
                $crate::resource::ElectionDataObjectId::$edoid.$memfn();
                &RIDFMT
            }
        }
    };
}

/// Implements [`Resource`](crate::resource::Resource) for
/// [`Validatable`](crate::validatable::Validatable) but non-[`Validated`](crate::validatable::Validated)
/// "Info" types having simple
/// [`ResourceId`s](crate::resource::ResourceId) which
/// implement [`HasStaticResourceIdFormat`](crate::resource::HasStaticResourceIdFormat)
#[macro_export]
macro_rules! impl_Resource_for_simple_ElectionDataObjectId_info_type {
    { $concrete_dr_type:path, $edoid:ident } => {
        $crate::impl_Resource_for_simple_ElectionDataObjectId_type! { $concrete_dr_type, $edoid, info_type_ridfmt }
    };
}

/// Implements [`Resource`](crate::resource::Resource) for
/// [`Validated`](crate::validatable::Validated) (non "Info") types having simple
/// [`ResourceId`s](crate::resource::ResourceId) which
/// implement [`HasStaticResourceIdFormat`](crate::resource::HasStaticResourceIdFormat)
#[macro_export]
macro_rules! impl_Resource_for_simple_ElectionDataObjectId_validated_type {
    { $concrete_dr_type:path, $edoid:ident } => {
        $crate::impl_Resource_for_simple_ElectionDataObjectId_type! { $concrete_dr_type, $edoid, validated_type_ridfmt }
    };
}

/// Implements [`Validatable`](crate::validatable::Validatable) and
/// [`Validated`](crate::validatable::Validated).
///
/// This macro encloses the function body which attempts to converts the `src` type to the
/// validated type or return a validation error.
///
/// See examples for use.
#[macro_export]
macro_rules! impl_validatable_validated {
    { $src:ident : $t_validatable:path, $eg:ident => EgResult< $t_validated:path > { $( $guts:tt )* } } => {
        impl $crate::validatable::Validatable for $t_validatable {
            type ValidatedInto = $t_validated;
        }

        impl $crate::validatable::Validatable for $t_validated {
            type ValidatedInto = $t_validated;
        }

        impl $crate::validatable::Validated for $t_validated {
            type ValidatedFrom = $t_validatable;

            #[allow(unused_variables)]
            #[allow(unused_imports)]
            fn try_validate_from(
                $src: Self::ValidatedFrom,
                $eg: & $crate::eg::Eg,
            ) -> $crate::errors::EgResult<$t_validated> {
                use $crate::validatable::*;
                $( $guts )*
            }
        }
    };

    /*
    /// Use this form when `Validatable` (_info) type implements HasStaticResourceIdFormat and Resource.
    ///
    /// It will register resource creation
    {
        $gather_rpspecific_registrations_fn:ident,
        $resource_id:expr,
        $src:ident : $t_validatable:path, $eg:ident => EgResult< $t_validated:path > { $( $guts:tt )* }
    } => {
        $crate::impl_validatable_validated! {
            $src : $t_validatable, $eg => EgResult<$t_validated>
        }

        fn $gather_rpspecific_registrations_fn(
            register_fn: &mut dyn FnMut($crate::resource_producer_registry::RPFnRegistration)
        ) {
            use $crate::{
                eg::Eg,
                resource::{Resource, ResourceFormat, ResourceId, ResourceIdFormat},
                resource_producer::{
                    ResourceProductionError,
                    ResourceProducer,
                    ResourceProductionResult, ResourceSource,
                    ResourceProducer_Any_Debug_Serialize,
                },
                resourceproducer_specific::{
                    GatherRPFnRegistrationsFnWrapper,
                },
                resource_producer_registry::{
                    FnNewResourceProducer,
                    GatherResourceProducerRegistrationsFnWrapper,
                    ResourceProducerCategory,
                    ResourceProducerRegistration,
                    ResourceProducerRegistry,
                    RPFnRegistration,
                },
                resource_production::RpOp,
                resource_slicebytes::ResourceSliceBytes,
            };

            #[allow(non_snake_case)]
            fn maybe_produce_ConcreteType(&Eg, &mut RpOp) -> Option<ResourceProductionResult> {
                let ridfmt_expected = ResourceIdFormat {
                    rid: $resource_id,
                    fmt: ResourceFormat::ConcreteType,
                };

                let ridfmt_requested = rp_op.target_ridfmt();

                if rp_op.target_ridfmt() != &ridfmt_expected {
                    return Some(Err(ResourceProductionError::UnexpectedResourceIdFormatRequested {
                        ridfmt_expected,
                        ridfmt_requested: ridfmt_requested.clone(),
                    }));
                }

                let rc: Rc<dyn Resource> = Rc::new(crate::EGDS_VERSION);
                let rpsrc = ResourceSource::constructed_concretetype();
                let result: ResourceProductionResult = Ok((rc, rpsrc));
                Some(result)
            }
            register_fn(RPFnRegistration::new_defaultproducer(
                ResourceIdFormat {
                    rid: ResourceId::ElectionGuardDesignSpecificationVersion,
                    fmt: ResourceFormat::ConcreteType,
                },
                Box::new(maybe_produce_ElectionGuardDesignSpecificationVersion_ConcreteType) )
            );


            f(&[crate::resource_producer_registry::ResourceProducerRegistration::new_defaultproducer(
                stringify!($t_validatable),
                ||,
            )]);
        }

        inventory::submit! {
            GatherRPFnRegistrationsFnWrapper($gather_rpspecific_registrations_fn)
        }
    };
    // */
}
