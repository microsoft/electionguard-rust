// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(clippy::needless_lifetimes)] //? TODO: Remove temp development code
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    //borrow::Cow,
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //hash::{BuildHasher, Hash, Hasher},
    io::{
        //BufRead, Cursor,
        Write,
    },
    //iter::zip,
    //marker::PhantomData,
    //path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    //str::FromStr,
    //sync::OnceLock,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
//use either::Either;
//use hashbrown::HashMap;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use util::abbreviation::Abbreviation;

use eg::{
    eg::{Eg, EgConfig},
    election_parameters::ElectionParameters,
    fixed_parameters::FixedParameters,
    resource::{
        ElectionDataObjectId as EdoId, ProduceResource, ProduceResourceExt, Resource,
        ResourceFormat, ResourceId, ResourceIdFormat,
    },
    serializable::SerializablePretty,
    varying_parameters::VaryingParameters,
};

//=================================================================================================|

fn main() -> ExitCode {
    use tracing::Level;
    use tracing_subscriber::fmt::format::FmtSpan;

    // Tracing Subscriber for logging.
    let subscriber_fmt = tracing_subscriber::fmt()
        //.with_ansi(false)
        //.with_file(false)
        .with_max_level(Level::TRACE)
        //.with_level(true)
        //.with_line_number(false)
        .with_span_events(FmtSpan::ACTIVE)
        .with_target(false)
        //.with_thread_ids(false)
        //.with_thread_names(false)
        .without_time()
        .finish();

    // Call `main2`
    tracing::subscriber::with_default(subscriber_fmt, || -> ExitCode {
        let result = async_global_executor::block_on(main2());

        let ec = match result {
            Ok(_) => {
                info!("Success!");
                ExitCode::SUCCESS
            }
            Err(e) => {
                error!("Error: {e:#}");
                ExitCode::FAILURE
            }
        };
        info!(name: "finished", "Finished, exiting with code: {ec:?}");
        ec
    })
}

async fn main2() -> Result<()> {
    info!(name: "started", "Started");

    let csprng_seed_str = "demo-eg";
    info!(csprng_seed_str);

    // Specify the election parameters
    let n = 5;
    let k = 3;

    info!(N = n, "Number of guardians:");
    info!(K = k, "Guardian quorum threshold:");

    let cnt_ballots = 10_usize;
    info!(cnt_ballots, "Number of ballots:");

    let eg = {
        let mut config = EgConfig::new();
        config.use_insecure_deterministic_csprng_seed_str(csprng_seed_str);
        config.enable_test_data_generation_n_k(n, k)?;

        // test code to only show specific mappings
        config.resourceproducer_registry_mut().registrations_retain(
            |registryengry_key, registryengry_value| {
                registryengry_key.name == "Specific" || registryengry_key.name == "ExampleData"
            },
        );

        Eg::from_config(config)
    };
    let eg = eg.as_ref();

    format!("{eg:#?}")
        .lines()
        .for_each(|line| debug!("`Eg`: {line}"));

    let (egds_version, egds_version_rsrc): (
        Arc<eg::egds_version::ElectionGuard_DesignSpecification_Version>,
        _,
    ) = eg
        .produce_resource_downcast(&ResourceIdFormat {
            rid: ResourceId::ElectionGuardDesignSpecificationVersion,
            fmt: ResourceFormat::ConcreteType,
        })
        .await?;
    info!("{egds_version:#?}");
    info!("source: {egds_version_rsrc}");

    pretty_print_to_stderr(
        egds_version.as_ref(),
        "ElectionGuardDesignSpecificationVersion",
    );

    let (egds_version_slicebytes, egds_version_slicebytes_rsrc) = eg
        .produce_resource(&ResourceIdFormat {
            rid: ResourceId::ElectionGuardDesignSpecificationVersion,
            fmt: ResourceFormat::SliceBytes,
        })
        .await?;
    info!("{egds_version_slicebytes:#?} {egds_version_slicebytes_rsrc}");
    info!("{egds_version_slicebytes:?} {egds_version_slicebytes_rsrc}");

    let (fixed_parameters, rsrc): (Arc<FixedParameters>, _) = eg
        .produce_resource_downcast(&EdoId::FixedParameters.validated_type_ridfmt())
        .await?;
    info!("{fixed_parameters:#?}");
    info!("source: {rsrc}");

    pretty_print_resource_to_stderr(fixed_parameters);

    let (fixed_parameters_info, rsrc): (Arc<FixedParameters>, _) = eg
        .produce_resource_downcast(&EdoId::FixedParameters.info_type_ridfmt())
        .await?;

    pretty_print_resource_to_stderr(fixed_parameters_info);

    /*
    info!("{fixed_parameters_info:#?}");
    info!("source: {rsrc}");

    let (varying_parameters, rsrc): (Arc<VaryingParameters>, _) =
        eg.produce_resource_downcast(&EdoId::VaryingParameters.validated_type_ridfmt())?;
    info!("{varying_parameters:#?}");
    info!("source: {rsrc}");

    let (election_parameters, rsrc): (Arc<ElectionParameters>, _) =
        eg.produce_resource_downcast(&EdoId::ElectionParameters.validated_type_ridfmt())?;
    info!("{election_parameters:#?}");
    info!("source: {rsrc}");
    // */

    Ok(())
}

//?     #  Write election parameters
//?     let election_parameters_json_file = artifacts_public_dir | path join "election_parameters.json"
//?     if not ($election_parameters_json_file | path exists) {
//?         run-subprocess --delimit [
//?             (eg_exe) write-parameters
//?                 --n $election_parameters.n
//?                 --k $election_parameters.k
//?                 --date $election_parameters.date
//?                 --info $election_parameters.info
//?                 --ballot-chaining prohibited
//?         ]
//?
//?         if not ($election_parameters_json_file | path exists) {
//?             log error $"ERROR: Election parameters file does not exist: ($election_parameters_json_file)"
//?             exit 1
//?         }
//?     }

//?     #  Verify standard parameters
//?     let standard_parameters_verified_file = artifacts_public_dir | path join "standard_parameters_verified.txt"
//?     if not ($standard_parameters_verified_file | path exists) {
//?         run-subprocess --delimit [
//?             (eg_exe) --insecure-deterministic verify-standard-parameters
//?         ]
//?
//?         log info $"Standard parameters: Verified! >($standard_parameters_verified_file)"
//?     }
//?
//?     #  Write election manifest (canonical and pretty), then validate them with the schema
//?
//?     let election_manifest_pretty_json_file = artifacts_public_dir | path join "election_manifest.json"
//?     let election_manifest_canonical_json_file = artifacts_public_dir | path join "election_manifest_canonical.bin"
//?
//?     if not ($election_manifest_pretty_json_file | path exists) {
//?         run-subprocess --delimit [
//?             (eg_exe) write-manifest --in-example --out-format pretty
//?         ]
//?
//?         if not ($election_manifest_pretty_json_file | path exists) {
//?             log error $"ERROR: Election manifest \(pretty) file does not exist: ($election_manifest_pretty_json_file)"
//?             exit 1
//?         }
//?     }
//?
//?     if not ($election_manifest_canonical_json_file | path exists) {
//?         run-subprocess --delimit [
//?             (eg_exe) write-manifest --in-example --out-format canonical
//?         ]
//?
//?         if not ($election_manifest_canonical_json_file | path exists) {
//?             log error $"ERROR: Election manifest \(canonical) file does not exist: ($election_manifest_canonical_json_file)"
//?             exit 1
//?         }
//?     }

//?     #  Write hashes
//?     let hashes_json_file = artifacts_public_dir | path join "hashes.json"
//?     if not ($hashes_json_file | path exists) {
//?         run-subprocess --delimit [
//?             (eg_exe) --insecure-deterministic write-hashes
//?         ]
//?
//?         if not ($hashes_json_file | path exists) {
//?             log error $"ERROR: Hashes .json file does not exist: ($hashes_json_file)"
//?             exit 1
//?         }
//?     }

//?     #  For each guardian
//?     for $i in 1..$election_parameters.n {
//?         egtest_per_guardian $i --no-jsonschema=$no_jsonschema
//?     }
//?
//?     #  Write joint public key
//?     for k and k-hat
//?     let joint_public_key_json_file = artifacts_public_dir | path join "joint_public_key.json"
//?     if not ($joint_public_key_json_file | path exists) {
//?         run-subprocess --delimit [
//?             (eg_exe) --insecure-deterministic write-joint-election-public-key
//?         ]
//?     }
//?     if not ($joint_public_key_json_file | path exists) {
//?         log error $"ERROR: Joint election public key .json file does not exist: ($joint_public_key_json_file)"
//?         exit 1
//?     }

//?     #  Write ExtendedBaseHash
//?     let extended_base_hash_json_file = artifacts_public_dir | path join "extended_base_hash.json"
//?     if not ($extended_base_hash_json_file | path exists) {
//?         run-subprocess --delimit [ (eg_exe) --insecure-deterministic write-hashes-ext ]
//?     }

//?     #  Write PreVotingData
//?     let pre_voting_data_json_file = artifacts_public_dir | path join "pre_voting_data.json"
//?     if not ($pre_voting_data_json_file | path exists) {
//?         run-subprocess --delimit [ (eg_exe) --insecure-deterministic write-pre-voting-data ]
//?     }
//?
//?     #  Write GeneratedTestDataVoterSelections
//?     for $i in 1..$num_ballots {
//?         egtest_per_random_voter $i --no-jsonschema=$no_jsonschema
//?     }
//?
//?     #
//?     #  Tests success!
//?     #
//?     log info ""
//?     log info "ElectionGuard tests successful!"
//?     log info ""
//?     log info "Resulting artifact files:"
//? }

//? def egtest_per_guardian [
//?     i: int
//?     --no-jsonschema
//? ] {
//?     let guardian_secret_dir = (artifacts_dir) | path join $"SECRET_for_guardian_($i)"
//?     if not ($guardian_secret_dir | path exists) {
//?         mkdir $guardian_secret_dir
//?     }
//?
//?     let guardian_secret_key_file = $guardian_secret_dir | path join $"guardian_($i).SECRET_key.json"
//?     let guardian_public_key_file = artifacts_public_dir | path join $"guardian_($i).public_key.json"
//?     let guardian_name = $"Guardian ($i)"
//?
//?     log info $"---- Guardian ($i)"
//?     log info $"Secret key file: ($guardian_secret_key_file)"
//?     log info $"Public key file: ($guardian_public_key_file)"
//?
//?     if not ($guardian_secret_key_file | path exists) {
//?         if ($guardian_public_key_file | path exists) {
//?             rm $guardian_public_key_file
//?         }
//?
//?         run-subprocess --delimit [
//?             (eg_exe) --insecure-deterministic guardian-secret-key-generate --i $i --name $guardian_name
//?         ]
//?
//?         if not ($guardian_secret_key_file | path exists) {
//?             log error $"ERROR: Guardian ($i) secret key file does not exist: ($guardian_secret_key_file)"
//?             exit 1
//?         }
//?     }
//?
//?     if not ($guardian_public_key_file | path exists) {
//?         run-subprocess --delimit [
//?             (eg_exe) --insecure-deterministic guardian-secret-key-write-public-key --i $i
//?         ]
//?
//?         if not ($guardian_public_key_file | path exists) {
//?             log error $"Guardian ($i) public key file does not exist: ($guardian_public_key_file)"
//?             exit 1
//?         }
//?     }
//? }

//? def egtest_per_random_voter [
//?     i: int
//?     --no-jsonschema
//? ] {
//?     let random_voter_selections_dir = (artifacts_dir) | path join "random_voter_selections"
//?     if not ($random_voter_selections_dir | path exists) {
//?         mkdir $random_voter_selections_dir
//?     }
//?
//?     let voter_selections_file = $random_voter_selections_dir | path join $"random_($i).voter_selections.json"
//?     let random_voter_name = $"Random Voter ($i)"
//?
//?     log info $"---- ($random_voter_name)"
//?     log info $"Random voter selections file: ($voter_selections_file)"
//?
//?     if not ($voter_selections_file | path exists) {
//?         run-subprocess --delimit [
//?             (eg_exe) --insecure-deterministic generate-random-voter-selections --seed $i --out-file $voter_selections_file
//?         ]
//?     }
//?
//?     let ballots_dir = (artifacts_dir) | path join "ballots"
//?     if not ($ballots_dir | path exists) {
//?         mkdir $ballots_dir
//?     }
//?
//?     let ballot_file = $ballots_dir | path join $"ballots_($i).voter_selections.json"
//?
//?     log info $"Ballot file: ($ballot_file)"
//?
//?     if not ($voter_selections_file | path exists) {
//?         run-subprocess --delimit [
//?             (eg_exe) --insecure-deterministic create-ballot-from-voter-selections --voter-selections $voter_selections_file --out-file $ballot_file
//?         ]
//?     }
//? }

fn pretty_print_to_stderr(sp: &dyn SerializablePretty, title: &str) {
    let _ = (|| -> anyhow::Result<()> {
        static REP_CHAR_BEGIN: &str = "--vvvvv--";
        static REP_CHAR_END: &str = "--^^^^^--";
        let mut stderr = std::io::stderr();
        let stderr = &mut stderr;
        writeln!(stderr, "-{0}{0}{0}- {title} -{0}{0}{0}-", REP_CHAR_BEGIN)?;
        sp.to_stdiowrite_pretty(stderr)?;
        writeln!(stderr, "-{0}{0}{0}- {title} -{0}{0}{0}-", REP_CHAR_END)?;
        Ok(())
    })();
}

fn pretty_print_resource_to_stderr<T, U>(sp: T)
where
    T: AsRef<U>,
    U: Resource + SerializablePretty,
{
    let u: &U = sp.as_ref();
    let title = format!("{} as {}", u.rid(), u.format());
    pretty_print_to_stderr(u, &title);
}
