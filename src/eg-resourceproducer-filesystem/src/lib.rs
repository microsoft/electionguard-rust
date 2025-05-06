// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
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

//! The ElectionGuard 2.1 Reference Implementation in Rust -- Optional filesystem support library
//!
//! This crate is useful when you wish to provide access to data persisted in files to
//! the code in the `eg` crate, and other code that may use it.

use std::{
    borrow::Cow,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    ffi::OsStr,
    //io::{BufRead, Cursor},
    path::{Path, PathBuf},
    sync::Arc,
    //str::FromStr,
    //sync::OnceLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use rand::{distr::Uniform, Rng, RngCore};
#[cfg(test)]
use serde::Serialize;
//use static_assertions::assert_obj_safe;
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

use eg::{
    eg::Eg,
    errors::{EgError, EgResult},
    loadable::LoadableFromStdIoReadValidatable,
    resource::{ProduceResource, ProduceResourceExt, Resource},
    resource_category::ResourceCategory,
    resource_id::{ElectionDataObjectId as EdoId, ResourceFormat, ResourceId, ResourceIdFormat},
    resource_persistence::ResourcePersistence,
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionError,
        ResourceProductionResult, ResourceSource,
    },
    resource_producer_registry::{
        FnNewResourceProducer, GatherResourceProducerRegistrationsFnWrapper,
        ResourceProducerCategory, ResourceProducerRegistration,
    },
    resource_production::RpOp,
    validatable::Validated,
};

//=================================================================================================|

/// A built-in [`ResourceProducer`] that provides
/// [`ResourceId::ElectionGuardDesignSpecificationVersion`].
#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Serialize))]
pub(crate) struct ResourceProducer_Filesystem;

impl ResourceProducer_Filesystem {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
    /*
    /// Opens the specified file for reading, or if "-" then read from stdin.
    /// Next it tries any specified artifact file.
    pub fn in_file_stdioread(
        &self,
        opt_path: Option<&PathBuf>,
        opt_artifact_file: Option<&ArtifactFile>,
    ) -> Result<(Box<dyn std::io::Read>, PathBuf)> {
        let mut open_options_read = OpenOptions::new();
        open_options_read.read(true);

        let stdioread_and_path: (Box<dyn std::io::Read>, PathBuf) = if let Some(path) = opt_path {
            let stdioread: Box<dyn std::io::Read> = if *path == PathBuf::from("-") {
                Box::new(std::io::stdin())
            } else {
                let file = open_options_read
                    .open(path)
                    .with_context(|| format!("Couldn't open file: {}", path.display()))?;
                Box::new(file)
            };

            (stdioread, path.clone())
        } else if let Some(artifact_file) = opt_artifact_file {
            let (file, path) = self.open(artifact_file, &open_options_read)?;
            let stdioread: Box<dyn std::io::Read> = Box::new(file);
            (stdioread, path)
        } else {
            bail!("Specify at least one of opt_path or opt_artifact_file");
        };

        Ok(stdioread_and_path)
    }

    /// Opens the specified file for writing, or if "-" then write to stdout.
    /// Next it tries any specified artifact file.
    pub fn out_file_stdiowrite(
        &self,
        opt_path: Option<&PathBuf>,
        opt_artifact_file: Option<&ArtifactFile>,
    ) -> Result<(Box<dyn std::io::Write>, PathBuf)> {
        let mut open_options_write = OpenOptions::new();
        open_options_write.write(true).create(true).truncate(true);

        let stdiowrite_and_path: (Box<dyn std::io::Write>, PathBuf) = if let Some(path) = opt_path {
            let stdiowrite: Box<dyn std::io::Write> = if *path == PathBuf::from("-") {
                Box::new(std::io::stdout())
            } else {
                let file = open_options_write.open(path).with_context(|| {
                    format!("Couldn't open file for writing: {}", path.display())
                })?;
                Box::new(file)
            };

            (stdiowrite, path.clone())
        } else if let Some(artifact_file) = opt_artifact_file {
            let (file, path) = self.open(artifact_file, &open_options_write)?;
            let bx_write: Box<dyn std::io::Write> = Box::new(file);
            (bx_write, path)
        } else {
            bail!("Specify at least one of opt_path or opt_artifact_file");
        };

        Ok(stdiowrite_and_path)
    }
    // */
}

impl ResourcePersistence for ResourceProducer_Filesystem {}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use std::sync::Arc;

    //use anyhow::{Context, Result, anyhow, bail, ensure};
    //use eg::{eg::Eg, eg_config::EgConfig};
    use insta::assert_ron_snapshot;

    use super::*;

    #[test_log::test]
    fn t1() {
        use ResourceCategory::*;

        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::resourceproducer_filesystem::t::t1",
        );
        let eg = eg.as_ref();

        /*
        // Trivial success cases.

        let (dr_rc, dr_src) = eg
            .produce_resource(&ResourceIdFormat {
                id: ResourceId::ElectionGuardDesignSpecificationVersion,
                fmt: ResourceFormat::SliceBytes,
            })
            .unwrap();
        assert_ron_snapshot!(dr_rc.rid(), @r#"ElectionGuardDesignSpecificationVersion"#);
        assert_ron_snapshot!(dr_rc.format(), @r#"SliceBytes"#);
        assert_ron_snapshot!(dr_src, @r#"Serialized"#);
        assert_ron_snapshot!(dr_rc.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()),
            @r#"Some("{\"number\":[2,1]}")"#);

        let (dr_rc, dr_src) = eg
            .produce_resource(&ResourceIdFormat {
                id: ResourceId::ElectionGuardDesignSpecificationVersion,
                fmt: ResourceFormat::ConcreteType,
            })
            .unwrap();
        assert_ron_snapshot!(dr_rc.rid(), @r#"ElectionGuardDesignSpecificationVersion"#);
        assert_ron_snapshot!(dr_rc.format(), @"ConcreteType");
        assert_ron_snapshot!(dr_src, @r#"Constructed"#);
        assert_ron_snapshot!(dr_rc.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()),
            @r#"None"#);
        // */
    }
}
