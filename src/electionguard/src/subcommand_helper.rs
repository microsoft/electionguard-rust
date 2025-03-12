// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::{fs::File, io::Read, path::Path, sync::Arc};

use anyhow::{Context, Result, bail, ensure};

use eg::eg::Eg;
use util::{
    csprng::{Csprng, CsprngBuilder},
    osrng::get_osrng_data_for_seeding,
};
use zeroize::Zeroizing;

use crate::{
    artifacts_dir::{ArtifactFile, ArtifactsDir},
    clargs::Clargs,
};

/// Stuff passed to every subcommand.
/// Generally derived from the command line arguments that appear before the subcommand.
// Important: !Copy !Clone
pub(crate) struct SubcommandHelper {
    /// The command line arguments that appear before the subcommand.
    /// Note that the `subcommand` member will just be a default.
    pub clargs: Clargs,

    pub artifacts_dir: ArtifactsDir,

    opt_insecure_deterministic_seed_data: Option<Vec<u8>>,

    opt_eg: Option<Arc<Eg>>,
}

impl SubcommandHelper {
    pub fn new(clargs: Clargs, artifacts_dir: ArtifactsDir) -> Result<Self> {
        Ok(Self {
            clargs,
            artifacts_dir,
            opt_insecure_deterministic_seed_data: None,
            opt_eg: None,
        })
    }

    /// Gets the [`Eg`] instance.
    /// In insecure deterministic mode, if called multiple times with the same customization_data,
    /// the same initialized csprng will be returned.
    pub fn get_eg(&mut self, subcommand_str: &str) -> Result<Arc<Eg>> {
        let arc_eg = if let Some(arc_eg) = self.opt_eg.as_ref() {
            arc_eg.clone()
        } else {
            let insecure_deterministic_pseudorandom_seed_data_file_path = self
                .artifacts_dir
                .path(ArtifactFile::InsecureDeterministicPseudorandomSeedData)?;

            let insecure_deterministic_pseudorandom_seed_data_file_exists =
                insecure_deterministic_pseudorandom_seed_data_file_path
                    .try_exists()
                    .unwrap_or_default();

            let eg = if self.clargs.insecure_deterministic {
                if !cfg!(feature = "eg-allow-insecure-deterministic-csprng") {
                    anyhow::bail!(
                        "The --insecure-deterministic arg requires building with the {:?} feature.",
                        "eg-allow-insecure-deterministic-csprng"
                    );
                } else {
                    let subcommand_str_bytes = subcommand_str.as_bytes();
                    let subcommand_str_bytes_len = subcommand_str_bytes.len() as u64;

                    let seed_data_from_file = self
                        .get_insecure_deterministic_pseudorandom_seed_data(
                            &insecure_deterministic_pseudorandom_seed_data_file_path,
                        )?;
                    let seed_data_from_file_len = seed_data_from_file.len() as u64;

                    let capacity = 8
                        + (seed_data_from_file_len as usize)
                        + 8
                        + (subcommand_str_bytes_len as usize);
                    let seed_data_len_be_bytes = seed_data_from_file_len.to_be_bytes();
                    let mut seed_data = Vec::with_capacity(capacity);
                    seed_data.extend_from_slice(&seed_data_len_be_bytes);
                    seed_data.extend_from_slice(seed_data_from_file);
                    seed_data.extend_from_slice(&subcommand_str_bytes_len.to_be_bytes());
                    seed_data.extend_from_slice(subcommand_str_bytes);
                    debug_assert_eq!(seed_data.len(), capacity);

                    Eg::new_with_insecure_deterministic_csprng_seed_data(&seed_data)
                }
            } else {
                if insecure_deterministic_pseudorandom_seed_data_file_exists {
                    eprintln!(
                        "WARNING: The --insecure-deterministic command line argument was not specified, but the insecure deterministc pseudorandom seed datafile exists: {}",
                        insecure_deterministic_pseudorandom_seed_data_file_path.display()
                    );
                }

                Eg::new()
            };

            self.opt_eg = Some(eg.clone());
            eg
        };

        Ok(arc_eg)
    }

    #[cfg(any(feature = "eg-allow-insecure-deterministic-csprng", test))]
    fn get_insecure_deterministic_pseudorandom_seed_data<P: AsRef<Path>>(
        &mut self,
        insecure_deterministic_pseudorandom_seed_data_file_path: P,
    ) -> Result<&Vec<u8>> {
        ensure!(
            self.clargs.insecure_deterministic,
            "Not in insecure deterministic mode."
        );

        let refmut_opt_insecure_deterministic_seed_data =
            &mut self.opt_insecure_deterministic_seed_data;

        Ok(
            if let Some(v) = refmut_opt_insecure_deterministic_seed_data {
                v
            } else {
                eprintln!("!!! WARNING: Using INSECURE deterministic mode. !!!");

                let path_str = insecure_deterministic_pseudorandom_seed_data_file_path
                    .as_ref()
                    .display()
                    .to_string();

                let mut v = Vec::new();
                File::open::<P>(insecure_deterministic_pseudorandom_seed_data_file_path)
                    .with_context(|| format!("Couldn't open file: {path_str}"))?
                    .read_to_end(&mut v)?;

                if v.is_empty() {
                    anyhow::bail!(
                        "No insecure deterministic pseudorandom seed data could be read from: {path_str}"
                    );
                } else {
                    eprintln!(
                        "Read {} bytes of insecure deterministic pseudorandom seed data from: {path_str}",
                        v.len()
                    );
                }

                refmut_opt_insecure_deterministic_seed_data.insert(v)
            },
        )
    }
}
