// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{fs::File, io::Read, path::Path};

use anyhow::{bail, ensure, Context, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

use util::csprng::{Csprng, CsprngBuilder, get_osrng_data_for_seeding};

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
}

impl SubcommandHelper {
    pub fn new(clargs: Clargs, artifacts_dir: ArtifactsDir) -> Result<Self> {
        Ok(Self {
            clargs,
            artifacts_dir,
            opt_insecure_deterministic_seed_data: None,
        })
    }

    /// Returns a [`builder`](util::csprng::CsprngBuilder) for a new
    /// pre-loaded from the OS entropy source (or the insecure deterministic pseudorandom seed data file),
    /// to be further customized or seeded.
    ///
    /// In insecure deterministic mode, if called multiple times with the same customization_data,
    /// the same initialized csprng will be returned.
    // TODO: this was migrated to `eg::eg_config`. Unify.
    pub fn build_csprng(&mut self) -> Result<CsprngBuilder> {
        let insecure_deterministic_pseudorandom_seed_data_file_path = self
            .artifacts_dir
            .path(ArtifactFile::InsecureDeterministicPseudorandomSeedData);

        let insecure_deterministic_pseudorandom_seed_data_file_exists =
            insecure_deterministic_pseudorandom_seed_data_file_path
                .try_exists()
                .unwrap_or_default();

        // Values are arbitrary, chosen by `dd if=/dev/urandom | xxd -p -l8`.
        #[derive(Clone, Copy)]
        #[repr(u32)]
        enum SeedMethod {
            InsecureDeterministic = 0x4813b968,
            TrueRandom = 0x32964bac,
        }

        let csprng_builder = if self.clargs.insecure_deterministic {
            let insecure_deterministic_pseudorandom_seed_data = self
                .get_insecure_deterministic_pseudorandom_seed_data(
                    &insecure_deterministic_pseudorandom_seed_data_file_path,
                )?;

            Csprng::build()
                .write_u64(SeedMethod::InsecureDeterministic as u64)
                .write_bytes(insecure_deterministic_pseudorandom_seed_data)
        } else {
            if insecure_deterministic_pseudorandom_seed_data_file_exists {
                eprintln!(
                    "WARNING: The --insecure-deterministic command line argument was not specified, but the insecure deterministc pseudorandom seed datafile exists: {}",
                    insecure_deterministic_pseudorandom_seed_data_file_path.display() );
            }

            let mut true_random_seed_data = Zeroizing::new([0u8; Csprng::max_entropy_seed_bytes()]);
            get_osrng_data_for_seeding(&mut true_random_seed_data);
            ensure!(
                eg::hash::HVALUE_BYTE_LEN <= true_random_seed_data.len(),
                "Not enough OS-provided true random data."
            );

            eprintln!(
                "Seeding CSPRNG with {} bytes of OS-provided true random data.",
                true_random_seed_data.len()
            );

            Csprng::build()
                .write_u64(SeedMethod::TrueRandom as u64)
                .write_bytes(true_random_seed_data)
        };

        Ok(csprng_builder)
    }

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
                    bail!("No insecure deterministic pseudorandom seed data could be read from: {path_str}");
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
