use std::path::PathBuf;

use crate::{artifacts_dir::ArtifactFile, subcommand_helper::SubcommandHelper, Subcommand};
use anyhow::{bail, Result};
use clap::Args;
use eg::{
    election_manifest::ElectionManifest, election_parameters::ElectionParameters,
    example_election_manifest::example_election_manifest_small,
    example_election_parameters::example_election_parameters, hashes::Hashes, nizk::ProofGuardian,
};
use util::{file::read_path, logging::Logging};

#[derive(Args, Debug)]
pub(crate) struct VerifyGuardianProof {
    /// Sequence order
    #[arg(long)]
    i: i32,

    /// File from which to read the election manifest.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Use the example election manifest.
    #[arg(long)]
    example_manifest: bool,
}

impl Subcommand for VerifyGuardianProof {
    fn uses_csprng(&self) -> bool {
        false
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        if self.example_manifest && self.manifest.is_some() {
            bail!("Specify either --example-manifest or --manifest, but not both.");
        }

        let election_parameters: ElectionParameters;
        let election_manifest: ElectionManifest;

        if self.example_manifest {
            election_parameters = example_election_parameters();
            election_manifest = example_election_manifest_small();
        } else {
            return Err(anyhow::anyhow!("Not implemented yet"));
        }

        let hashes = Hashes::new(&election_parameters, &election_manifest);

        assert!(self.i != 0 && self.i as u16 <= election_parameters.varying_parameters.n);

        let proof = ProofGuardian::from_json(
            &String::from_utf8(read_path(
                &subcommand_helper
                    .artifacts_dir
                    .path(ArtifactFile::GuardianProof),
            ))
            .unwrap(),
        );

        // Verify proof of knowledge
        Logging::log(
            &format!("Guardian {}", self.i),
            &format!(
                "\tProof: {:?}",
                proof.verify(
                    &election_parameters.fixed_parameters,
                    hashes.h_p,
                    self.i as u16,
                    election_parameters.varying_parameters.k,
                )
            ),
            line!(),
            file!(),
        );

        Ok(())
    }
}
