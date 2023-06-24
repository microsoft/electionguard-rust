use std::path::PathBuf;

use crate::{artifacts_dir::ArtifactFile, subcommand_helper::SubcommandHelper, Subcommand};
use anyhow::{bail, Result};
use clap::Args;
use eg::{
    election_manifest::ElectionManifest, election_parameters::ElectionParameters,
    example_election_manifest::example_election_manifest_small,
    example_election_parameters::example_election_parameters, hashes::Hashes,
};

#[derive(Args, Debug)]
pub(crate) struct GenerateGuardianKey {
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

impl Subcommand for GenerateGuardianKey {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng(b"VerifyStandardParameters")?;

        use eg::guardian::Guardian;

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

        // Generate new keys and proof
        let guardian = Guardian::new(&mut csprng, &election_parameters, self.i as usize);
        let public_key = guardian.public_key();
        let proof = guardian.proof_of_knowledge(
            &mut csprng,
            &election_parameters,
            hashes.h_p,
            self.i as u16,
        );

        subcommand_helper
            .artifacts_dir
            .out_file_write(
                &Some(
                    subcommand_helper
                        .artifacts_dir
                        .path(ArtifactFile::GuardianPrivateData(guardian.i as u16)),
                ),
                ArtifactFile::GuardianPrivateData(guardian.i as u16),
                "guardian private data",
                guardian.to_json().as_bytes(),
            )
            .and_then(|_| {
                subcommand_helper.artifacts_dir.out_file_write(
                    &Some(
                        subcommand_helper
                            .artifacts_dir
                            .path(ArtifactFile::GuardianPublicKey(guardian.i as u16)),
                    ),
                    ArtifactFile::GuardianPublicKey(guardian.i as u16),
                    "guardian public key",
                    public_key.to_json().as_bytes(),
                )
            })
            .and_then(|_| {
                subcommand_helper.artifacts_dir.out_file_write(
                    &Some(
                        subcommand_helper
                            .artifacts_dir
                            .path(ArtifactFile::GuardianProof(guardian.i as u16)),
                    ),
                    ArtifactFile::GuardianProof(guardian.i as u16),
                    "guardian proof",
                    proof.to_json().as_bytes(),
                )
            })
    }
}
