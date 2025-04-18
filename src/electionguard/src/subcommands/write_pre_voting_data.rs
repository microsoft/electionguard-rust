// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use eg::{
    eg::Eg, extended_base_hash::ExtendedBaseHash, hashes::Hashes, joint_public_key::JointPublicKey,
    pre_voting_data::PreVotingData, serializable::SerializablePretty,
};

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{
        //load_election_parameters, load_hashes, load_extended_base_hash, load_joint_public_key,
        ElectionManifestSource,
    },
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct WritePreVotingData {
    /// File to which to write the extended.
    /// Default is in the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for WritePreVotingData {
    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let eg = subcommand_helper.get_eg("WritePreVotingData")?;
        let _eg = eg.as_ref();
        anyhow::bail!("TODO: finish implementing WritePreVotingData");

        /*
        //? TODO: Do we need a command line arg to specify the election parameters source?
        let _election_parameters =
            load_election_parameters(eg, &subcommand_helper.artifacts_dir)?;

        //? TODO: Do we need a command line arg to specify the election manifest source?
        let election_manifest_source =
            ElectionManifestSource::ArtifactFileElectionManifestCanonical;
        let _election_manifest =
            election_manifest_source.load_election_manifest(&subcommand_helper.artifacts_dir)?;

        //? TODO: Do we need a command line arg to specify the hashes source?
        load_hashes(eg, &subcommand_helper.artifacts_dir)?;

        //? TODO: Do we need a command line arg to specify the joint election public key source?
        load_joint_public_key(eg, &subcommand_helper.artifacts_dir)?;

        //? TODO: Do we need a command line arg to specify the extended_base_hash source?
        load_extended_base_hash(eg, &subcommand_helper.artifacts_dir)?;

        Hashes::get_or_compute(eg)?;
        JointPublicKey::get_or_compute(eg)?;
        ExtendedBaseHash::get_or_compute(eg)?;

        PreVotingData::get_or_compute(eg)?;
        let pre_voting_data = produce_resource.pre_voting_data().await?;

        let (mut stdiowrite, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(self.out_file.as_ref(), Some(&ArtifactFile::PreVotingData))?;

        pre_voting_data
            .to_stdiowrite_pretty(stdiowrite.as_mut())
            .with_context(|| format!("Writing pre voting data to: {}", path.display()))?;

        drop(stdiowrite);

        println!("Wrote pre voting data to: {}", path.display());

        Ok(())
        // */
    }
}
