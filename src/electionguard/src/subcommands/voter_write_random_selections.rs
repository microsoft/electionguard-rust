// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};

use eg::{
    ballot::BallotEncrypted, serializable::SerializablePretty,
    voter_selections_plaintext::VoterSelectionsPlaintext,
};

use crate::{
    artifacts_dir::ArtifactFile, common_utils::load_pre_voting_data, subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct VoterWriteRandomSelection {
    /// File to which to write the random selections.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for VoterWriteRandomSelection {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(
        &mut self,
        subcommand_helper: &mut crate::subcommand_helper::SubcommandHelper,
    ) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng(b"VoterWriteRandomSelection")?;
        let csprng = &mut csprng;

        let pre_voting_data = load_pre_voting_data(&subcommand_helper.artifacts_dir, csprng)?;

        let election_manifest = &pre_voting_data.manifest;

        //? TODO just use the first ballot style
        let ballot_style_ix = election_manifest
            .ballot_styles()
            .indices()
            .next()
            .ok_or_else(|| anyhow!("No ballot styles in election manifest."))?;
        eprintln!("Using Ballot Style {ballot_style_ix}");

        let _ballot_style = election_manifest.get_ballot_style(ballot_style_ix)?;

        let ballot_selection_data_plaintext =
            VoterSelectionsPlaintext::new_generate_random_selections(
                &pre_voting_data,
                ballot_style_ix,
                csprng,
            )?;

        let ballot = BallotEncrypted::try_from_ballot_selection_data_plaintext(
            &pre_voting_data,
            ballot_selection_data_plaintext,
            None,
            csprng,
        )?;

        // distinct from `ballot.date`
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let (mut stdiowrite, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
            &self.out_file,
            Some(ArtifactFile::BallotEncrypted(
                timestamp as u128,
                ballot.confirmation_code,
            )),
        )?;

        ballot
            .to_stdiowrite_pretty(stdiowrite.as_mut())
            .with_context(|| format!("Writing ballot to: {}", path.display()))?;

        drop(stdiowrite);

        eprintln!("Wrote ballot to: {}", path.display());

        Ok(())
    }
}
