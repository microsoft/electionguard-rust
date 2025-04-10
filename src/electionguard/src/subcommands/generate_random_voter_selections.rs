// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};

use eg::{
    eg::Eg, serializable::SerializablePretty, voter_selections_plaintext::VoterSelectionsPlaintext,
};

use crate::{
    artifacts_dir::ArtifactFile,
    //? common_utils::load_pre_voting_data,
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct GenerateRandomVoterSelections {
    /// Seed data to customize the generation RNG. Only useful in
    /// conjunction with `--insecure-deterministic`.
    #[arg(long)]
    seed: Option<String>,

    /// File to which to write the random selections.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for GenerateRandomVoterSelections {
    fn do_it(
        &mut self,
        subcommand_helper: &mut crate::subcommand_helper::SubcommandHelper,
    ) -> Result<()> {
        let eg = subcommand_helper.get_eg("GenerateRandomVoterSelections")?;
        let _eg = eg.as_ref();

        anyhow::bail!("TODO: finish implementing GenerateRandomVoterSelections");

        /*
        let seed_str = self.seed.clone().unwrap_or_default();

        let _pre_voting_data =
            load_pre_voting_data(eg, &subcommand_helper.artifacts_dir)?;

        let ballot_style_ix = eg
            .election_manifest()?
            .ballot_styles()
            .random_index(eg.csrng())
            .ok_or_else(|| anyhow!("No ballot styles in election manifest."))?;
        println!("Using Ballot Style {ballot_style_ix}");

        let voter_selection_data_plaintext =
            VoterSelectionsPlaintext::new_generate_random_selections(
                eg,
                ballot_style_ix,
            )?;

        let (mut stdiowrite, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
            self.out_file.as_ref(),
            Some(&ArtifactFile::GeneratedTestDataVoterSelections(
                seed_str.to_owned(),
            )),
        )?;

        voter_selection_data_plaintext
            .to_stdiowrite_pretty(stdiowrite.as_mut())
            .with_context(|| format!("Writing random voter selections to: {}", path.display()))?;

        drop(stdiowrite);

        println!("Wrote random voter selections to: {}", path.display());

        Ok(())
        // */
    }
}
