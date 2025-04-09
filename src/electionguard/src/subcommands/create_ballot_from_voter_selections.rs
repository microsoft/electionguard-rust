// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use eg::{
    ballot::Ballot, eg::Eg, loadable::LoadableFromStdIoReadValidated,
    voter_selections_plaintext::VoterSelectionsPlaintext,
};

use crate::{
    //common_utils::load_pre_voting_data,
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct CreateBallotFromVoterSelections {
    /// File from which to read the voter selections.
    /// If "-", read from stdin.
    #[arg(long)]
    voter_selections_file: Option<PathBuf>,

    /// File to which to write the random selections.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for CreateBallotFromVoterSelections {
    fn do_it(
        &mut self,
        subcommand_helper: &mut crate::subcommand_helper::SubcommandHelper,
    ) -> Result<()> {
        let eg = subcommand_helper.get_eg("CreateBallotFromVoterSelections")?;
        let _eg = eg.as_ref();
        anyhow::bail!("TODO: finish implementing CreateBallotFromVoterSelections");

        /*
        load_pre_voting_data(eg, &subcommand_helper.artifacts_dir)?;

        let (mut stdioread, voter_selections_path) = subcommand_helper
            .artifacts_dir
            .in_file_stdioread(self.voter_selections_file.as_ref(), None)?;

        let voter_selections_plaintext =
            <VoterSelectionsPlaintext as LoadableFromStdIoReadValidated>::from_stdioread_validated(
                &mut stdioread,
                eg,
            )
            .with_context(|| {
                format!(
                    "Loading voter selections from: {}",
                    voter_selections_path.display()
                )
            })?;

        println!(
            "VoterSelectionsPlaintext loaded from: {}",
            voter_selections_path.display()
        );

        let _ballot = Ballot::try_new(
            voter_selections_plaintext,
            None, // opt_ballot_nonce_xi_B: Option<HValue>
            eg,
        )?;
        // */

        /* let (mut stdiowrite, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(self.out_file.as_ref(), None)?;

        voter_selection_data_plaintext
            .to_stdiowrite_pretty(stdiowrite.as_mut())
            .with_context(|| format!("Writing random voter selections to: {}", path.display()))?;

        drop(stdiowrite);

        println!("Wrote ballot to: {}", path.display());
        */

        #[allow(unreachable_code)]
        Ok(())
    }
}
