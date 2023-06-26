use std::path::PathBuf;

use crate::{artifacts_dir::ArtifactFile, subcommand_helper::SubcommandHelper, Subcommand};
use anyhow::Result;
use clap::Args;
use voter::ballot::VoterConfirmationCode;

#[derive(Args, Debug)]
pub(crate) struct VoterWriteConfirmationCode {
    /// The confirmation code as a hex-encoded string.
    #[arg(short, long, default_value_t = String::from(""))]
    code: String,

    /// File to which to write the QR code as SVG.
    /// Default is in the artifacts dir.
    #[arg(long)]
    qr_code_out: Option<PathBuf>,
}

impl Subcommand for VoterWriteConfirmationCode {
    fn uses_csprng(&self) -> bool {
        false
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        match VoterConfirmationCode::new(&self.code) {
            Some(code_data) => subcommand_helper
                .artifacts_dir
                .out_file_write(
                    &None,
                    ArtifactFile::VoterConfirmationCode,
                    "voter confirmation QR code",
                    code_data.as_bytes(),
                )
                .unwrap(),
            None => {}
        }

        Ok(())
    }
}
