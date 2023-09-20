// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use crate::{subcommand_helper::SubcommandHelper, Subcommand};
use anyhow::Result;
use clap::Args;
// use voter::ballot::VoterConfirmationQRCode;

#[derive(Args, Debug)]
pub(crate) struct VoterWriteConfirmationCode {
    /// The confirmation code as a hex-encoded string.
    #[arg(short, long, default_value_t = String::from(""))]
    code: String,

    /// File to which to write the QR code as SVG.
    /// Default is in the artifacts dir.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for VoterWriteConfirmationCode {
    fn uses_csprng(&self) -> bool {
        false
    }
    #[allow(unused_variables)]
    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        // match VoterConfirmationQRCode::new(&self.code) {
        //     Some(qr_code) => {
        //         let (mut bx_write, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
        //             &self.out_file,
        //             Some(ArtifactFile::VoterConfirmationCode(
        //                 HValue::from_str(&self.code).unwrap(),
        //             )),
        //         )?;

        //         qr_code.to_stdiowrite(bx_write.as_mut()).with_context(|| {
        //             format!("Writing voter confirmation QR code to: {}", path.display())
        //         })?;

        //         drop(bx_write);
        //     }
        //     None => {}
        // }

        // subcommand_helper
        // .artifacts_dir
        // .out_file_write(
        //     &None,
        //     ArtifactFile::VoterConfirmationCode,
        //     "voter confirmation QR code",
        //     code_data.as_bytes(),
        // )
        // .unwrap()

        Ok(())
    }
}
