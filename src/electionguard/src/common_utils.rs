// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};

// Writes to a file, or to stdout if the path is "-".
pub(crate) fn write_to_pathbuf_which_may_be_stdout(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    if path == &PathBuf::from("-") {
        std::io::stdout()
            .write_all(bytes)
            .with_context(|| "Couldn't write to stdout".to_owned())
    } else {
        std::fs::write(path, bytes)
            .with_context(|| format!("Couldn't write to file: {}", path.display()))
    }
}
