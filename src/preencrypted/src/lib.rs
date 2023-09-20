// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

pub mod ballot;
pub mod ballot_encrypting_tool;
pub mod ballot_recording_tool;
pub mod confirmation_code;
pub mod contest;
pub mod contest_hash;
pub mod contest_selection;
pub mod nonce;
