// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

pub mod ballot;
pub mod ballot_encrypting_tool;
pub mod ballot_list;
pub mod ballot_recording_tool;
pub mod confirmation_code;
pub mod contest;
pub mod contest_hash;
pub mod contest_selection;
pub mod device;
pub mod election_manifest;
pub mod election_parameters;
pub mod election_record;
pub mod example_election_manifest;
pub mod example_election_parameters;
pub mod fixed_parameters;
pub mod guardian;
pub mod hash;
pub mod hashes;
pub mod key;
pub mod nizk;
pub mod nonce;
pub mod standard_parameters;
pub mod varying_parameters;
pub mod verifier;
pub mod voter;
