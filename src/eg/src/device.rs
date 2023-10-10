// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use crate::election_record::PreVotingData;

pub struct Device {
    /// Unique identifier of the device
    pub uuid: String,

    /// Election record header
    pub header: PreVotingData,
}

impl Device {
    pub fn new(uuid: &str, header: PreVotingData) -> Self {
        Device {
            uuid: uuid.to_string(),
            header,
        }
    }

    pub fn get_uuid(&self) -> &String {
        &self.uuid
    }
}
