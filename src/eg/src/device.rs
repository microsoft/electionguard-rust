use crate::{ballot::BallotConfig, election_parameters::ElectionParameters};

pub struct Device {
    /// Unique identifier of the device
    pub uuid: String,

    /// Ballot configuration
    pub config: BallotConfig,

    /// Election Parameters
    pub election_parameters: ElectionParameters,
}

impl Device {
    pub fn new(
        uuid: String,
        config: &BallotConfig,
        election_parameters: &ElectionParameters,
    ) -> Self {
        Device {
            uuid,
            config: config.clone(),
            election_parameters: election_parameters.clone(),
        }
    }

    pub fn get_uuid(&self) -> &String {
        &self.uuid
    }
}
