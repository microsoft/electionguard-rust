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
            header: header,
        }
    }

    pub fn get_uuid(&self) -> &String {
        &self.uuid
    }
}
