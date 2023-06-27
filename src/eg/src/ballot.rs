use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

use crate::{
    confirmation_code::confirmation_code, contest::ContestEncrypted,
    contest_selection::ContestSelection, device::Device, hash::HValue,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// A ballot style is an ordered list of contest labels.
pub struct BallotStyle(pub Vec<String>);

/// An encrypted ballot.
#[derive(Debug)]
pub struct BallotEncrypted {
    /// Contests in this ballot
    contests: Vec<ContestEncrypted>,

    /// Confirmation code
    confirmation_code: HValue,

    /// Date (and time) of ballot generation
    date: String,

    /// Device that generated this ballot
    device: String,
}

impl BallotEncrypted {
    pub fn new(
        contests: &[ContestEncrypted],
        confirmation_code: HValue,
        date: &str,
        device: &str,
    ) -> BallotEncrypted {
        BallotEncrypted {
            contests: contests.to_vec(),
            confirmation_code,
            date: date.to_string(),
            device: device.to_string(),
        }
    }

    pub fn new_from_selections(
        device: &Device,
        csprng: &mut Csprng,
        primary_nonce: &[u8],
        selections: &Vec<ContestSelection>,
    ) -> BallotEncrypted {
        let mut contests = Vec::with_capacity(selections.len());

        for (i, selection) in selections.iter().enumerate() {
            contests.push(ContestEncrypted::new(
                device,
                csprng,
                primary_nonce,
                &device.header.manifest.contests[i],
                selection,
            ));
        }

        let confirmation_code =
            confirmation_code(&device.header.hashes_ext.h_e, &contests, &vec![0u8; 32]);
        BallotEncrypted {
            contests,
            confirmation_code,
            date: device.header.parameters.varying_parameters.date.clone(),
            device: device.uuid.clone(),
        }
    }

    pub fn contests(&self) -> &Vec<ContestEncrypted> {
        &self.contests
    }

    pub fn confirmation_code(&self) -> &HValue {
        &self.confirmation_code
    }

    pub fn date(&self) -> &String {
        &self.date
    }

    pub fn device(&self) -> &String {
        &self.device
    }
}
