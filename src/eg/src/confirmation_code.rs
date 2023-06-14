use serde::{Deserialize, Serialize};

use crate::{
    ballot::BallotConfig,
    contest::{ContestEncrypted, ContestPreEncrypted},
    hash::{eg_h, hex_to_bytes},
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationCode(pub String);

impl ConfirmationCode {
    /// Confirmation code for a pre-encrypted ballot (Equation 96)
    ///
    /// H(B) = H(H_E;42,χ_1,χ_2,...,χ_m ,B_aux)
    ///
    pub fn pre_encrypted(
        config: &BallotConfig,
        contests: &Vec<ContestPreEncrypted>,
        b_aux: &[u8],
    ) -> ConfirmationCode {
        let mut v = vec![0x42];

        contests.iter().for_each(|c| {
            v.extend(hex_to_bytes(&c.crypto_hash));
        });

        v.extend_from_slice(b_aux);
        ConfirmationCode(eg_h(&config.h_e, &v).to_string())
    }

    /// Confirmation code for an encrypted ballot (Equation 59)
    ///
    /// H(B) = H(H_E;24,χ_1,χ_2,...,χ_{m_B} ,B_aux).
    ///
    pub fn encrypted(
        config: &BallotConfig,
        contests: &Vec<ContestEncrypted>,
        b_aux: &[u8],
    ) -> ConfirmationCode {
        let mut v = vec![0x24];

        contests.iter().for_each(|c| {
            v.extend(hex_to_bytes(&c.crypto_hash));
        });

        v.extend_from_slice(b_aux);
        ConfirmationCode(eg_h(&config.h_e, &v).to_string())
    }
}
