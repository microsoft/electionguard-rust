// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]

//=================================================================================================|

/// Asymmetric keys have two parts, sometimes referred to as the "public", and "private" keys.
///
/// Rather than "private" keys, we refer to them consistently as "secret" to better reflect its
/// handling requirements and reduce confusion with the system's intended privacy properties.
/// I.e., a [`Guardian`] is required to keep this value secret, but there is not neccessarily an
/// expectation of "privacy".
#[derive(
    Clone,
    Copy,
    Debug,
    derive_more::Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize
)]
pub enum AsymmetricKeyPart {
    Public,
    Secret,
}

//=================================================================================================|

/// Usage of a Guardian key.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumCount,
    strum::VariantArray
)]
#[allow(non_camel_case_types)]
pub enum KeyPurpose {
    /// The "joint vote encryption public key K", EGDS 2.1.0 Sec 3.2.2 eq. 25 pg. 25.
    ///
    /// Used for encrypting homomorphically tallied fields:
    /// - Contest selectable options and additional data fields that undergo homomorphic tallying.
    ///
    /// Also used when referring to:
    /// - The "vote encryption key K", EGDS 2.1.0 Sec 3.2.2 eq. 7-8 (pg. 22) and NIZK proof eq. 10-11 (pg. 23).
    /// - The "secret key share z_i", EGDS 2.1.0 Sec 3.2.2 eq. 24 pg. 26.
    #[strum(to_string = "encrypt_ballot_votes")]
    Ballot_Votes,

    /// The "joint ballot data encryption public key ̂K" (K hat, or 0xCC_82_4B in UTF-8)
    /// EGDS 2.1.0 Sec 3.2.2 eq. 26 pg. 26.
    ///
    /// Used for encrypting non-homomorphically tallied fields:
    /// - Ballot nonces
    /// - Content of write-in values
    ///
    /// Also used when referring to:
    /// - "Guardian coefficients and key pair for encrypting other ballot data"
    ///   (EGDS 2.1.0 Sec 3.2.2 pg. 23).
    /// - The "secret key share $\hat{z}_i", EGDS 2.1.0 Sec 3.2.2 pg. 26.
    #[strum(to_string = "ballot_otherdata")]
    Ballot_OtherData,

    /// "Kappa κ" (EGDS 2.1.0 Sec 3.2.2 eq. 9)
    /// Used for:
    /// - Encrypting key share messages. Published in the record so that these messages may be verified.
    #[strum(to_string = "inter_guardian_communication")]
    InterGuardianCommunication,
}

impl KeyPurpose {
    /// Returns whether it is valid to use this guardian key to form a joint public key.
    pub fn forms_joint_public_key(self) -> bool {
        use KeyPurpose::*;
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Ballot_Votes => true,
            Ballot_OtherData => true,
            _ => false,
        }
    }
}
