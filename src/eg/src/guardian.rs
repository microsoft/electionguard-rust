// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module implements guardian indices.

use serde::{Deserialize, Serialize};
use util::index::Index;

use crate::errors::{EgError, EgResult};

#[doc(hidden)]
/// Tag used to specialize [`Index`] for Guardian indices.
pub struct GuardianIndexTag;

/// Guardian `i`.
///
/// Used for:
///
/// - [`VaryingParameters::n`](crate::varying_parameters::VaryingParameters::n), `1` <= [`n`](crate::varying_parameters::VaryingParameters::n) < `2^31`.
/// - [`VaryingParameters::k`](crate::varying_parameters::VaryingParameters::k), `1` <= [`k`](crate::varying_parameters::VaryingParameters::k) <= [`n`](crate::varying_parameters::VaryingParameters::n).
/// - [`GuardianSecretKey::i`](crate::guardian_secret_key::GuardianSecretKey::i), `1` <= [`i`](crate::guardian_secret_key::GuardianSecretKey::i) <= [`n`](crate::varying_parameters::VaryingParameters::n).
/// - [`GuardianPublicKey::i`](crate::guardian_public_key::GuardianPublicKey::i), `1` <= [`i`](crate::guardian_public_key::GuardianPublicKey::i) <= [`n`](crate::varying_parameters::VaryingParameters::n).
///
pub type GuardianIndex = Index<GuardianIndexTag>;

/// Attempts to convert a value into a GuardianIndex.
///
/// Just like [`TryInto`](std::convert::TryInto), but this gives you an [`EgResult`].
pub fn try_into_guardian_index<T>(ix1: T) -> EgResult<GuardianIndex>
where
    T: TryInto<GuardianIndex>,
    <T as TryInto<GuardianIndex>>::Error: Into<EgError>,
{
    TryInto::<GuardianIndex>::try_into(ix1).map_err(Into::<EgError>::into)
}

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
    Deserialize,
    Serialize,
    strum::Display,
    strum::EnumCount,
    strum::VariantArray
)]
#[allow(non_camel_case_types)]
pub enum GuardianKeyPurpose {
    /// The "joint vote encryption public key K"
    /// EGDS 2.1.0 Sec 3.2.2 eq. 25.
    ///
    /// Used for:
    /// - Contest selectable options and additional data fields that undergo homomorphic tallying.
    #[strum(to_string = "encrypt_ballot_numerical_votes_and_additional_data_fields")]
    Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,

    /// The "joint ballot data encryption public key ̂K" (K hat, or 0xCC_82_4B in UTF-8)
    /// EGDS 2.1.0 Sec 3.2.2 eq. 26.
    ///
    /// Used for:
    /// - Encrypting ballot nonces.
    /// - Encrypting content of write-in values.
    #[strum(to_string = "encrypt_ballot_additional_free_form_data")]
    Encrypt_Ballot_AdditionalFreeFormData,

    /// "Kappa"
    /// Used for:
    /// - Encrypting key share messages. Published in the record so that these messages may be verified.
    #[strum(to_string = "encrypt_inter_guardian_communication")]
    Encrypt_InterGuardianCommunication,
}

impl GuardianKeyPurpose {
    /// Returns whether it is valid to use this guardian key to form a joint public key.
    pub fn forms_joint_public_key(self) -> bool {
        use GuardianKeyPurpose::*;
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Encrypt_Ballot_NumericalVotesAndAdditionalDataFields => true,
            Encrypt_Ballot_AdditionalFreeFormData => true,
            _ => false,
        }
    }
}

/// Asymmetric keys have two parts, conventionally referred to as "public", and "private".
///
/// Here we this is called "secret" to better reflect its handling requirements and
/// reduce confusion with the system's intended privacy properties. I.e., a Guardian is required
/// to keep this value secret, but there is no notion of Guardian "privacy".
///
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

/// Identifies a Guardian key.
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
#[display("Guardian {guardian_ix}, {key_purpose}, {asymmetric_key_part}")]
pub struct GuardianKeyId {
    /// Guardian index, 1 <= i <= [`n`](crate::varying_parameters::VaryingParameters::n).
    pub guardian_ix: GuardianIndex,

    /// Key purpose
    pub key_purpose: GuardianKeyPurpose,

    /// Asymmetric part, 'Public' or 'Secret'.
    pub asymmetric_key_part: AsymmetricKeyPart,
}
