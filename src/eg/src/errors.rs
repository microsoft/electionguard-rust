// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(non_camel_case_types)] // We use underscores for clarity in some error message identifiers
#![allow(unused_imports)] //? TODO: Remove temp development code

use crate::{
    ballot_style::BallotStyleIndex,
    ciphertext::CiphertextIndex,
    election_manifest::{ContestIndex, ContestOptionIndex},
    guardian::{GuardianIndex, GuardianKeyPurpose},
    hash::HValue,
    resource::ResourceIdFormat,
};
pub use crate::{
    el_gamal::ElGamalError,
    guardian_public_key_trait::PublicKeyValidationError,
    loadable::EgLoadingError,
    resource_producer::ResourceProductionError,
    validatable::EgValidateError,
    verifiable_decryption::{
        CombineProofError, ComputeDecryptionError, DecryptionError, DecryptionShareCombinationError,
    },
    zk::ZkProofRangeError,
};

/// The main [`std::error::Error`] type returned by functions of the `eg` crate.
#[derive(thiserror::Error, Debug)]
pub enum EgError {
    #[error(
        "Need exactly `{expected}` bytes to make an `HValue` but received `{actual}` bytes instead."
    )]
    HValueByteLenMismatch { expected: usize, actual: usize },

    #[error(
        "The contest at index `{contest_ix}` in the election manifest incorrectly believes it is at index `{contests_contest_ix}`."
    )]
    ContestIndexMismatch {
        contest_ix: ContestIndex,
        contests_contest_ix: ContestIndex,
    },

    #[error("Ballot style `{0}` doesn't know its index, at a place and time when it should.")]
    BallotStyleDoesntKnowItsIndex(BallotStyleIndex),

    #[error(
        "A ballot style doesn't know its index, at a place and time when it should, and it wasn't known from context either."
    )]
    BallotStyleDoesntKnowItsIndexAndItWasNotClearFromContextEither,

    #[error(
        "A ballot style that believes it has ballot style index `{0}`, but it doesn't match the ballot style in the election manifest at that index."
    )]
    BallotStyleDoesntMatchElectionManifest(BallotStyleIndex),

    #[error(
        "The ballot style at index `{actual_ballot_style_ix}` in the election manifest incorrectly believes it is at index `{bs_ballot_style_ix}`."
    )]
    BallotStyleIndexMismatch {
        actual_ballot_style_ix: BallotStyleIndex,
        bs_ballot_style_ix: BallotStyleIndex,
    },

    #[error(
        "Election manifest contest `{actual_contest_ix}` option `{contest_option_ix}` incorrectly believes it belongs to contest `{co_contest_ix}`."
    )]
    OptionContestIndexMismatch {
        actual_contest_ix: ContestIndex,
        contest_option_ix: ContestOptionIndex,
        co_contest_ix: ContestIndex,
    },

    #[error(
        "Election manifest contest `{contest_ix}` option `{actual_contest_option_ix}` incorrectly believes it is at option index `{co_contest_option_ix}`."
    )]
    ContestOptionIndexMismatch {
        contest_ix: ContestIndex,
        actual_contest_option_ix: ContestOptionIndex,
        co_contest_option_ix: ContestOptionIndex,
    },

    #[error(
        "Contest selection limit value of {0} is not in the supported range of 0 to 2147483647."
    )]
    ContestSelectionLimitOutOfSupportedRange(u64),

    #[error(
        "While constructing a contest selection, encountered option value at (1-based index) {0} that is not in the supported range of 0 to 2147483647."
    )]
    ContestOptionFieldsPlaintextsNew(usize),

    #[error("Option selection limit value of {0} is.")]
    OptionSelectionLimitOutOfSupportedRange(u64),

    #[error(
        "Contest option selection limit can't be expressed as a number because it's `LimitedOnlyByContest`."
    )]
    OptionSelectionLimitIsNotNumeric,

    #[error("Contest `{0}` has no options.")]
    ContestHasNoOptions(ContestIndex),

    #[error("Contest option index `{0}` is not found in the contest.")]
    ContestOptionIndexNotInContest(ContestOptionIndex),

    #[error(
        "Contest option `{contest_option_ix}` of contest `{contestoption_contest_ix}` was asked to compute its effective selection limit as if it were in contest `{containing_contest_ix}` instead."
    )]
    ContestOptionActuallyInDifferentContest {
        contest_option_ix: ContestOptionIndex,
        containing_contest_ix: ContestIndex,
        contestoption_contest_ix: ContestIndex,
    },

    #[error(
        "Contest option of contest `{contestoption_contest_ix}` was asked to compute its effective selection limit as if it were in contest `{containing_contest_ix}` instead."
    )]
    ContestOptionActuallyInDifferentContest2 {
        containing_contest_ix: ContestIndex,
        contestoption_contest_ix: ContestIndex,
    },

    #[error(transparent)]
    PublicKeyValidationError(#[from] PublicKeyValidationError),

    #[error("Guardian key purpose `{key_purpose}` does not form a joint public key.")]
    NoJointPublicKeyForPurpose { key_purpose: GuardianKeyPurpose },

    #[error("Guardian(s) `{0:?}` are not represented in a joint public key")]
    JointPublicKeyCompute_GuardiansMissing(Vec<GuardianIndex>),

    #[error("Guardian {0} is represented more than once in a joint public key")]
    JointPublicKeyCompute_GuardianMultiple(GuardianIndex),

    #[error("Guardian {0} is represented more than once in a joint public key")]
    JointPublicKey_InvalidGroupElement(GuardianKeyPurpose),

    #[error("Error producing ballot proofs: {0}")]
    ProofError(#[from] ZkProofRangeError),

    #[error("Ballot style `{0}` not in election manifest.")]
    BallotStyleNotInElectionManifest(BallotStyleIndex),

    #[error("Contest index `{0}` does not exist in ElectionManifest.")]
    ContestNotInManifest(ContestIndex),

    #[error(
        "Contest `{contest_ix}` does not exist in ballot style label `{ballot_style_label}`. If known, the ballot style index within the election manifest is `{opt_ballot_style_ix:?}`."
    )]
    ContestNotInBallotStyle {
        contest_ix: ContestIndex,
        ballot_style_label: String,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    },

    #[error(
        "A `VoterSelectionsPlaintext` provided selections for contest `{contest_ix}` which does not exist in the election manifest. If known, the ballot style index within the election manifest is `{opt_ballot_style_ix:?}`."
    )]
    VoterSelectionsPlaintextSuppliesSelectionsForContestNotInElectionManifest {
        contest_ix: ContestIndex,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    },

    #[error(
        "A `VoterSelectionsPlaintext` provided selections for contest `{contest_ix}` which does not exist in ballot style labeled `{ballot_style_label}`. If known, the ballot style index within the election manifest is `{opt_ballot_style_ix:?}`."
    )]
    VoterSelectionsPlaintextSuppliesSelectionsForContestNotInBallotStyle {
        contest_ix: ContestIndex,
        ballot_style_label: String,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    },

    #[error(
        "A `VoterSelectionsPlaintext` of ballot style `{ballot_style_ix}`, provided selections for contest `{contest_ix}` having {num_options_defined} selectable options, but `{num_options_supplied}` options were supplied."
    )]
    VoterSelectionsPlaintextSuppliesWrongNumberOfOptionSelectionsForContest {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
        num_options_defined: usize,
        num_options_supplied: usize,
    },

    #[error(
        "While trying to produce a `Ballot`, the provided `VoterSelectionsPlaintext` contains a value for the extended base hash `H_E` that does not match the `H_E` for this election. \
Possibly this `VoterSelectionsPlaintext` was created for a different election or election configuration. \
VoterSelectionsPlaintext h_e=`{voterselections_h_e}`, \
PreVotingData h_e=`{election_h_e}`"
    )]
    VoterSelectionsPlaintextDoesNotMatchExpected {
        voterselections_h_e: crate::extended_base_hash::ExtendedBaseHash_H_E,
        election_h_e: crate::extended_base_hash::ExtendedBaseHash_H_E,
    },

    #[error("Ballot of style `{ballot_style_ix}` is missing contest `{contest_ix}`.")]
    BallotMissingDataFieldsForContestInBallotStyle {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(
        "Ballot style `{ballot_style_ix}` claims to contain contest `{contest_ix}` which does not exist in the election manifest."
    )]
    BallotStyleClaimsNonExistentContest {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(
        "Ballot of style `{ballot_style_ix}` claims to contain contest `{contest_ix}` which does not exist in the election manifest."
    )]
    BallotClaimsNonExistentContest {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(
        "While trying to construct a `VoterSelectionsPlaintext` of ballot style `{ballot_style_ix}`, selections were provided for contest `{contest_ix}` which does not exist in the election manifest."
    )]
    VoterSelectionsPlaintextClaimsNonExistentContest {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(
        "Ballot of style `{ballot_style_ix}` claims to contain contest `{contest_ix}` which is not present in the ballot style."
    )]
    BallotClaimsContestNonExistentInBallotStyle {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(
        "Ballot of style `{ballot_style_ix}` contest `{contest_ix}` fields ciphertexts did not verify"
    )]
    BallotContestFieldsCiphertextsDidNotVerify {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error("Contest option index out of range `{0}`")]
    ContestOptionIxOutOfRange(u32),

    #[error(transparent)]
    IndexError(#[from] util::index::IndexError),

    #[error(transparent)]
    Vec1Error(#[from] util::vec1::Vec1Error),

    #[cfg(feature = "eg-allow-test-data-generation")]
    #[error("Random number generation error: {0}")]
    RandError(String),

    /*
    #[error("Likely out of memory: {0}")]
    TryReserveError(#[from] std::collections::TryReserveError),
    // */
    #[error(transparent)]
    OtherA(#[from] anyhow::Error),

    #[error("{0}")]
    Str(&'static str),

    #[error(transparent)]
    DecryptionError(#[from] DecryptionError),

    #[error(transparent)]
    ComputeDecryptionError(#[from] ComputeDecryptionError),

    #[error(transparent)]
    CombineProofError(#[from] CombineProofError),

    #[error(transparent)]
    GuardianSecretKeyShareGenerationError(
        #[from] crate::guardian_share::GuardianSecretKeyShareGenerationError,
    ),

    #[error(transparent)]
    GuardianEncryptedSharePublicValidationError(
        #[from] crate::guardian_share::GuardianEncryptedSharePublicValidationError,
    ),

    #[error(transparent)]
    DecryptionShareCombinationError(#[from] DecryptionShareCombinationError),

    #[error(transparent)]
    ElGamal(#[from] ElGamalError),

    #[error(transparent)]
    LoadingError(#[from] EgLoadingError),

    #[error(transparent)]
    ValidationError(#[from] EgValidateError),

    #[error(transparent)]
    TooLargeFor31Bits(#[from] util::uint31::Uint31Error),

    #[error(transparent)]
    TooLargeFor53Bits(#[from] util::uint53::Uint53Error),

    #[error("Internal error.")]
    StdConvertInfallible(#[from] std::convert::Infallible),

    #[error("IO error.")]
    StdIoError(#[from] std::io::Error),

    #[error("Value out of range: {0}")]
    TryFromIntError(#[from] std::num::TryFromIntError),

    #[error("Malformed UTF-8: {0}")]
    MalformedUtf8Error(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    FieldError(#[from] util::algebra::FieldError),

    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error(
        "Overflow encrypting contest `{contest_ix}` option field `{option_field_ix}`, needed for selection limit proof."
    )]
    OverflowInOptionFieldTotal {
        contest_ix: u32,
        option_field_ix: u32,
    },

    #[error(
        "Contest `{contest_ix}` option or data field `{ciphertext_ix}` does not verify: proof is not present in encrypted contest data."
    )]
    BallotContestFieldCiphertextDoesNotVerify_ProofNotPresent {
        contest_ix: ContestIndex,
        ciphertext_ix: CiphertextIndex,
    },

    #[error(
        "Contest `{contest_ix}` option or data field `{ciphertext_ix}` does not verify: proof does not verify."
    )]
    BallotContestFieldCiphertextDoesNotVerify_ProofDoesNotVerify {
        contest_ix: ContestIndex,
        ciphertext_ix: CiphertextIndex,
    },

    #[error(
        "Contest `{contest_ix}` does not verify: contest selection limit of `{effective_contest_selection_limit}` does not verify."
    )]
    BallotContestFieldCiphertextDoesNotVerify_ContestSelectionLimit {
        contest_ix: ContestIndex,
        effective_contest_selection_limit: u32,
    },

    #[error(
        "Contest `{contest_ix}` does not verify: verified `{cnt_ciphertexts_verified}` ciphertexts but there are {cnt_data_fields_in_contest} data fields in the contest."
    )]
    BallotContestFieldCiphertextDoesNotVerify_WrongNumberOfCiphertextProofs {
        contest_ix: ContestIndex,
        cnt_ciphertexts_verified: usize,
        cnt_data_fields_in_contest: usize,
    },

    #[error(
        "Contest `{contest_ix}` was listed in the ballot style `{ballot_style_ix}`, but it was not verified."
    )]
    BallotContestNotVerified {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(
        "Contest `{contest_ix}` was verified, but it is not listed in the ballot style `{ballot_style_ix}`."
    )]
    BallotContestVerifiedNotInBallotStyle {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(transparent)]
    ResourceProductionError(ResourceProductionError),

    #[error("During resource production: {_0}.")]
    DuringResourceProduction(Box<EgError>),

    #[error("The `{ridfmt}` is not correct for type `{ty}`.")]
    UnexpectedResourceIdFormat {
        ridfmt: ResourceIdFormat,
        ty: &'static str,
    },

    #[error(
        "Unexpected mismatch of `{thing_name}`. Expected `{expected:?}`, actual: `{actual}` (usize)."
    )]
    UnexpectedValue_u128 {
        thing_name: &'static str,
        expected: std::ops::RangeInclusive<u128>,
        actual: u128,
    },

    #[error(
        "Unexpected mismatch of `{thing_name}`. Expected `{expected:?}`, actual: `{actual}` (usize)."
    )]
    UnexpectedValue_u64 {
        thing_name: &'static str,
        expected: std::ops::RangeInclusive<u64>,
        actual: u64,
    },

    #[error(
        "Unexpected mismatch of `{thing_name}`. Expected `{expected:?}`, actual: `{actual}` (usize)."
    )]
    UnexpectedValue_u32 {
        thing_name: &'static str,
        expected: std::ops::RangeInclusive<u32>,
        actual: u32,
    },
}

impl EgError {
    pub fn unless<F, E>(cond: bool, f: F) -> EgResult<()>
    where
        F: Fn() -> E,
        E: Into<EgError>,
    {
        if cond {
            Ok(())
        } else {
            Err(f().into())
        }
    }
}

// We can't use the `Serialize` derive macro, even with the #[serde(into = "String")] attribute,
// because the `anyhow` EgError variant doesn't support `Clone`.
impl serde::ser::Serialize for EgError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let s = self.to_string();
        serializer.serialize_str(s.as_str())
    }
}

impl From<&'static str> for EgError {
    /// Makes an [`EgError`] from any `&'static str`.
    fn from(s: &'static str) -> Self {
        EgError::Str(s)
    }
}

#[cfg(feature = "eg-allow-test-data-generation")]
impl From<rand::distr::uniform::Error> for EgError {
    /// Makes an [`EgError`] from a [`rand::distr::uniform::Error`].
    fn from(e: rand::distr::uniform::Error) -> Self {
        EgError::RandError(e.to_string())
    }
}

#[cfg(feature = "eg-allow-test-data-generation")]
impl From<rand::distr::weighted::Error> for EgError {
    /// Makes an [`EgError`] from a [`rand::distr::weighted::Error`].
    fn from(e: rand::distr::weighted::Error) -> Self {
        EgError::RandError(e.to_string())
    }
}

impl From<ResourceProductionError> for EgError {
    /// An [`EgError`] can always be made from a [`ResourceProductionError`].
    fn from(src: ResourceProductionError) -> Self {
        match src {
            ResourceProductionError::EgError(bx_egerror) => {
                Self::DuringResourceProduction(bx_egerror)
            }
            _ => Self::ResourceProductionError(src),
        }
    }
}

impl From<EgError> for String {
    /// Makes an [`String`](std::string::String) from an [`EgError`].
    fn from(e: EgError) -> Self {
        e.to_string()
    }
}

/// [`Result`](std::result::Result) type with `Err` type `E` of [`EgError`].
pub type EgResult<T> = std::result::Result<T, EgError>;
