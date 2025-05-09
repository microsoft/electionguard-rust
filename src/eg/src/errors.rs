// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(non_camel_case_types)] // We use underscores for clarity in some error message identifiers

use std::sync::Arc;

use static_assertions::assert_impl_all;

use crate::{
    ballot_style::BallotStyleIndex,
    ciphertext::CiphertextIndex,
    contest::ContestIndex,
    contest_option::ContestOptionIndex,
    egds_version::ElectionGuard_DesignSpecification_Version,
    guardian::GuardianIndex,
    key::KeyPurpose,
    label::EgLabelError,
    resource::{ElectionDataObjectId, ResourceId, ResourceIdFormat},
};

pub use crate::{
    el_gamal::ElGamalError,
    guardian_public_key_trait::PublicKeyValidationError,
    interguardian_share::{
        InterGuardianShareGenerationError, InterGuardianSharePublicValidationError,
    },
    loadable::EgLoadingError,
    resource_producer::ResourceProductionError,
    validatable::EgValidateError,
    verifiable_decryption::{
        CombineProofError, ComputeDecryptionError, DecryptionError, DecryptionShareCombinationError,
    },
    zk::ZkProofRangeError,
};

//=================================================================================================|

/// The main [`std::error::Error`] type returned by functions of the `eg` crate.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
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

    #[error("Ballot Style `{0}` doesn't know its index, at a place and time when it should.")]
    BallotStyleDoesntKnowItsIndex(BallotStyleIndex),

    #[error(
        "A Ballot Style doesn't know its index, at a place and time when it should, and it wasn't known from context either."
    )]
    BallotStyleDoesntKnowItsIndexAndItWasNotClearFromContextEither,

    #[error(
        "A Ballot Style that believes it has Ballot Style index `{0}`, but it doesn't match the Ballot Style in the election manifest at that index."
    )]
    BallotStyleDoesntMatchElectionManifest(BallotStyleIndex),

    #[error(
        "The Ballot Style at index `{actual_ballot_style_ix}` in the election manifest incorrectly believes it is at index `{bs_ballot_style_ix}`."
    )]
    BallotStyleIndexMismatch {
        actual_ballot_style_ix: BallotStyleIndex,
        bs_ballot_style_ix: BallotStyleIndex,
    },

    #[error(
        "Ballot Style `{ballot_style_ix}` `{ballot_style_label}` lists Contest `{contest_ix}` more than once."
    )]
    BallotStyleByIndexAndLabelDuplicateContest {
        ballot_style_ix: BallotStyleIndex,
        ballot_style_label: String,
        contest_ix: ContestIndex,
    },

    #[error("Ballot Style `{ballot_style_label}` lists Contest `{contest_ix}` more than once.")]
    BallotStyleByLabelDuplicateContest {
        ballot_style_label: String,
        contest_ix: ContestIndex,
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
        "Election manifest contests `{contest_ix_a}` and `{contest_ix_b}` have the same label `{duplicate_label}`."
    )]
    ContestsHaveDuplicateLabels {
        contest_ix_a: ContestIndex,
        contest_ix_b: ContestIndex,
        duplicate_label: String,
    },

    #[error(
        "Election manifest contest `{contest_ix}` options `{contest_option_ix_a}` and `{contest_option_ix_b}` have the same label `{duplicate_label}`."
    )]
    ContestOptionsHaveDuplicateLabels {
        contest_ix: ContestIndex,
        contest_option_ix_a: ContestOptionIndex,
        contest_option_ix_b: ContestOptionIndex,
        duplicate_label: String,
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

    #[error("`{qty_expected}` SecretCoefficients were expected, but `{qty_found}` were found.")]
    SecretCoefficientsIncorrectQuantity {
        qty_expected: usize,
        qty_found: usize,
    },

    #[error("`{qty_expected}` CoefficientCommitments were expected, but `{qty_found}` were found.")]
    CoefficientCommitmentsIncorrectQuantity {
        qty_expected: usize,
        qty_found: usize,
    },

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
    NoJointPublicKeyForPurpose { key_purpose: KeyPurpose },

    #[error("Guardian(s) `{0:?}` are not represented in a joint public key")]
    JointPublicKeyCompute_GuardiansMissing(Vec<GuardianIndex>),

    #[error("Guardian {0} is represented more than once in a joint public key")]
    JointPublicKeyCompute_GuardianMultiple(GuardianIndex),

    #[error("Guardian {0} is represented more than once in a joint public key")]
    JointPublicKey_InvalidGroupElement(KeyPurpose),

    #[error("Error producing ballot proofs: {0}")]
    ProofError(#[from] ZkProofRangeError),

    #[error(
        "Ballot Style `{ballot_style_ix}` is not present in the ElectionManifest, which has only `{election_manifest_cnt_ballot_styles}` Ballot Styles."
    )]
    BallotStyleNotInElectionManifest {
        ballot_style_ix: BallotStyleIndex,
        election_manifest_cnt_ballot_styles: usize,
    },

    #[error("Contest index `{0}` does not exist in ElectionManifest.")]
    ContestNotInManifest(ContestIndex),

    #[error(
        "Contest `{contest_ix}` does not exist in Ballot Style labeled `{ballot_style_label}`. If known, the Ballot Style index within the election manifest is `{opt_ballot_style_ix:?}`."
    )]
    ContestNotInBallotStyle {
        contest_ix: ContestIndex,
        ballot_style_label: String,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    },

    #[error(
        "A `VoterSelectionsPlaintext` provided selections for contest `{contest_ix}` which does not exist in the election manifest. If known, the Ballot Style index within the election manifest is `{opt_ballot_style_ix:?}`."
    )]
    VoterSelectionsPlaintextSuppliesSelectionsForContestNotInElectionManifest {
        contest_ix: ContestIndex,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    },

    #[error(
        "A `VoterSelectionsPlaintext` provided selections for contest `{contest_ix}` which does not exist in Ballot Style labeled `{ballot_style_label}`. If known, the Ballot Style index within the election manifest is `{opt_ballot_style_ix:?}`."
    )]
    VoterSelectionsPlaintextSuppliesSelectionsForContestNotInBallotStyle {
        contest_ix: ContestIndex,
        ballot_style_label: String,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    },

    #[error(
        "A `VoterSelectionsPlaintext` of Ballot Style `{ballot_style_ix}`, provided selections for contest `{contest_ix}` having {num_options_defined} selectable options, but `{num_options_supplied}` options were supplied."
    )]
    VoterSelectionsPlaintextSuppliesWrongNumberOfOptionSelectionsForContest {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
        num_options_defined: usize,
        num_options_supplied: usize,
    },

    #[error(
        "While producing a `ContestDataFieldsPlaintexts` for contest `{contest_ix}`, there were `{qty_expected}` values were expected, but `{qty_supplied}` were supplied."
    )]
    IncorrectQtyOfContestOptionFieldsPlaintexts {
        contest_ix: ContestIndex,
        qty_expected: usize,
        qty_supplied: usize,
    },

    #[error(
        "While producing a Ballot, the provided VoterSelectionsPlaintext contains a value for the extended base hash `H_E` that does not match the `H_E` for this election. \
Possibly this VoterSelectionsPlaintext was created for a different election or election configuration. \
VoterSelectionsPlaintext h_e=`{voterselections_h_e}`, \
PreVotingData h_e=`{election_h_e}`"
    )]
    VoterSelectionsPlaintextDoesNotMatchExpected {
        voterselections_h_e: crate::extended_base_hash::ExtendedBaseHash_H_E,
        election_h_e: crate::extended_base_hash::ExtendedBaseHash_H_E,
    },

    #[error("While producing a Ballot of style `{ballot_style_ix}`: {bx_err}")]
    WhileProducingBallot {
        ballot_style_ix: BallotStyleIndex,
        bx_err: Box<EgError>,
    },

    #[error("Ballot of style `{ballot_style_ix}` is missing contest `{contest_ix}`.")]
    BallotMissingDataFieldsForContestInBallotStyle {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(r#"Ballot Style{bsix} "{ballot_style_label}" claims to include Contest `{contest_ix}`, but that Contest does not exist in the ElectionManifest."#,
        bsix = opt_ballot_style_ix.map(|ix| format!(" `{ix}`")).unwrap_or_default()
    )]
    BallotStyleContestNotInElectionManifest {
        opt_ballot_style_ix: Option<BallotStyleIndex>,
        ballot_style_label: String,
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
        "While trying to construct a `VoterSelectionsPlaintext` of Ballot Style `{ballot_style_ix}`, selections were provided for contest `{contest_ix}` which does not exist in the election manifest."
    )]
    VoterSelectionsPlaintextClaimsNonExistentContest {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(
        "Ballot of style `{ballot_style_ix}` claims to contain contest `{contest_ix}` which is not present in the Ballot Style."
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

    #[error("{0}")]
    OtherError(WrapAnnoyingError<anyhow::Error>),

    #[error("{0}")]
    Str(&'static str),

    #[error(transparent)]
    DecryptionError(#[from] DecryptionError),

    #[error(transparent)]
    ComputeDecryptionError(#[from] ComputeDecryptionError),

    #[error(transparent)]
    CombineProofError(#[from] CombineProofError),

    #[error(
        "The fixed parameters claim to be for `{egds_version_from_fp_info}`, but they do not match the build configured parameters `{egds_version_from_buildcfg}`."
    )]
    FixedParametersDoNotMatchStatedElectionGuardDesignSpecificationVersion {
        egds_version_from_fp_info: ElectionGuard_DesignSpecification_Version,
        egds_version_from_buildcfg: ElectionGuard_DesignSpecification_Version,
    },

    #[error(
        "The fixed parameters neither declare an ElectionGuard Design Specification version, nor do they match the build configured parameters `{egds_version_from_buildcfg}`."
    )]
    FixedParametersDoNotDeclareAnElectionGuardDesignSpecificationVersionOrMatchStandardParams {
        egds_version_from_buildcfg: ElectionGuard_DesignSpecification_Version,
    },

    #[error(
        "The fixed parameters version `{egds_version_from_fp_info}` cannot be accepted because the application does not support toy parameters."
    )]
    ToyParametersNotSupported {
        egds_version_from_fp_info: ElectionGuard_DesignSpecification_Version,
    },

    #[error(
        "The fixed parameters version `{egds_version_from_fp_info}` cannot be accepted because the application does not support a non-standard ElectionGuard Design Specification version."
    )]
    NonstandardEgdsVersionNotSupported {
        egds_version_from_fp_info: ElectionGuard_DesignSpecification_Version,
    },

    #[error(transparent)]
    InterGuardianShareGenerationError(#[from] InterGuardianShareGenerationError),

    #[error(transparent)]
    InterGuardianSharePublicValidationError(#[from] InterGuardianSharePublicValidationError),

    #[error(transparent)]
    DecryptionShareCombinationError(#[from] DecryptionShareCombinationError),

    #[error(transparent)]
    ElGamal(#[from] ElGamalError),

    #[error(transparent)]
    LoadingError(EgLoadingError),

    #[error("During loading: {_0}.")]
    DuringLoading(Box<EgError>),

    #[error(transparent)]
    ValidationError(#[from] EgValidateError),

    #[error("During validation: {_0}.")]
    DuringValidation(Box<EgError>),

    #[error("Label error: {_0}.")]
    LabelError(EgLabelError),

    #[error(transparent)]
    TooLargeFor31Bits(#[from] util::uint31::U31Error),

    #[error(transparent)]
    TooLargeFor53Bits(#[from] util::uint53::U53Error),

    #[error("Internal error.")]
    StdConvertInfallible(
        #[from]
        #[serde(serialize_with = "util::serde::serialize_std_convert_infallible")]
        std::convert::Infallible,
    ),

    #[error("IO error: {0}")]
    StdIoError(WrapAnnoyingError<std::io::Error>),

    #[error("Value out of range: {0}")]
    TryFromIntError(
        #[from]
        #[serde(serialize_with = "util::serde::serialize_std_num_tryfrominterror")]
        std::num::TryFromIntError,
    ),

    #[error("Malformed UTF-8: {0}")]
    MalformedUtf8Error(
        #[from]
        #[serde(serialize_with = "util::serde::serialize_std_string_fromutf8error")]
        std::string::FromUtf8Error,
    ),

    #[error(transparent)]
    FieldError(#[from] crate::algebra::FieldError),

    #[error(transparent)]
    ParseIntError(
        #[from]
        #[serde(serialize_with = "util::serde::serialize_std_num_parseinterror")]
        std::num::ParseIntError,
    ),

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
        "Contest `{contest_ix}` was listed in the Ballot Style `{ballot_style_ix}`, but it was not verified."
    )]
    BallotContestNotVerified {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(
        "Contest `{contest_ix}` was verified, but it is not listed in the Ballot Style `{ballot_style_ix}`."
    )]
    BallotContestVerifiedNotInBallotStyle {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error(transparent)]
    ResourceProductionError(ResourceProductionError),

    #[error("During resource production: {_0}.")]
    DuringResourceProduction(Box<EgError>),

    #[error("A path could not be constructed for election data object `{0}`.")]
    ResourcePathFromEdoId(ElectionDataObjectId),

    #[error("A path could not be constructed for resource `{0}`.")]
    ResourcePathFromResourceId(ResourceId),

    #[error("The `{ridfmt}` is not correct for type `{ty}`.")]
    UnexpectedResourceIdFormatForType {
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

    #[error("JSON error: {0}")]
    JsonError(WrapAnnoyingError<serde_json::Error>),

    #[error("Deserializing (serde::de) error: {0}")]
    DeserializeError(String),
}

assert_impl_all!(EgError: Send, Sync);

impl EgError {
    pub fn unless<F, E>(cond: bool, f: F) -> EgResult<()>
    where
        F: Fn() -> E,
        E: Into<EgError>,
    {
        if cond { Ok(()) } else { Err(f().into()) }
    }

    /// Wraps an `EgError` in an `EgError::WhileProducingBallot`.
    pub fn while_producing_ballot(self, ballot_style_ix: BallotStyleIndex) -> Self {
        EgError::WhileProducingBallot {
            ballot_style_ix,
            bx_err: Box::new(self),
        }
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

impl From<EgLoadingError> for EgError {
    /// An [`EgError`] can always be made from a [`EgLoadingError`].
    fn from(src: EgLoadingError) -> Self {
        match src {
            EgLoadingError::EgError(bx_egerror) => Self::DuringLoading(bx_egerror),
            _ => Self::LoadingError(src),
        }
    }
}

impl From<EgLabelError> for EgError {
    /// An [`EgError`] can always be made from a [`EgLabelError`].
    fn from(src: EgLabelError) -> Self {
        Self::LabelError(src)
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

impl From<anyhow::Error> for EgError {
    /// A [`EgError`] can always be made from a [`anyhow::Error`].
    #[inline]
    fn from(anyhow_error: anyhow::Error) -> Self {
        EgError::OtherError(WrapAnnoyingError::from_anyhow_Error(anyhow_error))
    }
}

impl From<std::io::Error> for EgError {
    /// A [`EgError`] can always be made from a [`std::io::Error`].
    #[inline]
    fn from(src: std::io::Error) -> Self {
        EgError::StdIoError(WrapAnnoyingError::from(src))
    }
}

//? TODO this can go away when we move away from that inflexible macro generating the util::uint31::Uint31 type.
impl From<util::uint31::Uint31Error> for EgError {
    /// A [`EgError`] can always be made from a [`util::uint31::Uint31Error`].
    #[inline]
    fn from(src: util::uint31::Uint31Error) -> Self {
        EgError::TooLargeFor31Bits(src.into())
    }
}

//? TODO this can go away when we move away from that inflexible macro generating the util::uint53::Uint53 type.
impl From<util::uint53::Uint53Error> for EgError {
    /// A [`EgError`] can always be made from a [`util::uint53::Uint53Error`].
    #[inline]
    fn from(src: util::uint53::Uint53Error) -> Self {
        EgError::TooLargeFor53Bits(src.into())
    }
}

/// [`Result`](std::result::Result) type with `Err` type `E` of [`EgError`].
pub type EgResult<T> = std::result::Result<T, EgError>;

/// A wrapper for:
///
/// - anyhow::Error, because it does not implement [`std::error::Error`].
/// - std::io::Error, because it does not implement [`std::ops::Clone`].
#[derive(serde::Serialize)]
pub struct WrapAnnoyingError<T>(Vec<String>, #[serde(skip)] Arc<T>)
where
    T: std::fmt::Debug + std::fmt::Display + Send + Sync;

impl<T> Clone for WrapAnnoyingError<T>
where
    T: std::fmt::Debug + std::fmt::Display + Send + Sync,
{
    /// Returns a copy of the [`WrapAnnoyingError<T>`].
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone())
    }
}

impl<T> WrapAnnoyingError<T>
where
    T: std::fmt::Debug + std::fmt::Display + Send + Sync,
{
    pub fn ref_inner_arc(&self) -> &Arc<T> {
        &self.1
    }

    fn append_error_strings(v: &mut Vec<String>, e: &dyn std::error::Error) {
        const MAX_DEPTH: usize = 100;
        const MAX_V: usize = 1000;

        fn recur(v: &mut Vec<String>, depth: usize, e: &dyn std::error::Error) {
            if v.len() < MAX_V {
                v.push(format!("{depth}: {e:?}"));
                if depth < MAX_DEPTH {
                    let mut opt_e: Option<&dyn std::error::Error> = e.source();
                    while let Some(e) = opt_e {
                        recur(v, depth + 1, e);
                        opt_e = e.source();
                    }
                }
            }
        }

        recur(v, 1, e);
    }
}

impl WrapAnnoyingError<anyhow::Error> {
    /// A [`WrapAnyhowError`] can always be made from a [`anyhow::Error`].
    #[allow(non_snake_case)]
    #[inline]
    pub fn from_anyhow_Error(anyhow_error: anyhow::Error) -> Self {
        let mut v: Vec<String> = vec!["anyhow::Error".to_string()];
        for e in anyhow_error.chain() {
            Self::append_error_strings(&mut v, e);
        }
        Self(v, Arc::new(anyhow_error))
    }
}

impl From<serde_json::Error> for EgError {
    /// A [`EgError`] can always be made from a [`serde_json::Error`].
    #[inline]
    fn from(src: serde_json::Error) -> Self {
        EgError::JsonError(src.into())
    }
}

/*
impl From<EgError> for serde::de::MapAccess<'de>::Error {
    /// A [`serde::de::MapAccess<'de>::Error`] can always be made from a [`EgError`].
    #[inline]
    fn from(src: EgError) -> Self {
        serde::de::MapAccess<'de>::Error
    }
}
// */
impl serde::de::Error for EgError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        let s = msg.to_string();
        EgError::DeserializeError(s)
    }
}

impl<T> From<T> for WrapAnnoyingError<T>
where
    T: std::error::Error + std::fmt::Debug + std::fmt::Display + Send + Sync,
{
    /// A [`WrapAnnoyingError<T>`] can always be made from a `T:` [`std::error::Error`]
    /// `+` [`std::fmt::Debug`] `+` [`std::fmt::Display`] `+` [`Send`] `+` [`Sync`].
    #[inline]
    fn from(e: T) -> Self {
        let mut v: Vec<String> = vec!["T::Error".to_string()];
        Self::append_error_strings(&mut v, &e);
        Self(v, Arc::new(e))
    }
}

impl<T> std::fmt::Debug for WrapAnnoyingError<T>
where
    T: std::fmt::Debug + std::fmt::Display + Send + Sync,
{
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.1.as_ref(), f)
    }
}

impl<T> std::fmt::Display for WrapAnnoyingError<T>
where
    T: std::fmt::Debug + std::fmt::Display + Send + Sync,
{
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.1.as_ref(), f)
    }
}

impl<T> PartialEq for WrapAnnoyingError<T>
where
    T: std::fmt::Debug + std::fmt::Display + Send + Sync,
{
    /// Compare based only on the string representation.
    #[inline]
    fn eq(&self, rhs: &Self) -> bool {
        self.0.eq(&rhs.0)
    }
}

impl<T> Eq for WrapAnnoyingError<T> where T: std::fmt::Debug + std::fmt::Display + Send + Sync {}
