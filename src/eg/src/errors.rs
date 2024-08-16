// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(non_camel_case_types)] // We use underscores for clarity in some error message identifiers

use crate::{
    ballot_style::BallotStyleIndex,
    ciphertext::CiphertextIndex,
    election_manifest::{ContestIndex, ContestOptionIndex},
    guardian::GuardianIndex,
    hash::HValue,
};

pub use crate::{
    guardian_public_key_info::PublicKeyValidationError,
    u31::Uint31Error,
    u53::Uint53Error,
    verifiable_decryption::{
        CombineProofError, ComputeDecryptionError, DecryptionError, ShareCombinationError,
    },
    zk::ZkProofRangeError,
};

/// The main [`std::error::Error`] type returned by functions of the `eg` crate.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum EgError {
    #[error("Election manifest contest `{contest_ix}` incorrectly believes it is at index `{contests_contest_ix}`.")]
    ContestIndexMismatch {
        contest_ix: ContestIndex,
        contests_contest_ix: ContestIndex,
    },

    #[error("Election manifest ballot style `{actual_ballot_style_ix}` incorrectly believes it is at index `{bs_ballot_style_ix}`.")]
    BallotStyleIndexMismatch {
        actual_ballot_style_ix: BallotStyleIndex,
        bs_ballot_style_ix: BallotStyleIndex,
    },

    #[error("Election manifest contest `{actual_contest_ix}` option `{contest_option_ix}` incorrectly believes it belongs to contest  `{co_contest_ix}`.")]
    OptionContestIndexMismatch {
        actual_contest_ix: ContestIndex,
        contest_option_ix: ContestOptionIndex,
        co_contest_ix: ContestIndex,
    },

    #[error("Election manifest contest `{contest_ix}` option `{actual_contest_option_ix}` incorrectly believes it is at option index `{co_contest_option_ix}`.")]
    ContestOptionIndexMismatch {
        contest_ix: ContestIndex,
        actual_contest_option_ix: ContestOptionIndex,
        co_contest_option_ix: ContestOptionIndex,
    },

    #[error(
        "Contest selection limit value of {0} is not in the supported range of 0 to 2147483647."
    )]
    ContestSelectionLimitOutOfSupportedRange(u64),

    #[error("While constructing a contest selection, encountered option value at (1-based index) {0} that is not in the supported range of 0 to 2147483647.")]
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

    #[error("Contest option `{contest_option_ix}` of contest `{contestoption_contest_ix}` was asked to compute its effective selection limit as if it were in contest `{containing_contest_ix}` instead.")]
    ContestOptionActuallyInDifferentContest {
        contest_option_ix: ContestOptionIndex,
        containing_contest_ix: ContestIndex,
        contestoption_contest_ix: ContestIndex,
    },

    #[error("Contest option of contest `{contestoption_contest_ix}` was asked to compute its effective selection limit as if it were in contest `{containing_contest_ix}` instead.")]
    ContestOptionActuallyInDifferentContest2 {
        containing_contest_ix: ContestIndex,
        contestoption_contest_ix: ContestIndex,
    },

    #[error("PublicKeyValidationError: {0}")]
    PublicKeyValidationError(#[from] PublicKeyValidationError),

    #[error("Guardians {0} are not represented in the guardian public keys")]
    JointElectionPublicKeyCompute_GuardiansMissing(String),

    #[error("Guardian {0} is represented more than once in the guardian public keys")]
    JointElectionPublicKeyCompute_GuardianMultiple(GuardianIndex),

    #[error("Error producing ballot proofs: {0}")]
    ProofError(#[from] ZkProofRangeError),

    #[error("Ballot style `{0}` not in election manifest.")]
    BallotStyleNotInElectionManifest(BallotStyleIndex),

    #[error("Contest index `{0}` does not exist in ElectionManifest.")]
    ContestNotInManifest(ContestIndex),

    #[error("Contest `{contest_ix}` does not exist in ballot style label `{ballot_style_label}`. If known, the ballot style index within the manifest is `{opt_ballot_style_ix:?}`.")]
    ContestNotInBallotStyle {
        contest_ix: ContestIndex,
        ballot_style_label: String,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    },

    #[error("A `VoterSelectionsPlaintext` provided selections for contest `{contest_ix}` which does not exist in the election manifest. If known, the ballot style index within the election manifest is `{opt_ballot_style_ix:?}`.")]
    VoterSelectionsPlaintextSuppliesSelectionsForContestNotInElectionManifest {
        contest_ix: ContestIndex,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    },

    #[error("A `VoterSelectionsPlaintext` provided selections for contest `{contest_ix}` which does not exist in ballot style labeled `{ballot_style_label}`. If known, the ballot style index within the election manifest is `{opt_ballot_style_ix:?}`.")]
    VoterSelectionsPlaintextSuppliesSelectionsForContestNotInBallotStyle {
        contest_ix: ContestIndex,
        ballot_style_label: String,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    },

    #[error("A `VoterSelectionsPlaintext` of ballot style `{ballot_style_ix}`, provided selections for contest `{contest_ix}` having {num_options_defined} selectable options, but `{num_options_supplied}` options were supplied.")]
    VoterSelectionsPlaintextSuppliesWrongNumberOfOptionSelectionsForContest {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
        num_options_defined: usize,
        num_options_supplied: usize,
    },

    #[error("While trying to produce a `Ballot`, the provided `VoterSelectionsPlaintext` contains a value for `h_e` (the extended base hash) that does not match the the `PreVotingData`. \
A possible explanation is that that this `VoterSelectionsPlaintext` was created for a different election or election configuration. \
VoterSelectionsPlaintext h_e=`{vsp_h_e}`, \
PreVotingData h_e=`{pvd_h_e}`")]
    VoterSelectionsPlaintextDoesNotMatchPreVotingData { vsp_h_e: HValue, pvd_h_e: HValue },

    #[error("Ballot of style `{ballot_style_ix}` is missing contest `{contest_ix}`.")]
    BallotMissingDataFieldsForContestInBallotStyle {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error("Ballot style `{ballot_style_ix}` claims to contain contest `{contest_ix}` which does not exist in the election manifest.")]
    BallotStyleClaimsNonExistentContest {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error("Ballot of style `{ballot_style_ix}` claims to contain contest `{contest_ix}` which does not exist in the election manifest.")]
    BallotClaimsNonExistentContest {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error("While trying to construct a `VoterSelectionsPlaintext` of ballot style `{ballot_style_ix}`, selections were provided for contest `{contest_ix}` which does not exist in the election manifest.")]
    VoterSelectionsPlaintextClaimsNonExistentContest {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error("Ballot of style `{ballot_style_ix}` claims to contain contest `{contest_ix}` which is not present in the ballot style.")]
    BallotClaimsContestNonExistentInBallotStyle {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error("Ballot of style `{ballot_style_ix}` contest `{contest_ix}` fields ciphertexts did not verify")]
    BallotContestFieldsCiphertextsDidNotVerify {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error("Contest option index out of range `{0}`")]
    ContestOptionIxOutOfRange(u32),

    #[cfg(feature = "eg-test-data-generation")]
    #[error("Random number generation error: {0}")]
    RandError(String),

    #[error("A collection containing `{0}` elements of some kind was provided, which is larger than the limit of `2^31 - 1`.")]
    CollectionTooLarge(usize),

    #[error("An attempt was made to grow a collection already containing the maximum `2^31 - 1` elements.")]
    CollectionCantGrow,

    #[error("TryReserveError: {0}")]
    TryReserveError(#[from] std::collections::TryReserveError),

    #[error("Error description: {0}")]
    AnyhowError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(#[from] DecryptionError),

    #[error("Compute decryption error: {0}")]
    ComputeDecryptionError(#[from] ComputeDecryptionError),

    #[error("Combine proof error: {0}")]
    CombineProofError(#[from] CombineProofError),

    #[error("Share combination error: {0}")]
    ShareCombinationError(#[from] ShareCombinationError),

    #[error("Value is larger than `2^53 - 1`")]
    TooLargeFor31Bits(#[from] Uint31Error),

    #[error("Value is larger than `2^53 - 1`")]
    TooLargeFor53Bits(#[from] Uint53Error),

    #[error("Value out of range")]
    TryFromIntError(#[from] std::num::TryFromIntError),

    #[error("Couldn't parse integer")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Contest `{contest_ix}` option or data field `{ciphertext_ix}` does not verify: proof is not present in encrypted contest data.")]
    BallotContestFieldCiphertextDoesNotVerify_ProofNotPresent {
        contest_ix: ContestIndex,
        ciphertext_ix: CiphertextIndex,
    },

    #[error("Contest `{contest_ix}` option or data field `{ciphertext_ix}` does not verify: proof does not verify.")]
    BallotContestFieldCiphertextDoesNotVerify_ProofDoesNotVerify {
        contest_ix: ContestIndex,
        ciphertext_ix: CiphertextIndex,
    },

    #[error("Contest `{contest_ix}` does not verify: contest selection limit of `{effective_contest_selection_limit}` does not verify.")]
    BallotContestFieldCiphertextDoesNotVerify_ContestSelectionLimit {
        contest_ix: ContestIndex,
        effective_contest_selection_limit: u32,
    },

    #[error("Contest `{contest_ix}` does not verify: verified `{cnt_ciphertexts_verified}` ciphertexts but there are {cnt_data_fields_in_contest} data fields in the contest.")]
    BallotContestFieldCiphertextDoesNotVerify_WrongNumberOfCiphertextProofs {
        contest_ix: ContestIndex,
        cnt_ciphertexts_verified: usize,
        cnt_data_fields_in_contest: usize,
    },

    #[error("Contest `{contest_ix}` was listed in the ballot style `{ballot_style_ix}`, but it was not verified.")]
    BallotContestNotVerified {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },

    #[error("Contest `{contest_ix}` was verified, but it is not listed in the ballot style `{ballot_style_ix}`.")]
    BallotContestVerifiedNotInBallotStyle {
        ballot_style_ix: BallotStyleIndex,
        contest_ix: ContestIndex,
    },
}

#[cfg(feature = "eg-test-data-generation")]
impl From<rand::Error> for EgError {
    fn from(e: rand::Error) -> Self {
        EgError::RandError(e.to_string())
    }
}

impl From<anyhow::Error> for EgError {
    fn from(e: anyhow::Error) -> Self {
        EgError::AnyhowError(e.to_string())
    }
}

pub type EgResult<T> = std::result::Result<T, EgError>;
