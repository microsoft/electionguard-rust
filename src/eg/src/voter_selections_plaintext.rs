// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::collections::BTreeMap;

use rand::{distributions::Uniform, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    ballot_style::{BallotStyle, BallotStyleIndex},
    contest_option_fields::{ContestOptionFieldPlaintext, ContestOptionFieldsPlaintexts},
    election_manifest::ContestIndex,
    errors::{EgError, EgResult},
    hash::HValue,
    pre_voting_data::PreVotingData,
    serializable::SerializablePretty,
    vec1::Vec1,
};

use util::csprng::Csprng;

/// Plaintext voter selections for a specific ballot style.
///
/// This is specifically *not* a [`Ballot`], this is the input data format to the [`ElectionGuard`]
/// encryption which produces an ElectionGuard [`Ballot`].
///
/// For privacy, this structure specifically does not include device or date-time information.
///
#[derive(Debug, Serialize, Deserialize)]
pub struct VoterSelectionsPlaintext {
    /// The [extended base hash](crate::hashes_ext::HashesExt) from the [`PreVotingData`],
    /// checked to ensure the data is applied to the correct election.
    pub h_e: HValue,

    /// The 1-based index of the [`BallotStyle`] within the [`ElectionManifest`].
    pub ballot_style_ix: BallotStyleIndex,

    /// Plaintext contest option field values reflecting voter selections.
    /// These field values are not guaranteed to comply with effective selection limits.
    /// Additional data fields may be present after the voter-selectable options.
    pub contests_option_fields_plaintexts: BTreeMap<ContestIndex, ContestOptionFieldsPlaintexts>,
}

impl VoterSelectionsPlaintext {
    /// Constructs a new [`VoterSelectionsPlaintext`].
    pub fn try_new(
        pre_voting_data: &PreVotingData,
        ballot_style_ix: BallotStyleIndex,
        contests_option_fields_plaintexts: BTreeMap<ContestIndex, ContestOptionFieldsPlaintexts>,
    ) -> EgResult<Self> {
        let _self = Self {
            h_e: pre_voting_data.hashes_ext.h_e,
            ballot_style_ix,
            contests_option_fields_plaintexts,
        };

        _self.verify_against_pre_voting_data(pre_voting_data)?;

        Ok(_self)
    }

    /// Verifies that the [`VoterSelectionsPlaintext`] is consistent with the provided
    /// [`PreVotingData`], particularly its [`BallotStyle`] the ElectionManifest.
    ///
    /// This does not reference selection limits.
    ///
    /// Returns the [`BallotStyleIndex`] and a reference to the [`BallotStyle`] for convenience.
    pub fn verify_against_pre_voting_data<'a>(
        &self,
        pre_voting_data: &'a PreVotingData,
    ) -> EgResult<(BallotStyleIndex, &'a BallotStyle)> {
        // Verify the extended base hash.
        if self.h_e != pre_voting_data.hashes_ext.h_e {
            return Err(EgError::VoterSelectionsPlaintextDoesNotMatchPreVotingData {
                vsp_h_e: pre_voting_data.hashes_ext.h_e,
                pvd_h_e: self.h_e,
            });
        }

        // Verify the specified BallotStyle exists in the manifest.
        let ballot_style = pre_voting_data
            .manifest
            .get_ballot_style(self.ballot_style_ix)?;

        // For each [`Contest`] for which selections were provided
        for (&contest_ix, contest_option_fields_plaintexts) in
            &self.contests_option_fields_plaintexts
        {
            // Verify the ElectionManifest and BallotStyle contain the Contest for which voter selections were provided.
            let contest = ballot_style.get_contest(pre_voting_data, contest_ix)
                .map_err(|e| match e {
                        EgError::ContestNotInBallotStyle { contest_ix, ballot_style_label, .. } =>
                                EgError::VoterSelectionsPlaintextSuppliesSelectionsForContestNotInBallotStyle {
                                        contest_ix,
                                        ballot_style_label,
                                        opt_ballot_style_ix: Some(self.ballot_style_ix), },
                        EgError::ContestNotInManifest(contest_ix) =>
                                EgError::VoterSelectionsPlaintextSuppliesSelectionsForContestNotInElectionManifest {
                                        contest_ix,
                                        opt_ballot_style_ix: Some(self.ballot_style_ix), },
                        _ => e,
                    })?;

            // Check that the number of contest option field plaintexts matches the number of contest options.
            // We do not enforce selection limits here.
            if contest_option_fields_plaintexts.len() != contest.contest_options.len() {
                return Err(EgError::VoterSelectionsPlaintextSuppliesWrongNumberOfOptionSelectionsForContest {
                    ballot_style_ix: self.ballot_style_ix, contest_ix,
                    num_options_defined: contest.contest_options.len(),
                    num_options_supplied: contest_option_fields_plaintexts.len() });
            }
        }

        Ok((self.ballot_style_ix, ballot_style))
    }

    /// Constructs a new [`VoterSelectionsPlaintext`].
    #[cfg(feature = "eg-test-data-generation")]
    pub fn new_generate_random_selections(
        pre_voting_data: &PreVotingData,
        ballot_style_ix: BallotStyleIndex,
        csprng: &mut Csprng,
    ) -> EgResult<Self> {
        let ballot_style = pre_voting_data.manifest.get_ballot_style(ballot_style_ix)?;

        let mut contests_option_fields_plaintexts = BTreeMap::new();
        for &contest_ix in ballot_style.contests().iter() {
            let contest_selections_pts =
                Self::random_contest_selections(pre_voting_data, ballot_style, contest_ix, csprng)?;

            contests_option_fields_plaintexts.insert(contest_ix, contest_selections_pts);
        }

        Self::try_new(
            pre_voting_data,
            ballot_style_ix,
            contests_option_fields_plaintexts,
        )
    }

    #[cfg(feature = "eg-test-data-generation")]
    fn random_contest_selections(
        pre_voting_data: &PreVotingData,
        ballot_style: &BallotStyle,
        contest_ix: ContestIndex,
        csprng: &mut Csprng,
    ) -> EgResult<ContestOptionFieldsPlaintexts> {
        let contest = ballot_style.get_contest(pre_voting_data, contest_ix)?;

        let contest_options = &contest.contest_options;
        let cnt_contest_options = contest_options.len();

        let mut contest_option_fields_plaintexts =
            Vec1::<ContestOptionFieldPlaintext>::with_capacity(cnt_contest_options);
        if !contest_option_fields_plaintexts.is_empty() {
            for _ in 0..cnt_contest_options {
                contest_option_fields_plaintexts.try_push(ContestOptionFieldPlaintext::zero())?;
            }

            let effective_contest_selection_limit: u32 =
                contest.effective_contest_selection_limit()?.into();

            // 20%: no selection,
            // 10%: apply fewer than selection limit (undervote),
            // 70%: exactly the selection limit.
            let mut selections_remaining = match csprng.sample(Uniform::from(0..100)) {
                0..20 => 0,
                20..30 => match effective_contest_selection_limit {
                    0..2 => 0,
                    2 => 1,
                    _ => csprng.sample(Uniform::from(1..effective_contest_selection_limit)),
                },
                _ => effective_contest_selection_limit,
            };

            let options_effective_selection_limits =
                contest.figure_options_effective_selection_limits()?;

            while selections_remaining != 0 {
                // Pick a random selectable option from the contest.

                // Unwrap() is justified here because we already checked that `contest_options` is not empty.
                #[allow(clippy::unwrap_used)]
                let option_ix = contest_options.random_index(csprng).unwrap();

                // Look up the effective selection limit for the selected option.

                // Unwrap() is justified here because option_ix was selected from contest_options.
                #[allow(clippy::unwrap_used)]
                let effective_option_selection_limit =
                    *options_effective_selection_limits.get(option_ix).unwrap();

                // Unwrap() is justified here because option_ix was selected from contest_options.
                #[allow(clippy::unwrap_used)]
                let mut_ref_option_field_pt =
                    contest_option_fields_plaintexts.get_mut(option_ix).unwrap();

                let current_val = u32::from(*mut_ref_option_field_pt);
                if current_val < effective_option_selection_limit.into() {
                    *mut_ref_option_field_pt =
                        ContestOptionFieldPlaintext::try_new(current_val + 1)?;
                    selections_remaining -= 1;
                }
            }
        }

        Ok(contest_option_fields_plaintexts.into())
    }
}

impl SerializablePretty for VoterSelectionsPlaintext {}
