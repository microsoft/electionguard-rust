// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::rc::Rc;

use either::*;
use serde::{Deserialize, Serialize};
use util::{
    index::Index,
    vec1::{HasIndexType, Vec1},
};

use crate::{
    ballot_style::{BallotStyle, BallotStyleIndex, BallotStyleInfo},
    ciphertext::{Ciphertext, CiphertextIndex},
    eg::Eg,
    errors::{EgError, EgResult},
    selection_limits::{
        ContestSelectionLimit, EffectiveContestSelectionLimit, EffectiveOptionSelectionLimit,
        OptionSelectionLimit,
    },
    serializable::SerializableCanonical,
    validatable::Validated,
    voting_device::VotingDeviceInformationSpec,
};

/*
/// The configuration options for recording Overvotes and Undervotes for each Contest
/// on a Ballot.
pub enum UnderOverVoted {
    /// Under/Overvoted condition is not recorded.
    NotIncluded,

    /// The existance of an Under/Overvoted condition for this is recorded.
    FlagOnly,
    Quantitiy
}

/// Configuration options for recording specific conditions on an encrypted Ballot.
/// Enabling these configuration options generally increases the number of data fields for
/// each Contest, and thus the size of the encrypted Ballot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdditionalContestDataFields {
    // Overvote
    overvote: UnderOverVote,

    // Undervote
    undervote: UnderOverVote,

    // Record null vote
    null_vote: bool,

    // [Optional] Write in field
}
*/

/// The election manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ElectionManifestInfo {
    /// A descriptive label for this election.
    pub label: String,

    /// All the [`Contest`]s in the election.
    pub contests: Vec1<Contest>,

    /// All the [`BallotStyle`]s of the election.
    pub ballot_styles: Either<Vec1<BallotStyleInfo>, Vec1<BallotStyle>>,

    /// EGDS 2.1.0 Sec 3.4.3 - Voting Device Information
    ///
    /// The manifest specifies which data is to be included in the `S_device` string
    /// which is hashed to produce the [`VotingDeviceInformationHash`], `H_DI`.
    pub voting_device_information_spec: Rc<VotingDeviceInformationSpec>,
}

crate::impl_knows_friendly_type_name! { ElectionManifestInfo }

crate::impl_Resource_for_simple_ElectionDataObjectId_info_type! { ElectionManifestInfo, ElectionManifest }

impl SerializableCanonical for ElectionManifestInfo {}

impl<'de> Deserialize<'de> for ElectionManifestInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Error, MapAccess};
        use strum::{IntoStaticStr, VariantNames};

        #[derive(Deserialize, IntoStaticStr, VariantNames)]
        #[serde(field_identifier)]
        #[allow(non_camel_case_types)]
        enum Field {
            label,
            contests,
            ballot_styles,
        }

        struct ElectionManifestInfoVisitor;

        impl<'de> de::Visitor<'de> for ElectionManifestInfoVisitor {
            type Value = ElectionManifestInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("ElectionManifest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let Some((Field::label, label)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::label.into()));
                };

                let Some((Field::contests, contests)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::contests.into()));
                };

                let Some((Field::ballot_styles, v_bsi)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::ballot_styles.into()));
                };

                let v1_bsi: Vec1<BallotStyleInfo> =
                    Vec1::try_from_vec(v_bsi).map_err(|e| V::Error::custom(e.to_string()))?;

                //? TODO
                let voting_device_information_spec = VotingDeviceInformationSpec::default();
                let rc_voting_device_information_spec = Rc::new(voting_device_information_spec);

                Ok(ElectionManifestInfo {
                    label,
                    contests,
                    ballot_styles: Left(v1_bsi),
                    voting_device_information_spec: rc_voting_device_information_spec,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("ElectionManifestInfo", FIELDS, ElectionManifestInfoVisitor)
    }
}

crate::impl_validatable_validated! {
    src: ElectionManifestInfo, eg => EgResult<ElectionManifest> {
        //? let election_parameters = eg.election_parameters()?.as_ref();

        let ElectionManifestInfo {
            label,
            contests,
            ballot_styles,
            voting_device_information_spec,
        } = src;

        //----- Validate `label`.

        //? TODO let label = label.validate(eg)?;

        //----- Validate `contests`.

        //? TODO let contests = contests.validate(eg)?;

        //for contest in contests {
            // Validate the contest.
            //? TODO *contest = (*contest).validate(eg)?;
            //? TODO    if the stated selection limit is greater than the sum of the option selection limits, issue a warning.
            //? TODO    if the contest has a selection limit of 0, issue a warning
            //? TODO    For each option
            //? TODO       if the option has a selection limit of 0, issue a warning

            //? TODO if the contest is present in zero ballot styles, issue a warning.
        //}

        //----- Validate `ballot_styles`.

        //? TODO can we just use 'map' here or something?
        let ballot_styles: Vec1<BallotStyle> = match ballot_styles {
            Left(v1_bsi) => {
                let mut v1_bs: Vec1<BallotStyle> = Vec1::new();
                for bsi in v1_bsi {
                    let bs = <BallotStyle as Validated>::try_validate_from(bsi, eg)?;
                    v1_bs.try_push(bs)?;
                }
                v1_bs
            }
            Right(v1_bs) => v1_bs,
        };

        //----- Validate `voting_device_information_spec`.

        //----- Construct the object from the validated data.

        let mut self_ = ElectionManifest {
            label,
            contests,
            ballot_styles,
            voting_device_information_spec,
        };

        // Inform the contained objects of their indices.
        self_.inform_contests_and_options_of_their_indices()?;
        self_.inform_ballot_styles_of_their_indices()?;

        //----- Return the fully constructed and validated `ElectionManifest` object.

        Ok(self_)
    }
}

impl From<ElectionManifest> for ElectionManifestInfo {
    /// Convert from ElectionManifest back to a ElectionManifestInfo for re-validation.
    fn from(src: ElectionManifest) -> Self {
        let ElectionManifest {
            label,
            contests,
            ballot_styles,
            voting_device_information_spec,
        } = src;

        Self {
            label,
            contests,
            ballot_styles: Right(ballot_styles),
            voting_device_information_spec,
        }
    }
}

/// The election manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElectionManifest {
    label: String,
    contests: Vec1<Contest>,
    ballot_styles: Vec1<BallotStyle>,
    voting_device_information_spec: Rc<VotingDeviceInformationSpec>,
}

impl ElectionManifest {
    /// Creates and validates a new [`ElectionManifest`] composed of the supplied members.
    pub fn new(
        eg: &Eg,
        label: String,
        contests: Vec1<Contest>,
        ballot_styles: Vec1<BallotStyle>,
        voting_device_information_spec: Rc<VotingDeviceInformationSpec>,
    ) -> EgResult<Self> {
        let election_manifest_info = ElectionManifestInfo {
            label,
            contests,
            ballot_styles: Right(ballot_styles),
            voting_device_information_spec,
        };

        ElectionManifest::try_validate_from(election_manifest_info, eg)
    }

    /// Returns access to the label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns access to the collection of [`Contest`]s.
    ///
    /// If you just want a specific contest:
    /// - If you know the ballot style, consider using `ballot_style.get_contest()`.
    /// - Otherwise, `election_manifest.get_contest_without_checking_ballot_style()`.
    pub fn contests(&self) -> &Vec1<Contest> {
        &self.contests
    }

    /// Returns access to the collection of [`BallotStyle`]s.
    ///
    /// If you just want a specific ballot style, consider using [`.get_ballot_style()`].
    pub fn ballot_styles(&self) -> &Vec1<BallotStyle> {
        &self.ballot_styles
    }

    /// Returns a ref to the [`BallotStyle`] at the specified [`BallotStyleIndex`].
    ///
    /// Verifies that the resulting `BallotStyle`:
    /// - knows its `BallotStyleIndex`, and
    /// - its `BallotStyleIndex` matches the one by which it was just retrieved.
    ///
    pub fn get_ballot_style_validate_ix(
        &self,
        ballot_style_ix: BallotStyleIndex,
    ) -> EgResult<&BallotStyle> {
        let bs = self
            .ballot_styles
            .get(ballot_style_ix)
            .ok_or(EgError::BallotStyleNotInElectionManifest(ballot_style_ix))?;

        // Don't give it the `ElectionManifest`. Since we already know it was
        // retrieved from it at the specified index, the additional work it does is not useful.
        bs.get_validated_ballot_style_ix(Some(ballot_style_ix), None)?;

        Ok(bs)
    }

    /// EGDS 2.1.0 Sec 3.4.3 - Voting Device Information
    ///
    /// The manifest specifies which data is to be included in the `S_device` string
    /// which is hashed to produce the [`VotingDeviceInformationHash`], `H_DI`.
    pub fn voting_device_information_spec(&self) -> &VotingDeviceInformationSpec {
        &self.voting_device_information_spec
    }

    /// Returns a ref to the [`Contest`] at the specified index.
    ///
    /// Note: If you know the ballot style, prefer to use the `ballot_style.get_contest()` instead.
    pub fn get_contest_without_checking_ballot_style(
        &self,
        contest_ix: ContestIndex,
    ) -> EgResult<&Contest> {
        self.contests
            .get(contest_ix)
            .ok_or(EgError::ContestNotInManifest(contest_ix))
    }

    /// Inform each contest of its index.
    /// Also, inform the contest options of their indices.
    fn inform_contests_and_options_of_their_indices(&mut self) -> EgResult<()> {
        for (contest_ix, contest) in self.contests.enumerate_mut() {
            contest.inform_contest_of_its_index_and_its_options_of_theirs(contest_ix)?;
        }
        Ok(())
    }

    /// Inform each ballot style of its index.
    ///
    /// Returns error if a ballotStyle believes it is the wrong index.
    fn inform_ballot_styles_of_their_indices(&mut self) -> EgResult<()> {
        for (actual_ballot_style_ix, ballot_style) in self.ballot_styles.enumerate_mut() {
            let mut_opt_ballot_style_ix = ballot_style.mut_opt_ballot_style_ix();
            match mut_opt_ballot_style_ix {
                Some(bs_ballot_style_ix) => {
                    if *bs_ballot_style_ix != actual_ballot_style_ix {
                        return Err(EgError::BallotStyleIndexMismatch {
                            actual_ballot_style_ix,
                            bs_ballot_style_ix: *bs_ballot_style_ix,
                        });
                    }
                }
                None => *mut_opt_ballot_style_ix = Some(actual_ballot_style_ix),
            }
        }
        Ok(())
    }
}

impl SerializableCanonical for ElectionManifest {}

crate::impl_knows_friendly_type_name! { ElectionManifest }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { ElectionManifest, ElectionManifest }

/// A contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contest {
    /// The 1-based index of this [`Contest`] in the order it is defined in the
    /// [`ElectionManifest`].
    #[serde(skip)]
    pub opt_contest_ix: Option<ContestIndex>,

    /// The label for this `Contest`.
    pub label: String,

    /// The maximum number of selections ("votes") that may be distributed over all the selectable
    /// options of a contest.
    ///
    /// If not specified, the default is `1`.
    #[serde(default, skip_serializing_if = "ContestSelectionLimit::is_default")]
    pub selection_limit: ContestSelectionLimit,

    /// The contest options, e.g. "candidates".
    /// The order and quantity of contest options matches the contest's definition in the
    /// [`ElectionManifest`].
    #[serde(rename = "options")]
    pub contest_options: Vec1<ContestOption>,
}

impl Contest {
    /// Returns a ref to the [`ContestOption`] at index `ix`.
    pub fn get_contest_option(&self, ix: ContestOptionIndex) -> EgResult<&ContestOption> {
        self.contest_options
            .get(ix)
            .ok_or(EgError::ContestOptionIndexNotInContest(ix))
    }

    /// The number of data fields for the selectable options of this [`Contest`].
    pub fn num_selectable_option_data_fields(&self) -> usize {
        self.contest_options.len()
    }

    /// The number of (non-selectable) additional data fields used for this [`Contest`].
    pub fn num_additional_non_selectable_option_data_fields(&self) -> usize {
        //? TODO determine this once policy of recording (over|under)vote[ds], is fully defined.
        0
    }

    /// The total number of data fields used for this [`Contest`]. I.e., the total number of
    /// [`Ciphertexts`](crate::ciphertext::Ciphertext) recorded for this `Contest` on a
    /// [`Ballot`](crate::ballot::Ballot) of a [`BallotStyle`] containing it.
    ///
    /// This is simply the sum of `num_selectable_option_data_fields()` and
    /// `num_additional_non_selectable_option_data_fields()`.
    pub fn num_data_fields(&self) -> usize {
        self.num_selectable_option_data_fields()
            + self.num_additional_non_selectable_option_data_fields()
    }

    /// The effective selection limit for this [`Contest`].
    ///
    /// This is the smaller of this contest's selection limit and the sum of the selection limits of all
    /// this `Contest`'s options'.
    pub fn effective_contest_selection_limit(&self) -> EgResult<EffectiveContestSelectionLimit> {
        EffectiveContestSelectionLimit::figure(self)
    }

    /// The effective selection limits for every [`ContestOption`] of this [`Contest`].
    pub fn figure_options_effective_selection_limits(
        &self,
    ) -> EgResult<Vec1<EffectiveOptionSelectionLimit>> {
        let mut v = Vec::<EffectiveOptionSelectionLimit>::with_capacity(self.contest_options.len());
        for contest_option in self.contest_options.iter() {
            let esl = contest_option.effective_selection_limit(self)?;
            v.push(esl);
        }
        v.try_into().map_err(Into::into)
    }

    /// Informs the [`Contest`] of its [`ContestIndex`], and the [`ContestOption`](ContestOption)s of their
    /// indices.
    fn inform_contest_of_its_index_and_its_options_of_theirs(
        &mut self,
        contest_ix: ContestIndex,
    ) -> EgResult<()> {
        match self.opt_contest_ix {
            Option::Some(contests_contest_ix) => {
                if contests_contest_ix != contest_ix {
                    return Err(EgError::ContestIndexMismatch {
                        contest_ix,
                        contests_contest_ix,
                    });
                }
            }
            Option::None => {
                self.opt_contest_ix = Some(contest_ix);
            }
        }

        for (contest_option_ix, contest_option) in self.contest_options.enumerate_mut() {
            // Verify or set the [`ContestOption`]'s understanding of its containing `contest_ix`.
            match self.opt_contest_ix {
                Some(co_contest_ix) => {
                    if co_contest_ix != contest_ix {
                        return Err(EgError::OptionContestIndexMismatch {
                            actual_contest_ix: contest_ix,
                            contest_option_ix,
                            co_contest_ix,
                        });
                    }
                }
                None => {
                    self.opt_contest_ix = Some(contest_ix);
                }
            }

            // Verify or set the [`ContestOption`]'s understanding of its own `contest_option_ix`.
            match contest_option.opt_contest_option_ix {
                Some(co_contest_option_ix) => {
                    if co_contest_option_ix != contest_option_ix {
                        return Err(EgError::ContestOptionIndexMismatch {
                            contest_ix,
                            actual_contest_option_ix: contest_option_ix,
                            co_contest_option_ix,
                        });
                    }
                }
                None => {
                    contest_option.opt_contest_option_ix = Some(contest_option_ix);
                }
            }
        }
        Ok(())
    }
}

impl HasIndexType for Contest {
    type IndexTypeParam = Contest;
}

/// A 1-based index of a [`Contest`] in the order it is defined in the [`ElectionManifest`].
pub type ContestIndex = Index<Contest>;

/// An option in a [`Contest`].
///
/// This refers to selectable options, and not to any additional data fields.
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestOption {
    /// The 1-based index of the [`Contest`] to which this contest option belongs.
    #[serde(skip)]
    pub opt_contest_ix: Option<ContestIndex>,

    /// The 1-based index of this [`ContestOption`] within its [`Contest`].
    #[serde(skip)]
    pub opt_contest_option_ix: Option<ContestOptionIndex>,

    /// The label for this [`ContestOption`].
    pub label: String,

    /// The maximum number of selections ("votes") that a voter may apply to this contest option.
    ///
    /// If not specified, the default is `1`.
    #[serde(default, skip_serializing_if = "OptionSelectionLimit::is_default")]
    pub selection_limit: OptionSelectionLimit,
}

impl ContestOption {
    /// The effective selection limit for this contest option.
    /// This is the smaller of this options's selection limit and the contest's
    /// selection limit.
    pub fn effective_selection_limit(
        &self,
        containing_contest: &Contest,
    ) -> EgResult<EffectiveOptionSelectionLimit> {
        // If we happen to know the contest index of this option and the contest index of the containing
        // contest passed-in, verify they are the same.
        if let (Some(contestoption_contest_ix), Some(containing_contest_ix)) =
            (self.opt_contest_ix, containing_contest.opt_contest_ix)
        {
            if contestoption_contest_ix != containing_contest_ix {
                return Err(match self.opt_contest_option_ix {
                    Option::Some(contest_option_ix) => {
                        EgError::ContestOptionActuallyInDifferentContest {
                            contest_option_ix,
                            containing_contest_ix,
                            contestoption_contest_ix,
                        }
                    }
                    Option::None => EgError::ContestOptionActuallyInDifferentContest2 {
                        containing_contest_ix,
                        contestoption_contest_ix,
                    },
                });
            }
        }

        EffectiveOptionSelectionLimit::figure(containing_contest, self)
    }
}

impl HasIndexType for ContestOption {
    type IndexTypeParam = Ciphertext;
}

/// A 1-based index of a [`ContestOption`] in the order it is defined within its
/// [`Contest`], in the order it is defined in the [`ElectionManifest`].
///
/// Same type as [`CiphertextIndex`], [`ContestOptionFieldPlaintextIndex`](crate::contest_option_fields::ContestOptionFieldPlaintextIndex), [`ContestDataFieldIndex`](crate::contest_data_fields_plaintexts::ContestDataFieldIndex), etc.
pub type ContestOptionIndex = CiphertextIndex;

// Unit tests for the election manifest.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod t {
    use std::io::Cursor;

    use super::*;
    use crate::{
        loadable::LoadableFromStdIoReadValidated,
        resource_id::ElectionDataObjectId,
        serializable::{SerializableCanonical, SerializablePretty},
    };

    #[test]
    fn t1() {
        let election_manifest_ridfmt =
            ElectionDataObjectId::ElectionParameters.validated_type_ridfmt();

        let eg = &Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::election_manifest::test::test_election_manifest",
        );

        // Pretty
        {
            let json_pretty = {
                let mut buf = Cursor::new(vec![0u8; 0]);
                eg.produce_resource_downcast_no_src::<ElectionManifest>(&election_manifest_ridfmt)
                    .unwrap()
                    .to_stdiowrite_pretty(&mut buf)
                    .unwrap();
                buf.into_inner()
            };
            assert!(json_pretty.len() > 6);
            assert_eq!(*json_pretty.last().unwrap(), b'\n');

            let election_manifest_from_json_pretty = ElectionManifest::from_stdioread_validated(
                &mut Cursor::new(json_pretty.clone()),
                eg,
            )
            .unwrap();

            let json_pretty_2 = {
                let mut buf = Cursor::new(vec![0u8; 0]);
                election_manifest_from_json_pretty
                    .to_stdiowrite_pretty(&mut buf)
                    .unwrap();
                buf.into_inner()
            };

            assert_eq!(json_pretty, json_pretty_2);
            assert_eq!(
                *eg.election_manifest().unwrap(),
                election_manifest_from_json_pretty
            );
        }

        // Canonical
        {
            let canonical_bytes = eg
                .election_manifest()
                .unwrap()
                .to_canonical_bytes()
                .unwrap();
            assert!(canonical_bytes.len() > 5);
            assert_ne!(canonical_bytes[canonical_bytes.len() - 1], b'\n');
            assert_ne!(canonical_bytes[canonical_bytes.len() - 1], 0x00);

            let election_manifest_from_canonical_bytes =
                ElectionManifest::from_stdioread_validated(&mut Cursor::new(canonical_bytes), eg)
                    .unwrap();

            assert_eq!(
                *eg.election_manifest().unwrap(),
                election_manifest_from_canonical_bytes
            );
        }
    }
}
