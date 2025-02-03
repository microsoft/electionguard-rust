// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    ballot_style::BallotStyleIndex,
    contest_option_fields::ContestOptionFieldsPlaintexts,
    eg::Eg,
    election_manifest::{ContestIndex, ContestOptionIndex},
    errors::{EgError, EgResult},
    extended_base_hash::ExtendedBaseHash_H_E,
    serializable::SerializableCanonical,
    validatable::Validated,
};

cfg_if::cfg_if! { if #[cfg(feature = "eg-allow-test-data-generation")] {
    use crate::{
        contest_option_fields::ContestOptionFieldPlaintext,
        election_manifest::Contest,

    };
    use util::{csrng::Csrng, vec1::Vec1};
} }

/// Info for constructing a [`VoterSelectionsPlaintextInfo`] through validation.
///
#[derive(Clone, Debug, Serialize)]
pub struct VoterSelectionsPlaintextInfo {
    pub h_e: ExtendedBaseHash_H_E,
    pub ballot_style_ix: BallotStyleIndex,
    pub contests_option_fields_plaintexts: BTreeMap<ContestIndex, ContestOptionFieldsPlaintexts>,
}

impl<'de> Deserialize<'de> for VoterSelectionsPlaintextInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use strum::{IntoStaticStr, VariantNames};

        #[derive(Deserialize, IntoStaticStr, VariantNames)]
        #[serde(field_identifier)]
        #[allow(non_camel_case_types)]
        enum Field {
            h_e,
            ballot_style_ix,
            contests_option_fields_plaintexts,
        }

        struct VoterSelectionsPlaintextInfoVisitor;

        impl<'de> Visitor<'de> for VoterSelectionsPlaintextInfoVisitor {
            type Value = VoterSelectionsPlaintextInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("VoterSelectionsPlaintextInfo")
            }

            fn visit_map<MapAcc>(
                self,
                mut map: MapAcc,
            ) -> Result<VoterSelectionsPlaintextInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let Some((Field::h_e, h_e)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field("h_e"));
                };

                let Some((Field::ballot_style_ix, ballot_style_ix)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field("ballot_style_ix"));
                };

                let Some((
                    Field::contests_option_fields_plaintexts,
                    contests_option_fields_plaintexts,
                )) = map.next_entry()?
                else {
                    return Err(MapAcc::Error::missing_field(
                        "contests_option_fields_plaintexts",
                    ));
                };

                Ok(VoterSelectionsPlaintextInfo {
                    h_e,
                    ballot_style_ix,
                    contests_option_fields_plaintexts,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct(
            "VoterSelectionsPlaintextInfo",
            FIELDS,
            VoterSelectionsPlaintextInfoVisitor,
        )
    }
}

crate::impl_knows_friendly_type_name! { VoterSelectionsPlaintextInfo }

crate::impl_MayBeResource_for_non_Resource! { VoterSelectionsPlaintextInfo }

crate::impl_validatable_validated! {
    src: VoterSelectionsPlaintextInfo, eg => EgResult<VoterSelectionsPlaintext> {
        let election_h_e = eg.extended_base_hash()?.h_e().clone();

        let election_manifest = eg.election_manifest()?;
        let election_manifest = election_manifest.as_ref();

        let VoterSelectionsPlaintextInfo {
            h_e: voterselections_h_e,
            ballot_style_ix,
            contests_option_fields_plaintexts,
        } = src;

        //----- Verify `h_e`.

        if voterselections_h_e != election_h_e {
            return Err(EgError::VoterSelectionsPlaintextDoesNotMatchExpected {
                voterselections_h_e,
                election_h_e,
            });
        }

        //----- Verify `ballot_style_ix`

        let ballot_style = election_manifest.get_ballot_style_validate_ix(ballot_style_ix)?;

        //----- Verify `contests_option_fields_plaintexts`.

        // For each [`Contest`] for which selections were provided
        for (&contest_ix, contest_option_fields_plaintexts) in &contests_option_fields_plaintexts {
            // Verify the ElectionManifest and BallotStyle contain the Contest for which voter selections were provided.
            let contest = ballot_style.get_contest(election_manifest, contest_ix)
                .map_err(|e| match e {
                        EgError::ContestNotInBallotStyle { contest_ix, ballot_style_label, .. } =>
                                EgError::VoterSelectionsPlaintextSuppliesSelectionsForContestNotInBallotStyle {
                                    contest_ix,
                                    ballot_style_label,
                                    opt_ballot_style_ix: Some(ballot_style_ix),
                                },
                        EgError::ContestNotInManifest(contest_ix) =>
                                EgError::VoterSelectionsPlaintextSuppliesSelectionsForContestNotInElectionManifest {
                                        contest_ix,
                                        opt_ballot_style_ix: Some(ballot_style_ix),
                                },
                        _ => e,
                    })?;

            // Check that the number of contest option field plaintexts matches the number of contest options.
            // We do not enforce selection limits here.
            if contest_option_fields_plaintexts.len() != contest.contest_options.len() {
                Err(EgError::VoterSelectionsPlaintextSuppliesWrongNumberOfOptionSelectionsForContest {
                    ballot_style_ix, contest_ix,
                    num_options_defined: contest.contest_options.len(),
                    num_options_supplied: contest_option_fields_plaintexts.len()
                })?;
            }
        }

        //----- Construct the object from the validated data.

        Ok(VoterSelectionsPlaintext {
            h_e: voterselections_h_e,
            ballot_style_ix,
            contests_option_fields_plaintexts,
        })
    }
}

impl From<VoterSelectionsPlaintext> for VoterSelectionsPlaintextInfo {
    fn from(src: VoterSelectionsPlaintext) -> Self {
        let VoterSelectionsPlaintext {
            h_e,
            ballot_style_ix,
            contests_option_fields_plaintexts,
        } = src;

        Self {
            h_e,
            ballot_style_ix,
            contests_option_fields_plaintexts,
        }
    }
}

/// Plaintext voter selections for a specific ballot style.
///
/// This is specifically *not* a [`Ballot`](crate::ballot::Ballot), this is the input data format to the [ElectionGuard](crate)
/// encryption which produces an [ElectionGuard `Ballot`](crate::ballot::Ballot).
///
/// For privacy, this structure specifically does not include device or date-time information.
///
#[derive(Debug)]
pub struct VoterSelectionsPlaintext {
    h_e: ExtendedBaseHash_H_E,
    ballot_style_ix: BallotStyleIndex,
    contests_option_fields_plaintexts: BTreeMap<ContestIndex, ContestOptionFieldsPlaintexts>,
}

impl VoterSelectionsPlaintext {
    /// The [extended base hash, `H_E`](crate::extended_base_hash::ExtendedBaseHash_HValue),
    /// checked to ensure the data is applied to the correct election.
    pub fn h_e(&self) -> &ExtendedBaseHash_H_E {
        &self.h_e
    }

    /// The 1-based index of the [`BallotStyle`] within the [`ElectionManifest`](crate::election_manifest::ElectionManifest).
    pub fn ballot_style_ix(&self) -> BallotStyleIndex {
        self.ballot_style_ix
    }

    /// Plaintext contest option field values reflecting voter selections.
    /// These field values are not guaranteed to comply with effective selection limits.
    /// Additional data fields may be present after the voter-selectable options.
    pub fn contests_option_fields_plaintexts(
        &self,
    ) -> &BTreeMap<ContestIndex, ContestOptionFieldsPlaintexts> {
        &self.contests_option_fields_plaintexts
    }

    /// Constructs a new [`VoterSelectionsPlaintext`] from random contest selections.
    #[cfg(feature = "eg-allow-test-data-generation")]
    pub fn new_generate_random_selections(
        eg: &Eg,
        ballot_style_ix: BallotStyleIndex,
    ) -> EgResult<Self> {
        let h_e = eg.extended_base_hash()?.h_e().clone();

        let election_manifest = eg.election_manifest()?;
        let election_manifest = election_manifest.as_ref();

        let ballot_style = election_manifest.get_ballot_style_validate_ix(ballot_style_ix)?;

        let mut contests_option_fields_plaintexts = BTreeMap::new();
        for &contest_ix in ballot_style.contests().iter() {
            let contest = ballot_style.get_contest(election_manifest, contest_ix)?;
            let contest_selections_pts = Self::random_contest_selections(contest, eg.csrng())?;

            contests_option_fields_plaintexts.insert(contest_ix, contest_selections_pts);
        }

        let voter_selections_plaintext = VoterSelectionsPlaintextInfo {
            h_e,
            ballot_style_ix,
            contests_option_fields_plaintexts,
        };

        VoterSelectionsPlaintext::try_validate_from(voter_selections_plaintext, eg)
    }

    #[cfg(feature = "eg-allow-test-data-generation")]
    #[allow(clippy::unwrap_used)] // test code
    fn random_contest_selections(
        contest: &Contest,
        csrng: &dyn Csrng,
    ) -> EgResult<ContestOptionFieldsPlaintexts> {
        let contest_options = &contest.contest_options;
        if contest_options.is_empty() {
            return Ok(Vec1::<ContestOptionFieldPlaintext>::new().into());
        }

        let effective_contest_selection_limit: u32 =
            contest.effective_contest_selection_limit()?.into();

        let cnt_contest_options = contest_options.len();

        let mut contest_option_fields_plaintexts =
            Vec1::<ContestOptionFieldPlaintext>::with_capacity(cnt_contest_options);
        for _ in 0..cnt_contest_options {
            contest_option_fields_plaintexts.try_push(ContestOptionFieldPlaintext::zero())?;
        }

        // 20%: no selection,
        // 10%: apply fewer than selection limit (undervote),
        // 70%: exactly the selection limit.
        //? TODO overvote?

        let mut selections_remaining = match csrng.next_u32_range(0, 100).unwrap() {
            0..20 => 0,
            20..30 => match effective_contest_selection_limit {
                0..=1 => 0,
                2 => 1,
                _ => csrng
                    .next_u32_range(1, effective_contest_selection_limit)
                    .unwrap(),
            },
            _ => effective_contest_selection_limit,
        };

        // This is a not-very-fancy way of randomly distributing selections over selectable options.
        // It's not likely to be representative of real-world voter behavior, but it ought to
        // exercise all the cases given enough iterations.

        let effective_option_selection_limits =
            contest.figure_options_effective_selection_limits()?;

        let mut options_with_selections_remaining: Vec<ContestOptionIndex> =
            effective_option_selection_limits
                .enumerate()
                .filter_map(|(ix, &eosl)| (u32::from(eosl) != 0).then_some(ix))
                .collect();

        let mut iters = 0_usize;
        while selections_remaining != 0 && !options_with_selections_remaining.is_empty() {
            // Pick a random selectable option and remove it from the list.
            let (option_ix, eosl) = {
                let remaining_ix0 = csrng
                    .next_usize_range(0, options_with_selections_remaining.len())
                    .unwrap();
                let option_ix = options_with_selections_remaining.remove(remaining_ix0);

                // Unwrap() is justified here because the collection was created from contest_options,
                // option_ix was selected from contest_options, and the size hasn't changed.
                #[allow(clippy::unwrap_used)]
                let eosl = u32::from(*effective_option_selection_limits.get(option_ix).unwrap());

                (option_ix, eosl)
            };

            // Get the current value of the option.
            // Unwrap() is justified here because option_ix was selected from contest_options.
            #[allow(clippy::unwrap_used)]
            let mut_ref_option_field_pt =
                contest_option_fields_plaintexts.get_mut(option_ix).unwrap();

            let current_val = u32::from(*mut_ref_option_field_pt);

            // Assert is justified here because this is test data generation.
            assert!(current_val < eosl);
            let option_selections_remaining = eosl - current_val;

            // Add a random quantity of selections to the option.
            let max_to_add = option_selections_remaining.min(selections_remaining);

            // Unwrap() is justified here because we just checked `selections_remaining != 0` and `current_val < eosl`.
            let qty_to_add = csrng.next_u32_rangeinclusive(1, max_to_add).unwrap();
            let new_val = current_val + qty_to_add;
            selections_remaining -= qty_to_add;

            *mut_ref_option_field_pt = ContestOptionFieldPlaintext::try_new(new_val)?;

            // If the option has not yet reached its selection limit, put it back in the list.
            if new_val < eosl {
                options_with_selections_remaining.push(option_ix);
            }

            iters += 1;
            if iters > 10_000 * cnt_contest_options {
                // Probabalistically, this ought to never happen with typical values of selection
                // limits. But even if it did, the result would still be a validly-random set of
                // voter selections.
                debug_assert!(false, "Improbable loop count in random_contest_selections");
                break;
            }
        }

        Ok(contest_option_fields_plaintexts.into())
    }
}

crate::impl_knows_friendly_type_name! { VoterSelectionsPlaintext }

crate::impl_MayBeResource_for_non_Resource! { VoterSelectionsPlaintext } //? TODO crate::impl_Resource_for_simple_ElectionDataObjectId_type! { TodoTheEdoType, TodoTheEdoId }

impl serde::Serialize for VoterSelectionsPlaintext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("h_e", &self.h_e)?;
        map.serialize_entry("ballot_style", &self.ballot_style_ix)?;
        map.serialize_entry("contests", &VSPContestSerialized(self))?;
        map.end()
    }
}

struct VSPContestSerialized<'a>(&'a VoterSelectionsPlaintext);
impl serde::Serialize for VSPContestSerialized<'_> {
    fn serialize<S>(&'_ self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeSeq;
        let map_ci_cofp = &self.0.contests_option_fields_plaintexts;
        let mut seq = serializer.serialize_seq(Some(map_ci_cofp.len()))?;
        for (&ci, cofp) in map_ci_cofp {
            seq.serialize_element(&VSPContestSerializedContest(ci, cofp))?;
        }
        seq.end()
    }
}

struct VSPContestSerializedContest<'a>(ContestIndex, &'a ContestOptionFieldsPlaintexts);
impl serde::Serialize for VSPContestSerializedContest<'_> {
    fn serialize<S>(&'_ self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("contest", &self.0)?;
        map.serialize_entry("selections", &self.1)?;
        map.end()
    }
}

impl SerializableCanonical for VoterSelectionsPlaintext {}
