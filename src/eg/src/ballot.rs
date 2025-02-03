// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::DerefMut,
};

use serde::{Deserialize, Serialize};
use util::algebra::FieldElement;

use crate::{
    ballot_style::{BallotStyle, BallotStyleIndex},
    chaining_mode::ChainingField,
    contest_data_fields_ciphertexts::ContestDataFieldsCiphertexts,
    contest_data_fields_plaintexts::ContestDataFieldsPlaintexts,
    eg::Eg,
    election_manifest::ContestIndex,
    errors::{EgError, EgResult},
    fixed_parameters::FixedParameters,
    hash::{eg_h, HValue, SpecificHValue},
    pre_voting_data::PreVotingData,
    serializable::SerializableCanonical,
    validatable::Validated,
    voter_selections_plaintext::{VoterSelectionsPlaintext, VoterSelectionsPlaintextInfo},
};

//=================================================================================================|

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BallotState {
    /// Voter selections are completed and present in encrypted form.
    /// The ballot has not yet been cast, challenged, or spoiled.
    VoterSelectionsEncrypted,

    /// Voter selections are completed and present in encrypted form.
    /// The ballot has been cast.
    /// Selections MUST be considered to express voter intent, so
    /// the ballot MUST NOT be decrypted.
    /// Selections MUST be included in the tally.
    /// This is a final state.
    Cast,

    /// Voter selections are completed and present in encrypted form.
    /// The ballot has been spoiled, it will NOT be cast.
    /// Selections MUST be considered as potentially expressing voter intent, so
    /// the ballot MUST NOT be decrypted.
    /// However, selections MUST NOT be included in the tally.
    /// This is a final state.
    Spoiled,

    /// Voter selections are completed and present in encrypted form.
    /// The ballot has been challenged, it will never been cast.
    /// Selections MUST NOT be interpreted as an expression of voter intent.
    /// The ballot SHOULD be decrypted for verification.
    /// Selections MUST NOT be included in the tally.
    Challenged,

    /// A challenged ballot in which voter selections have been decrypted.
    /// Voter selections are present in both encrypted and plaintext form.
    /// Selections MUST NOT be interpreted as an expression of voter intent.
    /// Selections MUST NOT be included in the tally.
    /// The challenged and decrypted ballot SHOULD be published.
    /// This is a final state.
    ChallengedDecrypted,
}

//-------------------------------------------------------------------------------------------------|

/// [`SpecificHValue`] tag type for EGDS 2.1.0 sec 3.3.2 pg 29 "selection encryption identifier hash" `H_I`.
#[allow(non_camel_case_types)]
pub enum HValue_H_I_tag {}

/// [`SpecificHValue`] type for EGDS 2.1.0 sec 3.3.2 pg 29 "selection encryption identifier hash" `H_I`.
#[allow(non_camel_case_types)]
pub type HValue_H_I = SpecificHValue<HValue_H_I_tag>;

//=================================================================================================|

/// [`SpecificHValue`] tag type for EGDS 2.1.0 sec 3.3.3 pg 29 "ballot nonce" `ξ_B`.
#[allow(non_camel_case_types)]
pub enum BallotNonce_xi_B_tag {}

/// [`SpecificHValue`] type for EGDS 2.1.0 sec 3.3.3 pg 29 "ballot nonce" `ξ_B`.
#[allow(non_camel_case_types)]
pub type BallotNonce_xi_B = SpecificHValue<BallotNonce_xi_B_tag>;

//=================================================================================================|

/// Ballot hash or "confirmation code".
///
/// EGDS 2.1.0 sec 3.4.2 pg 42 eq. 71:
///
///    H_C = H(H_I; 0x29, χ1, χ2, ..., χ_{m_B}, B_C)
///
#[allow(non_snake_case)]
pub fn compute_confirmation_code<'a, I>(
    contests_fields_ciphertexts: I,
    chaining_field_B_C: &ChainingField,
    h_i: &HValue_H_I,
) -> HValue
where
    I: Iterator<Item = &'a ContestDataFieldsCiphertexts> + ExactSizeIterator,
{
    let expected_len = 37 + contests_fields_ciphertexts.len() * 32; // EGDS 2.1.0 pg. 76 (71)

    let mut v = Vec::with_capacity(expected_len);
    v.push(0x29);

    for item in contests_fields_ciphertexts {
        v.extend_from_slice(item.contest_hash.as_ref());
    }

    v.extend(chaining_field_B_C.as_array());

    assert_eq!(v.len(), expected_len);

    eg_h(h_i, v)
}

//=================================================================================================|

#[derive(Debug, Clone, Serialize)]
pub struct BallotInfo {
    /// The 1-based index of the [`BallotStyle`] within the [`ElectionManifest`](crate::election_manifest::ElectionManifest).
    pub ballot_style_ix: BallotStyleIndex,

    /// The state of ballot.
    pub ballot_state: BallotState,

    /// EGDS 2.1.0 sec 3.3.2 describes a "Selection encryption identifier" `id_B`
    /// as 256 uniform random bits which is publicly released with the selection
    /// encryptions of the ballot.
    ///
    /// For convenience, we'll use an `HValue` type for this.
    pub id_b: HValue,

    /// EGDS 2.1.0 sec 3.3.2 "selection identifier hash" `H_I`
    pub h_i: HValue_H_I,

    /// Encrypted data fields for [`Contest`](crate::election_manifest::Contest)s reflecting voter selections and
    /// possibly additional contest data fields.
    pub contests_data_fields_ciphertexts: BTreeMap<ContestIndex, ContestDataFieldsCiphertexts>,

    /// Confirmation code.
    pub confirmation_code: HValue,

    //#[serde(default, skip_serializing_if = "String::is_empty")]
    /// Identifier of device that encrypted the voter selections to produce a ballot.
    /// Optional, can be empty.
    pub device_id: String,

    //#[serde(default, skip_serializing_if = "String::is_empty")]
    /// The device may apply an identifier to the ballot. Optional, can be empty.
    pub ballot_id: String,

    //#[serde(default, skip_serializing_if = "String::is_empty")]
    /// Date and time of ballot encryption.
    /// Optional, can be empty.
    /// Consider using [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339#section-5.8),
    /// AKA "ISO 8601" format for this.
    pub encryption_datetime: String,
}

impl<'de> Deserialize<'de> for BallotInfo {
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
            ballot_style,
            ballot_state,
            id_b,
            h_i,
            contests_data_fields_ciphertexts,
            confirmation_code,
            device_id,
            ballot_id,
            encryption_datetime,
        }

        struct BallotInfoVisitor;

        impl<'de> Visitor<'de> for BallotInfoVisitor {
            type Value = BallotInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("BallotInfo")
            }

            fn visit_map<V>(self, mut map: V) -> Result<BallotInfo, V::Error>
            where
                V: MapAccess<'de>,
            {
                let Some((Field::ballot_style, ballot_style_ix)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::ballot_style.into()));
                };

                let Some((Field::ballot_state, ballot_state)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::ballot_state.into()));
                };

                let Some((Field::id_b, id_b)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::id_b.into()));
                };

                let Some((Field::h_i, h_i)) = map.next_entry::<_, HValue>()? else {
                    return Err(V::Error::missing_field(Field::h_i.into()));
                };
                let h_i = HValue_H_I::from(h_i);

                let Some((
                    Field::contests_data_fields_ciphertexts,
                    contests_data_fields_ciphertexts,
                )) = map.next_entry()?
                else {
                    return Err(V::Error::missing_field(
                        Field::contests_data_fields_ciphertexts.into(),
                    ));
                };

                let Some((Field::confirmation_code, confirmation_code)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::confirmation_code.into()));
                };

                let Some((Field::device_id, device_id)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::device_id.into()));
                };

                let Some((Field::ballot_id, ballot_id)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::ballot_id.into()));
                };

                let Some((Field::encryption_datetime, encryption_datetime)) = map.next_entry()?
                else {
                    return Err(V::Error::missing_field(Field::encryption_datetime.into()));
                };

                Ok(BallotInfo {
                    ballot_style_ix,
                    ballot_state,
                    id_b,
                    h_i,
                    contests_data_fields_ciphertexts,
                    confirmation_code,
                    device_id,
                    ballot_id,
                    encryption_datetime,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("Ballot", FIELDS, BallotInfoVisitor)
    }
}

crate::impl_knows_friendly_type_name! { BallotInfo }

crate::impl_MayBeResource_for_non_Resource! { BallotInfo } //? TODO impl Resource

impl SerializableCanonical for BallotInfo {}

crate::impl_validatable_validated! {
    src: BallotInfo, eg => EgResult<Ballot> {
        let election_manifest = eg.election_manifest()?;
        let election_manifest = election_manifest.as_ref();

        let BallotInfo {
            ballot_style_ix,
            ballot_state,
            id_b,
            h_i,
            contests_data_fields_ciphertexts,
            confirmation_code,
            device_id,
            ballot_id,
            encryption_datetime,
        } = src;

        //----- Validate `ballot_style_ix`.

        // Calling `ElectionManifest::get_ballot_style_validate_ix()` validates that the election_manifest contains a
        // `BallotStyle` at `ballot_style_ix`. It does some other validation as well, see
        // `BallotStyle::get_validated_ballot_style_ix()` for details.
        let ballot_style = election_manifest.get_ballot_style_validate_ix(ballot_style_ix)?;

        //----- Validate `ballot_state`.

        //? TODO what additionally can we validate about this field?

        //----- Validate `id_b`.

        //? TODO what additionally can we validate about this field?

        //----- Validate `h_i`.

        //? TODO what additionally can we validate about this field?

        //----- Validate `contests_data_fields_ciphertexts`.

        // Verify that every contest in the ballot style:
        // - is present in this ballot's data fields ciphertexts.
        for &contest_ix in ballot_style.contests() {
            if !contests_data_fields_ciphertexts.contains_key(&contest_ix) {
                return Err(EgError::BallotMissingDataFieldsForContestInBallotStyle {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        // Also, invoke the common verification function for the ciphertexts.
        Ballot::validate_contests_data_fields_ciphertexts_to_ballot_style(
            eg,
            ballot_style,
            &contests_data_fields_ciphertexts,
            Some(ballot_style_ix) )?;

        //? TODO what additionally can we validate about this field?

        //----- Validate `confirmation_code`.

        //? TODO what additionally can we validate about this field?

        //----- Validate `device_id`.

        //? TODO what additionally can we validate about this field?

        //----- Validate `ballot_id`.

        //? TODO what additionally can we validate about this field?

        //----- Validate `encryption_datetime`.

        //? TODO what additionally can we validate about this field?

        //? TODO validate `confirmation_code`

        //? TODO validate `device_id`

        //? TODO validate `ballot_id`

        //? TODO validate `encryption_datetime`

        //----- Construct and return the object from the validated data.

        Ok(Ballot {
            ballot_style_ix,
            ballot_state,
            id_b,
            h_i,
            contests_data_fields_ciphertexts,
            confirmation_code,
            device_id,
            ballot_id,
            encryption_datetime,
        })
    }
}

impl From<Ballot> for BallotInfo {
    /// Convert from Ballot back to a BallotInfo for re-validation.
    fn from(src: Ballot) -> Self {
        let Ballot {
            ballot_style_ix,
            ballot_state,
            id_b,
            h_i,
            contests_data_fields_ciphertexts,
            confirmation_code,
            device_id,
            ballot_id,
            encryption_datetime,
        } = src;

        BallotInfo {
            ballot_style_ix,
            ballot_state,
            id_b,
            h_i,
            contests_data_fields_ciphertexts,
            confirmation_code,
            device_id,
            ballot_id,
            encryption_datetime,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Ballot {
    //? TODO should we include h_e here?
    ballot_style_ix: BallotStyleIndex,
    ballot_state: BallotState,
    id_b: HValue,
    h_i: HValue_H_I,
    contests_data_fields_ciphertexts: BTreeMap<ContestIndex, ContestDataFieldsCiphertexts>,
    confirmation_code: HValue,
    device_id: String,
    ballot_id: String,
    encryption_datetime: String,
}

impl Ballot {
    /// The 1-based index of the [`BallotStyle`] within the [`ElectionManifest`](crate::election_manifest::ElectionManifest).
    pub fn ballot_style_ix(&self) -> BallotStyleIndex {
        self.ballot_style_ix
    }

    /// The state of ballot.
    pub fn ballot_state(&self) -> &BallotState {
        &self.ballot_state
    }

    /// EGDS 2.1.0 sec 3.3.2 describes a
    /// "Selection encryption identifier" `id_B` as 256 uniform random bits.
    /// Publicly released with the selection encryptions of the ballot.
    /// For convenience, we'll use `HValue` for this.
    pub fn id_b(&self) -> &HValue {
        &self.id_b
    }

    /// EGDS 2.1.0 sec 3.3.2 "selection identifier hash" `H_I`
    pub fn h_i(&self) -> &HValue_H_I {
        &self.h_i
    }

    /// Encrypted data fields for [`Contest`](crate::election_manifest::Contest)s reflecting voter selections and
    /// possibly additional contest data fields.
    pub fn contests_data_fields_ciphertexts(
        &self,
    ) -> &BTreeMap<ContestIndex, ContestDataFieldsCiphertexts> {
        &self.contests_data_fields_ciphertexts
    }

    /// Confirmation code.
    pub fn confirmation_code(&self) -> &HValue {
        &self.confirmation_code
    }

    /// Identifier of device that encrypted the voter selections to produce a ballot.
    /// Optional, can be empty.
    pub fn device_id(&self) -> &String {
        &self.device_id
    }

    /// The device may apply an identifier to the ballot. Optional, can be empty.
    pub fn ballot_id(&self) -> &String {
        &self.ballot_id
    }

    /// Date and time of ballot encryption.
    /// Optional, can be empty.
    /// Consider using [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339#section-5.8),
    /// AKA "ISO 8601" format for this.
    pub fn encryption_datetime(&self) -> &String {
        &self.encryption_datetime
    }

    /// Create a new [`Ballot`] from a [`VoterSelectionsPlaintext`].
    ///
    /// All ElectionGuard 2.1 [`Ballot`]s are created encrypted.
    ///
    /// - `eg` - [`Eg`] context
    /// - `voter_selections_plaintext` - The [voter selections](VoterSelectionsPlaintext).
    ///   Also identifies the [`BallotStyleIndex`].
    /// - `chaining_field_B_C` - The [`ChainingField`] byte array `B_C`.
    /// - `opt_ballot_nonce_xi_B` - Optional [`BallotNonce_xi_B`].
    ///   If `None`, a random nonce will be generated.
    ///
    /// If a nonce is not provided, a random nonce will be generated.
    #[allow(non_snake_case)]
    pub fn try_new(
        eg: &Eg,
        voter_selections_plaintext: VoterSelectionsPlaintext,
        chaining_field_B_C: &ChainingField,
        opt_ballot_nonce_xi_B: Option<BallotNonce_xi_B>,
    ) -> EgResult<Ballot> {
        let extended_base_hash = eg.extended_base_hash()?;
        let extended_base_hash = extended_base_hash.as_ref();
        let election_h_e = extended_base_hash.h_e();

        let VoterSelectionsPlaintextInfo {
            h_e: voterselections_h_e,
            ballot_style_ix,
            contests_option_fields_plaintexts,
        } = voter_selections_plaintext.into();

        // Check the h_e from the VSP with that from PVD.
        if &voterselections_h_e != election_h_e {
            return Err(EgError::VoterSelectionsPlaintextDoesNotMatchExpected {
                voterselections_h_e,
                election_h_e: election_h_e.clone(),
            });
        }
        let h_e = voterselections_h_e;

        // Generate a random ballot nonce `xi_B` if one is not provided.
        let ballot_nonce_xi_B =
            opt_ballot_nonce_xi_B.unwrap_or_else(|| BallotNonce_xi_B::generate_random(eg.csrng()));

        // Convert the plaintext contest option fields to plaintext contest data fields.
        let mut contests_data_fields_plaintexts: BTreeMap<
            ContestIndex,
            ContestDataFieldsPlaintexts,
        > = BTreeMap::new();
        for (contest_ix, contest_option_fields_plaintexts) in contests_option_fields_plaintexts {
            let specific_contest_data_fields_plaintexts =
                ContestDataFieldsPlaintexts::try_from_option_fields(
                    eg,
                    contest_ix,
                    contest_option_fields_plaintexts,
                )?;
            contests_data_fields_plaintexts
                .insert(contest_ix, specific_contest_data_fields_plaintexts);
        }

        // Figure the selection encryption identifier `id_b` and selection identifier hash `h_i`

        let id_b = HValue::generate_random(eg.csrng());

        let h_i = {
            let mut v = vec![0x20];
            v.extend_from_slice(id_b.as_ref());

            let expected_len = 33; // EGDS 2.1.0 pg. 75 (32)
            assert_eq!(v.len(), expected_len);

            HValue_H_I::compute_from_eg_h(&h_e, &v)
        };

        // Encrypt the plaintext contest data fields to make the contest data fields ciphertexts.
        let mut contests_data_fields_ciphertexts: BTreeMap<
            ContestIndex,
            ContestDataFieldsCiphertexts,
        > = BTreeMap::new();

        for (contest_ix, contest_data_fields_plaintexts) in contests_data_fields_plaintexts {
            let contest_data_fields_ciphertexts = {
                ContestDataFieldsCiphertexts::from_contest_data_fields_plaintexts(
                    eg,
                    &h_i,
                    &ballot_nonce_xi_B,
                    contest_ix,
                    contest_data_fields_plaintexts,
                )?
            };

            contests_data_fields_ciphertexts.insert(contest_ix, contest_data_fields_ciphertexts);
        }

        let ballot_state = BallotState::VoterSelectionsEncrypted;

        let confirmation_code = compute_confirmation_code(
            contests_data_fields_ciphertexts.values(),
            chaining_field_B_C,
            &h_i,
        );

        //? TODO Make these function election_parameters
        let device_id = "".to_owned();
        let ballot_id = "".to_owned();
        let encryption_datetime = "".to_owned();

        let ballot_info = BallotInfo {
            ballot_style_ix,
            ballot_state,
            id_b,
            h_i,
            contests_data_fields_ciphertexts,
            confirmation_code,
            device_id,
            ballot_id,
            encryption_datetime,
        };

        Ballot::try_validate_from(ballot_info, eg)
    }

    //? TODO consider moving to [`BallotStyle`]
    //
    /// Verify a set of [`ContestDataFieldsCiphertexts`]s.
    ///
    /// Typically these would be from one [`Ballot`], but really what they have in
    /// common is their [`BallotStyle`].
    ///
    /// It verifies that:
    ///
    /// - [`ContestDataFieldsCiphertexts`] are supplied for every contest on the `BallotStyle`,
    /// - every `ContestIndex` belongs to the `BallotStyle`, and that
    /// - all of the `ContestDataFieldsCiphertexts` proofs are correct.
    ///
    /// Supplying the `opt_ballot_style_ix` allows additional checks.
    ///
    pub fn validate_contests_data_fields_ciphertexts_to_ballot_style(
        eg: &Eg,
        ballot_style: &BallotStyle,
        contests_data_fields_ciphertexts: &BTreeMap<ContestIndex, ContestDataFieldsCiphertexts>,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    ) -> EgResult<()> {
        let election_manifest = eg.election_manifest()?;
        let election_manifest = election_manifest.as_ref();

        // Validates that the `BallotStyle` knows its `BallotStyleIndex`.
        // See `BallotStyle::get_validated_ballot_style_ix()` for details.
        let ballot_style_ix = ballot_style
            .get_validated_ballot_style_ix(opt_ballot_style_ix, Some(election_manifest))?;

        // Verify that every contest in the BallotStyle
        // - is present in this ballot's data fields ciphertexts.
        for &contest_ix in ballot_style.contests() {
            if !contests_data_fields_ciphertexts.contains_key(&contest_ix) {
                return Err(EgError::BallotMissingDataFieldsForContestInBallotStyle {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        // Verify that every contest for which data fields ciphertexts are supplied
        // is present in the ballot style.
        for &contest_ix in contests_data_fields_ciphertexts.keys() {
            if !ballot_style.contests().contains(&contest_ix) {
                return Err(EgError::BallotClaimsContestNonExistentInBallotStyle {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        // Verify the proofs for all data fields for every contest for which
        // data fields ciphertexts are supplied.
        let mut verified_contests = BTreeSet::<ContestIndex>::new();
        for (&contest_ix, contest_fields_ciphertexts) in contests_data_fields_ciphertexts.iter() {
            contest_fields_ciphertexts.verify_proofs_for_all_data_fields_in_contest(eg)?;

            verified_contests.insert(contest_ix);
        }

        // Verify that we verified all contests in the ballot style.
        for &contest_ix in ballot_style.contests() {
            if !verified_contests.contains(&contest_ix) {
                return Err(EgError::BallotContestNotVerified {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        // Verify that all contests we verified are in the ballot style.
        for &contest_ix in verified_contests.iter() {
            if !ballot_style.contests().contains(&contest_ix) {
                return Err(EgError::BallotContestVerifiedNotInBallotStyle {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        Ok(())
    }

    //? TODO move to `BallotScaled`
    /// Scale the contest option values of a [`Ballot`] by a factor, producing a [`BallotScaled`](crate::ballot_scaled::BallotScaled).
    /// Each encrypted vote in the ballot gets scaled by the same factor.
    pub fn scale(
        &self,
        fixed_parameters: &FixedParameters,
        factor: &FieldElement,
    ) -> crate::ballot_scaled::BallotScaled {
        //? TODO move to `ballot_scaled.rs`
        let contests = self
            .contests_data_fields_ciphertexts
            .iter()
            .map(|(idx, ballot)| (*idx, ballot.scale(fixed_parameters, factor)))
            .collect();
        crate::ballot_scaled::BallotScaled { contests }
    }
}

crate::impl_knows_friendly_type_name! { Ballot }

crate::impl_MayBeResource_for_non_Resource! { Ballot } //? TODO impl Resource

impl SerializableCanonical for Ballot {}
