// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides implementation of guardian secret keys. For more details see Section `3.2`
//! of the Electionguard specification `2.1.0`. [TODO check ref]
//!
//! EGDS 2.1.0 Sec 3.2.1 pg. 22:
//! ## "Because a guardian only uses its secret shares zi and ˆzi of the joint secret keys for decryption,
//!    the actual guardian secret keys si and ˆsi are not needed any more and may be discarded once all
//!    shares have been successfully generated."

use std::{borrow::Cow, sync::Arc};

use either::Either;
use serde::{Deserialize, Serialize};
use strum::IntoStaticStr;
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

use util::{csrng::Csrng, vec1::HasIndexType};

/// Same type as [`GuardianPublicKeyIndex`].
pub use crate::guardian::GuardianIndex;
use crate::{
    algebra::{FieldElement, GroupElement, ScalarField},
    eg::Eg,
    election_parameters::{self, ElectionParameters},
    errors::{EgError, EgResult},
    fixed_parameters::{FixedParameters, FixedParametersTrait, FixedParametersTraitExt},
    guardian::GuardianKeyPartId,
    guardian_coeff_proof::CoefficientsProof,
    guardian_public_key::GuardianPublicKey,
    guardian_public_key_trait::GuardianKeyInfoTrait,
    key::{AsymmetricKeyPart, KeyPurpose},
    resource::{
        ElectionDataObjectId, ProduceResource, ProduceResourceExt, Resource, ResourceFormat,
        ResourceIdFormat,
    },
    secret_coefficient::SecretCoefficient,
    secret_coefficients::{SecretCoefficients, SecretCoefficientsInfo, SecretCoefficientsTrait},
    serializable::SerializableCanonical,
    validatable::{Validatable, Validated},
};

/// A commitment to a single [`SecretCoefficient`].
///
/// This corresponds to the `K_{i,j}` in Equation `10`. [TODO fix ref]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoefficientCommitment(pub GroupElement);

impl CoefficientCommitment {
    /// Returns the [`CoefficientCommitment`] as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_left_pad(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        let group = fixed_parameters.group();
        self.0.to_be_bytes_left_pad(group)
    }
}

/// A vector of [`CoefficientCommitment`]s, defining the guardians public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoefficientCommitments(pub Vec<CoefficientCommitment>);

impl CoefficientCommitments {
    /// Returns the number of [`CoefficientCommitments`]s.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Provides access to the coefficient commitments as [`&[CoefficientCommitment]`](std::slice).
    pub fn as_slice(&self) -> &[CoefficientCommitment] {
        self.0.as_slice()
    }

    /// Provides [`Iterator`] access to the [`CoefficientCommitment`]s.
    pub fn iter(&self) -> impl Iterator<Item = &CoefficientCommitment> {
        self.0.iter()
    }
}

impl From<Vec<CoefficientCommitment>> for CoefficientCommitments {
    fn from(v: Vec<CoefficientCommitment>) -> Self {
        CoefficientCommitments(v)
    }
}

/// Info for constructing a [`GuardianSecretKey`] through validation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct GuardianSecretKeyInfo {
    /// Identifies the guardian index number, the key purpose, and the
    /// asymmetric key part (i.e., [`Secret`](crate::guardian::AsymmetricKeyPart::Secret).
    pub key_id: GuardianKeyPartId,

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    ///
    /// Optional, may be blank.
    pub name: String,

    /// "Published" polynomial coefficient commitments.
    pub coefficient_commitments: CoefficientCommitments,

    /// Proof of knowledge of a specific [`GuardianSecretKey`], and
    /// commitment to a specific public communication key.
    ///
    /// EGDS 2.1.0 bottom of pg. 23.
    ///
    /// May not have been generated yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opt_coefficients_proof: Option<Arc<CoefficientsProof>>,

    /// Secret polynomial coefficients.
    pub secret_coefficients: Either<SecretCoefficientsInfo, SecretCoefficients>,

    /// Refers to this object as a [`Resource`].
    ridfmt: ResourceIdFormat,
}

impl GuardianKeyInfoTrait for GuardianSecretKeyInfo {
    fn guardian_key_id(&self) -> &GuardianKeyPartId {
        &self.key_id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn coefficient_commitments(&self) -> &CoefficientCommitments {
        &self.coefficient_commitments
    }

    fn opt_coefficients_proof(&self) -> &Option<Arc<CoefficientsProof>> {
        &self.opt_coefficients_proof
    }
}

impl<'de> Deserialize<'de> for GuardianSecretKeyInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use strum::VariantNames;

        #[derive(Deserialize, IntoStaticStr, VariantNames)]
        #[serde(field_identifier)]
        #[allow(non_camel_case_types)]
        enum Field {
            i,
            name,
            purpose,
            coefficient_commitments,
            coefficients_proof,
            secret_coefficients,
        }

        struct GuardianSecretKeyInfoVisitor;

        impl<'de> Visitor<'de> for GuardianSecretKeyInfoVisitor {
            type Value = GuardianSecretKeyInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("GuardianSecretKeyInfo")
            }

            fn visit_map<MapAcc>(
                self,
                mut map: MapAcc,
            ) -> Result<GuardianSecretKeyInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let Some((Field::i, i)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field(Field::i.into()));
                };

                let (name, next_entry): (String, _) = match map.next_key()? {
                    Some(Field::name) => (map.next_value()?, map.next_entry()?),
                    Some(key) => (String::new(), Some((key, map.next_value()?))),
                    None => (String::new(), None),
                };

                let Some((Field::purpose, purpose)) = next_entry else {
                    return Err(MapAcc::Error::missing_field(Field::purpose.into()));
                };

                let Some((Field::coefficient_commitments, coefficient_commitments)) =
                    map.next_entry()?
                else {
                    return Err(MapAcc::Error::missing_field(
                        Field::coefficient_commitments.into(),
                    ));
                };

                let (opt_coefficients_proof, next_entry): (Option<Arc<CoefficientsProof>>, _) =
                    match map.next_key()? {
                        Some(Field::coefficients_proof) => {
                            (Some(Arc::new(map.next_value()?)), map.next_entry()?)
                        }
                        Some(key) => (None, Some((key, map.next_value()?))),
                        None => (None, None),
                    };

                let Some((Field::secret_coefficients, secret_coefficients_info)) = next_entry
                else {
                    return Err(MapAcc::Error::missing_field(
                        Field::secret_coefficients.into(),
                    ));
                };

                let key_id = GuardianKeyPartId {
                    guardian_ix: i,
                    key_purpose: purpose,
                    asymmetric_key_part: AsymmetricKeyPart::Secret,
                };

                let edoid = ElectionDataObjectId::GuardianKeyPart(key_id);
                let ridfmt = edoid.info_type_ridfmt();

                Ok(GuardianSecretKeyInfo {
                    key_id,
                    name,
                    coefficient_commitments,
                    opt_coefficients_proof,
                    secret_coefficients: Either::Left(secret_coefficients_info),
                    ridfmt,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("GuardianSecretKey", FIELDS, GuardianSecretKeyInfoVisitor)
    }
}

impl SerializableCanonical for GuardianSecretKeyInfo {}

crate::impl_knows_friendly_type_name! { GuardianSecretKeyInfo }

impl Resource for GuardianSecretKeyInfo {
    fn ridfmt(&self) -> Cow<'_, ResourceIdFormat> {
        #[cfg(debug_assertions)]
        {
            let key_id_expected = GuardianKeyPartId {
                asymmetric_key_part: AsymmetricKeyPart::Secret,
                ..self.key_id
            };
            let edoid_expected = ElectionDataObjectId::GuardianKeyPart(key_id_expected);
            let ridfmt_expected = edoid_expected.info_type_ridfmt();
            debug_assert_eq!(self.ridfmt, ridfmt_expected);
        }
        Cow::Borrowed(&self.ridfmt)
    }
}

crate::impl_validatable_validated! {
    src: GuardianSecretKeyInfo, produce_resource => EgResult<GuardianSecretKey> {
        // Validate the info common to public and secret keys.
        src.validate_public_key_info_to_election_parameters(produce_resource).await?;

        let GuardianSecretKeyInfo {
            key_id,
            name,
            coefficient_commitments,
            opt_coefficients_proof,
            secret_coefficients: either_secret_coefficients,
            ridfmt,
        } = src;

        //? TODO leverage some common code for GuardianSecretKey and GuardianPublicKey? See GuardianPublicKeyTrait::validate_public_key_info_to_election_parameters

        //----- Validate `key_id`.

        let key_id_expected = GuardianKeyPartId {
                guardian_ix: key_id.guardian_ix,
                key_purpose: key_id.key_purpose,
                asymmetric_key_part: AsymmetricKeyPart::Secret,
            };

        if key_id != key_id_expected {
            let s = format!("Expecting: `{key_id_expected}`, got: `{key_id}`"); //? TODO proper error type
            return Err(EgValidateError::Other(s))?;
        }

        //----- Validate `name`.

        //? TODO: validate `name`

        //----- Validate `coefficient_commitments`.

        //? TODO: validate `coefficient_commitments`

        //----- Validate `opt_coefficients_proof`.

        //? TODO: validate `opt_coefficients_proof`

        //----- Validate `secret_coefficients`.

        let secret_coefficients: SecretCoefficients = match either_secret_coefficients {
            Either::Left(secret_coefficients_info) => {
                SecretCoefficients::try_validate_from(secret_coefficients_info, produce_resource)?
            }
            Either::Right(secret_coefficients) => secret_coefficients,
        };

        let edoid_expected = ElectionDataObjectId::GuardianKeyPart(key_id_expected);
        let ridfmt_expected = edoid_expected.info_type_ridfmt();

        if ridfmt != ridfmt_expected {
            let s = format!("Expecting: `{ridfmt_expected}`, got: `{ridfmt}`");
            return Err(EgValidateError::Other(s))?;
        }

        //----- Construct the validated ElectionDataObject.

        let self_ = Self {
            key_id,
            name,
            coefficient_commitments,
            opt_coefficients_proof,
            secret_coefficients,
            ridfmt: ElectionDataObjectId::GuardianKeyPart(key_id).validated_type_ridfmt(),
        };

        Ok(self_)
    }
}

impl From<GuardianSecretKey> for GuardianSecretKeyInfo {
    fn from(src: GuardianSecretKey) -> Self {
        let GuardianSecretKey {
            key_id,
            name,
            coefficient_commitments,
            opt_coefficients_proof,
            secret_coefficients,
            ridfmt: _,
        } = src;

        let secret_coefficients_info = SecretCoefficientsInfo::from(secret_coefficients);

        Self {
            key_id,
            name,
            coefficient_commitments,
            opt_coefficients_proof,
            secret_coefficients: Either::Left(secret_coefficients_info),
            ridfmt: ElectionDataObjectId::GuardianKeyPart(key_id).info_type_ridfmt(),
        }
    }
}

/// The secret key for a guardian.
///
/// See Section `3.2.2` for details on the generation of secret keys.
#[derive(Clone, Debug, Serialize)]
pub struct GuardianSecretKey {
    /// Identifies the guardian index number, the key purpose, and the
    /// asymmetric key part (i.e., [`Secret`](crate::guardian::AsymmetricKeyPart::Secret).
    key_id: GuardianKeyPartId,

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    ///
    /// Optional, may be blank.
    name: String,

    /// "Published" polynomial coefficient commitments.
    ///
    /// EGDS 2.1.0 bottom of pg. 21 "K_{i,j}".
    coefficient_commitments: CoefficientCommitments,

    /// Proof of knowledge of a specific [`GuardianSecretKey`], and
    /// commitment to a specific public communication key.
    ///
    /// EGDS 2.1.0 bottom of pg. 23.
    ///
    /// May not have been generated yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    opt_coefficients_proof: Option<Arc<CoefficientsProof>>,

    /// Secret polynomial coefficients.
    ///
    /// EGDS 2.1.0 bottom of pg. 21 "a_{i, j} such 0 < j < k".
    secret_coefficients: SecretCoefficients,

    /// Refers to this object as a [`Resource`].
    #[serde(skip_serializing)]
    ridfmt: ResourceIdFormat,
}

impl HasIndexType for GuardianSecretKey {
    type IndexTypeParam = crate::guardian::GuardianIndexTag;
}

impl GuardianKeyInfoTrait for GuardianSecretKey {
    fn guardian_key_id(&self) -> &GuardianKeyPartId {
        &self.key_id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn coefficient_commitments(&self) -> &CoefficientCommitments {
        &self.coefficient_commitments
    }

    fn opt_coefficients_proof(&self) -> &Option<Arc<CoefficientsProof>> {
        &self.opt_coefficients_proof
    }
}

impl GuardianSecretKey {
    /// Generates a [`GuardianSecretKey`] for guardian `i`.
    ///
    /// It does not include the [`CoefficientsProof`], as that cannot be generated until
    /// after the [`public communication key`](ElGamalPublicKey) is known.
    ///
    /// The arguments are
    /// - `produce_resource` - common resource data provider
    /// - `guardian_ix` - the guardian's 1-based index
    /// - `name` - Short name with which to refer to the guardian. Should not have any line breaks. Optional, may be blank.
    /// - `key_purpose` - purpose of the key.
    pub async fn generate(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        guardian_ix: GuardianIndex,
        name: String,
        key_purpose: KeyPurpose,
    ) -> EgResult<Arc<Self>> {
        let election_parameters = produce_resource.election_parameters().await?;
        let election_parameters = election_parameters.as_ref();
        let fixed_parameters = election_parameters.fixed_parameters();
        let k = election_parameters.k();
        let group = fixed_parameters.group();

        let key_id = GuardianKeyPartId {
            guardian_ix,
            key_purpose,
            asymmetric_key_part: AsymmetricKeyPart::Secret,
        };

        let secret_coefficients = SecretCoefficients::generate(produce_resource).await?;
        if secret_coefficients.len() != k.as_quantity() {
            let e = EgError::SecretCoefficientsIncorrectQuantity {
                qty_expected: k.as_quantity(),
                qty_found: secret_coefficients.len(),
            };
            trace!("{e}");
            return Err(e);
        }

        let coefficient_commitments: CoefficientCommitments = secret_coefficients
            .iter()
            .map(|secret_coefficient| {
                CoefficientCommitment(group.g_exp(secret_coefficient.as_ref()))
            })
            .collect::<Vec<_>>()
            .into();
        if coefficient_commitments.len() != k.as_quantity() {
            let e = EgError::CoefficientCommitmentsIncorrectQuantity {
                qty_expected: k.as_quantity(),
                qty_found: coefficient_commitments.len(),
            };
            trace!("{e}");
            return Err(e);
        }

        let opt_coefficients_proof = None;

        let gsk_info = GuardianSecretKeyInfo {
            key_id,
            name,
            coefficient_commitments,
            opt_coefficients_proof,
            secret_coefficients: Either::Right(secret_coefficients),
            ridfmt: ElectionDataObjectId::GuardianKeyPart(key_id).info_type_ridfmt(),
        };

        let gsk = GuardianSecretKey::try_validate_from(gsk_info, produce_resource)?;

        Ok(Arc::new(gsk))
    }

    /// Returns the [`SecretCoefficients`] of the [`GuardianSecretKey`].
    pub fn secret_coefficients(&self) -> &SecretCoefficients {
        &self.secret_coefficients
    }

    /// Returns the actual secret key of the [`GuardianSecretKey`].
    ///
    /// The returned value corresponds to `a_{i,0}` as defined in Section `3.2.2`.
    pub fn secret_s(&self) -> &FieldElement {
        self.secret_coefficients.as_slice()[0].as_ref()
    }

    /// Computes the [`GuardianPublicKey`] corresponding to the [`GuardianSecretKey`].
    pub fn make_public_key(&self) -> GuardianPublicKey {
        let Self {
            key_id,
            name,
            coefficient_commitments,
            opt_coefficients_proof,
            secret_coefficients: _,
            ridfmt: _,
        } = self.clone();

        let GuardianKeyPartId {
            guardian_ix,
            key_purpose,
            asymmetric_key_part,
        } = key_id;
        debug_assert_eq!(asymmetric_key_part, AsymmetricKeyPart::Secret);

        let key_id = GuardianKeyPartId {
            guardian_ix,
            key_purpose,
            asymmetric_key_part: AsymmetricKeyPart::Public,
        };

        GuardianPublicKey {
            key_id,
            name,
            coefficient_commitments,
            opt_coefficients_proof,
            ridfmt: ElectionDataObjectId::GuardianKeyPart(key_id).validated_type_ridfmt(),
        }
    }
}

impl SerializableCanonical for GuardianSecretKey {}

crate::impl_knows_friendly_type_name! { GuardianSecretKey }

impl Resource for GuardianSecretKey {
    fn ridfmt(&self) -> Cow<'_, ResourceIdFormat> {
        #[cfg(debug_assertions)]
        {
            let key_id_expected = GuardianKeyPartId {
                asymmetric_key_part: AsymmetricKeyPart::Secret,
                ..self.key_id
            };
            let edoid_expected = ElectionDataObjectId::GuardianKeyPart(key_id_expected);
            let ridfmt_expected = edoid_expected.validated_type_ridfmt();
            debug_assert_eq!(self.ridfmt, ridfmt_expected);
        }
        Cow::Borrowed(&self.ridfmt)
    }
}

static_assertions::assert_impl_all!(GuardianSecretKeyInfo: crate::validatable::Validatable);
static_assertions::assert_impl_all!(GuardianSecretKey: crate::validatable::Validated);
