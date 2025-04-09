// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides implementation of guardian public keys. For more details see
//! Section `3.2` of the Electionguard specification `2.1.0`.

use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

use util::vec1::HasIndexType;

/// Same type as [`GuardianSecretKeyIndex`].
pub use crate::guardian::GuardianIndex;
use crate::{
    guardian::{AsymmetricKeyPart, GuardianKeyPartId},
    guardian_coeff_proof::CoefficientsProof,
    guardian_public_key_trait::GuardianKeyInfoTrait,
    guardian_secret_key::CoefficientCommitments,
    resource::{ElectionDataObjectId, Resource, ResourceFormat, ResourceIdFormat},
    resource::{ProduceResource, ProduceResourceExt},
    serializable::SerializableCanonical,
};

/// Info for constructing a [`GuardianPublicKey`] through validation.
///
#[derive(Clone, Debug, serde::Serialize)]
pub struct GuardianPublicKeyInfo {
    /// Identifies the guardian index number, the key purpose, and the
    /// asymmetric key part (i.e., [`Public`](crate::guardian::AsymmetricKeyPart::Public).
    pub key_id: GuardianKeyPartId,

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    ///
    /// Optional, may be blank.
    pub name: String,

    /// Published polynomial coefficient commitments.
    ///
    /// EGDS 2.1.0 bottom of pg. 21 "K_{i,j}"
    pub coefficient_commitments: CoefficientCommitments,

    /// Proof of knowledge of a specific [`GuardianSecretKey`], and
    /// commitment to a specific public communication key.
    ///
    /// EGDS 2.1.0 bottom of pg. 23.
    ///
    /// May not have been generated yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opt_coefficients_proof: Option<Arc<CoefficientsProof>>,

    /// Refers to this object as a [`Resource`].
    ridfmt: ResourceIdFormat,
}

impl GuardianKeyInfoTrait for GuardianPublicKeyInfo {
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

crate::impl_knows_friendly_type_name! { GuardianPublicKeyInfo }

impl Resource for GuardianPublicKeyInfo {
    fn ridfmt(&self) -> &ResourceIdFormat {
        #[cfg(debug_assertions)]
        {
            let key_id_expected = GuardianKeyPartId {
                asymmetric_key_part: AsymmetricKeyPart::Public,
                ..self.key_id
            };
            let edoid_expected = ElectionDataObjectId::GuardianKeyPart(key_id_expected);
            let ridfmt_expected = edoid_expected.info_type_ridfmt();
            debug_assert_eq!(self.ridfmt, ridfmt_expected);
        }
        &self.ridfmt
    }
}

impl SerializableCanonical for GuardianPublicKeyInfo {}

impl<'de> Deserialize<'de> for GuardianPublicKeyInfo {
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
            i,
            name,
            purpose,
            coefficient_commitments,
            coefficients_proof,
        }

        struct GuardianPublicKeyInfoVisitor;

        impl<'de> Visitor<'de> for GuardianPublicKeyInfoVisitor {
            type Value = GuardianPublicKeyInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("GuardianPublicKeyInfo")
            }

            fn visit_map<MapAcc>(
                self,
                mut map: MapAcc,
            ) -> Result<GuardianPublicKeyInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let Some((Field::i, i)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field("i"));
                };

                let (name, next_entry): (String, _) = match map.next_key()? {
                    Some(Field::name) => (map.next_value()?, map.next_entry()?),
                    Some(key) => (String::new(), Some((key, map.next_value()?))),
                    None => (String::new(), None),
                };

                let Some((Field::purpose, key_purpose)) = next_entry else {
                    return Err(MapAcc::Error::missing_field("purpose"));
                };

                let Some((Field::coefficient_commitments, coefficient_commitments)) =
                    map.next_entry()?
                else {
                    return Err(MapAcc::Error::missing_field(
                        Field::coefficient_commitments.into(),
                    ));
                };

                let opt_coefficients_proof: Option<Arc<CoefficientsProof>> = match map.next_key()? {
                    Some(Field::coefficients_proof) => Some(Arc::new(map.next_value()?)),
                    Some(field) => {
                        return Err(MapAcc::Error::unknown_field(field.into(), &[]));
                    }
                    None => None,
                };

                let key_id = GuardianKeyPartId {
                    guardian_ix: i,
                    key_purpose,
                    asymmetric_key_part: AsymmetricKeyPart::Public,
                };
                let edoid = ElectionDataObjectId::GuardianKeyPart(key_id);
                let ridfmt = edoid.info_type_ridfmt();

                Ok(GuardianPublicKeyInfo {
                    key_id,
                    name,
                    coefficient_commitments,
                    opt_coefficients_proof,
                    ridfmt,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("GuardianPublicKey", FIELDS, GuardianPublicKeyInfoVisitor)
    }
}

crate::impl_validatable_validated! {
    src: GuardianPublicKeyInfo, produce_resource => EgResult<GuardianPublicKey> {
        // Validate the info common to public and secret keys.
        src.validate_public_key_info_to_election_parameters(produce_resource).await?;

        let GuardianPublicKeyInfo {
            key_id,
            name,
            coefficient_commitments,
            opt_coefficients_proof,
            ridfmt,
        } = src;

        //? TODO leverage some common code for GuardianSecretKey and GuardianPublicKey? See GuardianPublicKeyTrait::validate_public_key_info_to_election_parameters

        // Validate the key_id
        let keyid_expected = GuardianKeyPartId {
            guardian_ix: key_id.guardian_ix,
            key_purpose: key_id.key_purpose,
            asymmetric_key_part: AsymmetricKeyPart::Public,
        };

        //? TODO validate the name

        //? TODO validate/verify the coefficient_commitments

        //? TODO validate/verify the opt_coefficients_proof

        let edoid_expected = ElectionDataObjectId::GuardianKeyPart(keyid_expected);
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
            ridfmt: ElectionDataObjectId::GuardianKeyPart(key_id).validated_type_ridfmt(),
        };

        Ok(self_)
    }
}

impl From<GuardianPublicKey> for GuardianPublicKeyInfo {
    fn from(src: GuardianPublicKey) -> Self {
        let GuardianPublicKey {
            key_id,
            name,
            coefficient_commitments,
            opt_coefficients_proof,
            ridfmt: _,
        } = src;

        Self {
            key_id,
            name,
            coefficient_commitments,
            opt_coefficients_proof,
            ridfmt: ElectionDataObjectId::GuardianKeyPart(key_id).info_type_ridfmt(),
        }
    }
}

/// The public key for a guardian.
///
/// See Section `3.2.2` for details on the generation of public keys.
#[derive(Clone, Debug, Serialize)]
pub struct GuardianPublicKey {
    /// Identifies the guardian index number, the key purpose, and the
    /// asymmetric key part (i.e., [`Public`](crate::guardian::AsymmetricKeyPart::Public).
    pub(crate) key_id: GuardianKeyPartId,

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    ///
    /// Optional, may be blank.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) name: String,

    pub(crate) coefficient_commitments: CoefficientCommitments,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) opt_coefficients_proof: Option<Arc<CoefficientsProof>>,

    /// Refers to this object as a [`Resource`].
    #[serde(skip_serializing)]
    pub(crate) ridfmt: ResourceIdFormat,
}

impl HasIndexType for GuardianPublicKey {
    type IndexTypeParam = crate::guardian::GuardianIndexTag;
}

impl GuardianKeyInfoTrait for GuardianPublicKey {
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

impl SerializableCanonical for GuardianPublicKey {}

crate::impl_knows_friendly_type_name! { GuardianPublicKey }

impl Resource for GuardianPublicKey {
    fn ridfmt(&self) -> &ResourceIdFormat {
        #[cfg(debug_assertions)]
        {
            let key_id_expected = GuardianKeyPartId {
                asymmetric_key_part: AsymmetricKeyPart::Public,
                ..self.key_id
            };
            let edoid_expected = ElectionDataObjectId::GuardianKeyPart(key_id_expected);
            let ridfmt_expected = edoid_expected.validated_type_ridfmt();
            if self.ridfmt != ridfmt_expected {
                error!(
                    "GuardianPublicKey::ridfmt - self.ridfmt: {:#?}",
                    self.ridfmt
                );
                error!("GuardianPublicKey::ridfmt - ridfmt_expected: {ridfmt_expected:#?}");
                assert_eq!(self.ridfmt, ridfmt_expected);
            }
        }
        &self.ridfmt
    }
}

static_assertions::assert_impl_all!(GuardianPublicKeyInfo: crate::validatable::Validatable);
static_assertions::assert_impl_all!(GuardianPublicKey: crate::validatable::Validated);

//=================================================================================================|

/*
#[allow(non_upper_case_globals)]
const RID_GuardianPublicKey: ResourceId = ResourceId::ElectionDataObject(EdoId::GuardianPublicKey);

#[allow(non_upper_case_globals)]
const RIDFMT_GuardianPublicKey_ValidatedEdo: ResourceIdFormat = ResourceIdFormat {
    rid: RID_GuardianPublicKey,
    fmt: ResourceFormat::ValidElectionDataObject,
};

#[allow(non_snake_case)]
fn maybe_produce_GuardianPublicKey_ValidatedEdo(rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
    Some(produce_GuardianPublicKey_ValidatedEdo(rp_op))
}

#[allow(non_snake_case)]
fn produce_GuardianPublicKey_ValidatedEdo(rp_op: &Arc<RpOp>) -> ResourceProductionResult {
    rp_op.check_ridfmt(&RIDFMT_GuardianPublicKey_ValidatedEdo)?;

    let key_id_expected = GuardianKeyPartId {
        asymmetric_key_part: AsymmetricKeyPart::Public,
        ..self.key_id
    };
    let ResourceId::ElectionDataObject(edo_id) = rp_op.target_rid() else {
        let ridfmt_expected =
        let e = ResourceProductionError::UnexpectedResourceIdFormatRequested {
            ridfmt_expected: ResourceIdFormat,
            ridfmt_requested: ResourceIdFormat,
            };
        error!(rf = trace_field_rf, "{e:?}");
        Err(e)?;
bail!();
    }

    #[allow(non_upper_case_globals)]
    const RID_GuardianSecretKey: ResourceId = ResourceId::ElectionDataObject(EdoId::GuardianSecretKey());

        const RIDFMT_GuardianSecretKey_ValidatedEdo: ResourceIdFormat = ResourceIdFormat {
        rid: RID_GuardianSecretKey,
        fmt: ResourceFormat::ValidElectionDataObject,
    };
        let extended_base_hash = async_global_executor::block_on(
        GuardianPublicKey::compute(rp_op.as_ref())
        self.produce_resource_budget_downcast::<T>(ridfmt, None)
    )?;

    let arc: Arc<dyn Resource> = Arc::new(extended_base_hash);

    let rpsrc = ResourceSource::Valid(ValidReason::Inherent);
    Ok((arc, rpsrc))
}

//=================================================================================================|

fn gather_rpspecific_registrations(register_fn: &mut dyn FnMut(RPFnRegistration)) {
    register_fn(RPFnRegistration::new_defaultproducer(
        RIDFMT_GuardianPublicKey_ValidatedEdo,
        Box::new(maybe_produce_GuardianPublicKey_ValidatedEdo),
    ));
}

inventory::submit! {
    GatherRPFnRegistrationsFnWrapper(gather_rpspecific_registrations)
}
    // */

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use crate::{
        eg::Eg,
        errors::EgResult,
        guardian::GuardianKeyPurpose,
        guardian_public_key_trait::GuardianKeyInfoTrait,
        guardian_secret_key::GuardianSecretKey,
        resource::{ProduceResourceExt, Resource},
    };

    #[test_log::test]
    fn test_key_generation() {
        async_global_executor::block_on(test_key_generation_async());
    }

    async fn test_key_generation_async() {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::guardian_public_key::test_key_generation",
        );
        let eg = eg.as_ref();

        let election_parameters = eg.election_parameters().await.unwrap();
        let election_parameters = election_parameters.as_ref();
        let fixed_parameters = election_parameters.fixed_parameters();
        let group = fixed_parameters.group();
        let field = fixed_parameters.field();
        let varying_parameters = election_parameters.varying_parameters();

        let k = varying_parameters.k().as_quantity();

        let mut guardians_secret_keys = vec![];
        for guardian_ix in varying_parameters.each_guardian_ix() {
            let gsk_votes = GuardianSecretKey::generate(
                eg,
                guardian_ix,
                format!("Guardian {guardian_ix}"),
                GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
            )
            .await
            .unwrap();
            guardians_secret_keys.push(gsk_votes);
        }

        let guardian_public_keys = guardians_secret_keys
            .iter()
            .map(|sk| sk.make_public_key())
            .collect::<Vec<_>>();

        for guardian_secret_key in guardians_secret_keys.iter() {
            // This is useful because it does an internal check of `ridfmt`.
            let _ = guardian_secret_key.ridfmt();

            assert_eq!(guardian_secret_key.secret_coefficients().0.len(), k);
            assert_eq!(guardian_secret_key.coefficient_commitments().0.len(), k);

            for secret_coefficient in guardian_secret_key.secret_coefficients().0.iter() {
                assert!(&secret_coefficient.0.is_valid(field));
            }

            for coefficient_commitment in guardian_secret_key.coefficient_commitments().0.iter() {
                assert!(&coefficient_commitment.0.is_valid(group));
            }
        }

        for (i, guardian_public_key) in guardian_public_keys.iter().enumerate() {
            // This is useful because it does an internal check of `ridfmt`.
            let _ = guardian_public_key.ridfmt();

            assert_eq!(guardian_public_key.coefficient_commitments.0.len(), k);

            for (j, coefficient_commitment) in guardian_public_key
                .coefficient_commitments
                .0
                .iter()
                .enumerate()
            {
                assert_eq!(
                    &coefficient_commitment.0,
                    &guardians_secret_keys[i].coefficient_commitments().0[j].0
                );
            }

            assert_eq!(
                guardian_public_key.public_key_k_i_0().unwrap(),
                &guardian_public_key.coefficient_commitments().0[0].0
            );
        }
    }
}
