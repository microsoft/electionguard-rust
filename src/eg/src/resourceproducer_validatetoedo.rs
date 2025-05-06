// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::{
    any::{Any, TypeId},
    borrow::Cow,
    sync::Arc,
};

use serde::Serialize;
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

//
use util::abbreviation::Abbreviation;

use crate::{
    eg::Eg,
    errors::EgError,
    guardian::GuardianKeyPartId,
    key::{AsymmetricKeyPart, KeyPurpose},
    loadable::KnowsFriendlyTypeName,
    resource::{
        ElectionDataObjectId as EdoId, MayBeResource, ProduceResource, ProduceResourceExt,
        Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionError,
        ResourceProductionResult, ResourceSource,
    },
    resource_producer_registry::{
        FnNewResourceProducer, GatherResourceProducerRegistrationsFnWrapper,
        ResourceProducerCategory, ResourceProducerRegistration, ResourceProducerRegistry,
    },
    resource_production::RpOp,
    validatable::{Validatable, Validated},
};

//=================================================================================================|

/// A [`ResourceProducer`] that, when a persisted Edo is requested, attempts to load
/// its [`SliceBytes`] representation and validate it.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct ResourceProducer_ValidateToEdo;

impl ResourceProducer_ValidateToEdo {
    pub const NAME: &str = "ValidateToEdo";

    fn arc_new() -> Arc<dyn ResourceProducer_Any_Debug_Serialize + 'static> {
        let self_ = Self;
        Arc::new(self_)
    }
}

impl ResourceProducer for ResourceProducer_ValidateToEdo {
    fn name(&self) -> Cow<'static, str> {
        Self::NAME.into()
    }

    fn fn_rc_new(&self) -> FnNewResourceProducer {
        Self::arc_new
    }

    #[instrument(
        name = "RP_ValidateToEdo",
        level = "debug",
        fields(rf = trace_display(&rp_op.requested_ridfmt().abbreviation())),
        skip(self, rp_op),
        ret
    )]
    fn maybe_produce(&self, rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
        tracing::Span::current().record(
            "rid",
            tracing::field::display(rp_op.requested_rid().abbreviation()),
        );
        tracing::Span::current().record(
            "fmt",
            tracing::field::display(rp_op.requested_fmt().abbreviation()),
        );

        let produce_resource = rp_op.as_ref();

        let edo_id = match rp_op.requested_ridfmt().into_owned() {
            ResourceIdFormat {
                rid: ResourceId::ElectionDataObject(edo_id),
                fmt: ResourceFormat::ValidElectionDataObject,
            } => edo_id.clone(),
            _ => {
                // We only handle requests for a validated ElectionDataObject.
                return None;
            }
        };

        debug!("edo_id={edo_id:?}");

        //? TODO temp test code
        if edo_id == EdoId::ElectionManifest {
            warn!("rp_op={rp_op:?}");
        }

        // Try to obtain the resource in its not-yet-validated `Info` format.

        let ridfmt_validatable = ResourceIdFormat {
            rid: rp_op.requested_rid().into_owned(),
            fmt: ResourceFormat::ConcreteType,
        };

        debug!("ridfmt_validatable={ridfmt_validatable:?}");

        let resource_production_result =
            async_global_executor::block_on(rp_op.produce_resource(&ridfmt_validatable));

        match resource_production_result {
            Ok((arc_validatable, resource_source_validatable)) => {
                // We managed to produce the requested `Validatable` type.

                debug_assert_eq!(arc_validatable.ridfmt().as_ref(), &ridfmt_validatable);

                if arc_validatable.ridfmt().as_ref() == &ridfmt_validatable {
                    // Continue on to the next function to try to validate it to the type we need.
                    self.maybe_produce2_(
                        produce_resource,
                        rp_op,
                        &edo_id,
                        ridfmt_validatable,
                        arc_validatable,
                        resource_source_validatable,
                    )
                } else {
                    let e = ResourceProductionError::UnexpectedResourceIdFormatProduced {
                        requested: ridfmt_validatable.clone(),
                        produced: arc_validatable.ridfmt().into_owned(),
                    };
                    let e = ResourceProductionError::DependencyProductionError {
                        ridfmt_request: rp_op.requested_ridfmt().into_owned(),
                        dep_err: Box::new(e),
                    };
                    error!("{e:?}");
                    Some(Err(e))
                }
            }
            Err(ResourceProductionError::NoProducerFound { .. }) => None,
            Err(dep_err) => {
                let e = ResourceProductionError::DependencyProductionError {
                    ridfmt_request: rp_op.requested_ridfmt().into_owned(),
                    dep_err: Box::new(dep_err),
                };
                error!("{e:?}");
                Some(Err(e))
            }
        }
    }
}

impl ResourceProducer_ValidateToEdo {
    #[cfg(all(test, not(test)))] //? TODO would prefer something which didn't require generics
    fn maybe_produce2_(
        &self,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        rp_op: &Arc<RpOp>,
        edoid: &EdoId,
        ridfmt_validatable: ResourceIdFormat,
        arc_validatable: Arc<dyn Resource>,
        rsrc: ResourceSource,
    ) -> Option<ResourceProductionResult> {
        use crate::validatable::{MayBeValidatableUnsized, ValidatableUnsized};
        use downcast_rs::DowncastSync;

        let arc_dyn_any_send_sync = arc_validatable.into_any_arc();
        let ref_dyn_any_send_sync =
            AsRef::<dyn MayBeValidatableUnsized + Send + Sync>::as_ref(arc_dyn_any_send_sync);

        // TODO can only downcast to concrete type.
        match arc_dyn_any_send_sync.downcast::<dyn MayBeValidatableUnsized>() {
            Err(arc) => {
                let e = ResourceProductionError::CouldntDowncastResource {
                    src_ridfmt: ridfmt_validatable,
                    src_type: format!("{:?}", arc.type_id()),
                    target_type: format!("{:?}", TypeId::of::<dyn MayBeValidatableUnsized>()),
                };
                error!("{e:?}");
                Some(Err(e))
            }
            Ok(arc_dyn_maybevalidatableunsized) => {
                debug!("Successfully downcasted {}", arc_validatable.ridfmt());

                None //? TODO
            }
        }
    }

    #[cfg(any(test, not(test)))] //? TODO current working code
    fn maybe_produce2_(
        &self,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        rp_op: &Arc<RpOp>,
        edoid: &EdoId,
        ridfmt_validatable: ResourceIdFormat,
        arc_validatable: Arc<dyn Resource>,
        resource_source: ResourceSource,
    ) -> Option<ResourceProductionResult> {
        let arc_dyn_any_send_sync: Arc<dyn Any + Send + Sync> = arc_validatable.into_any_arc();

        #[rustfmt::skip]
        let result = match edoid {
            EdoId::FixedParameters => self.maybe_produce3_::<crate::fixed_parameters::FixedParameters>(produce_resource, ridfmt_validatable, arc_dyn_any_send_sync,  resource_source),
            EdoId::VaryingParameters => self.maybe_produce3_::<crate::varying_parameters::VaryingParameters>(produce_resource, ridfmt_validatable, arc_dyn_any_send_sync,  resource_source),
            EdoId::ElectionParameters => self.maybe_produce3_::<crate::election_parameters::ElectionParameters>(produce_resource, ridfmt_validatable, arc_dyn_any_send_sync,  resource_source),
            //? TODO EdoId::BallotStyle  => self.maybe_produce3_::<crate::ballot_style::BallotStyle>(eg, src_ridfmt, arc_dyn_any_send_sync, rsrc),
            //? TODO EdoId::VotingDeviceInformationSpec  => self.maybe_produce3_::<crate::voting_device::VotingDeviceInformationSpec>(eg, src_ridfmt, arc_dyn_any_send_sync, rsrc),
            EdoId::ElectionManifest => self.maybe_produce3_::<crate::election_manifest::ElectionManifest>(produce_resource, ridfmt_validatable, arc_dyn_any_send_sync,  resource_source),
            //? TODO EdoId::Hashes  => self.maybe_produce3_::<crate::hashes::Hashes>(eg, src_ridfmt, arc_dyn_any_send_sync, rsrc),
            EdoId::GuardianKeyPart(GuardianKeyPartId { asymmetric_key_part: AsymmetricKeyPart::Public, .. })  => self.maybe_produce3_::<crate::guardian_public_key::GuardianPublicKey>(produce_resource, ridfmt_validatable, arc_dyn_any_send_sync,  resource_source),
            EdoId::GuardianKeyPart(GuardianKeyPartId { asymmetric_key_part: AsymmetricKeyPart::Secret, .. })  => self.maybe_produce3_::<crate::guardian_secret_key::GuardianSecretKey>(produce_resource, ridfmt_validatable, arc_dyn_any_send_sync,  resource_source),
            //? TODO EdoId::JointPublicKey  => self.maybe_produce3_::<crate::joint_public_key::JointPublicKey>(eg, src_ridfmt, arc_dyn_any_send_sync, rsrc),
            //? TODO EdoId::ExtendedBaseHash  => self.maybe_produce3_::<crate::extended_base_hash::ExtendedBaseHash>(eg, src_ridfmt, arc_dyn_any_send_sync, rsrc),
            //? TODO EdoId::PreVotingData  => self.maybe_produce3_::<crate::pre_voting_data::PreVotingData>(eg, src_ridfmt, arc_dyn_any_send_sync, rsrc),
            #[cfg(feature = "eg-allow-test-data-generation")]
            //? TODO EdoId::GeneratedTestDataVoterSelections(_) => self.maybe_produce3_::<crate::voter_selections_plaintext::VoterSelectionsPlaintext>(eg, src_ridfmt, arc_dyn_any_send_sync, rsrc),
            EdoId::ElectionTallies  => self.maybe_produce3_::<crate::election_tallies::ElectionTallies>(produce_resource, ridfmt_validatable, arc_dyn_any_send_sync,  resource_source),
            _ => {
                return None;
            } //? TODO eventually this goes away?
        };
        Some(result)
    }

    fn maybe_produce3_<ValidatedInto>(
        &self,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        src_ridfmt: ResourceIdFormat,
        arc_dyn_any_send_sync: Arc<dyn Any + Send + Sync>,
        resource_source: ResourceSource,
    ) -> ResourceProductionResult
    where
        ValidatedInto: Validated + Resource + Sized + Send + Sync,
        <ValidatedInto as Validated>::ValidatedFrom: Resource + Clone + Sized + Send + Sync,
    {
        let src_typename = std::any::type_name_of_val(arc_dyn_any_send_sync.as_ref());
        let src_typeid = arc_dyn_any_send_sync.as_ref().type_id();

        //let valiated_into_typename = std::any::type_name::<ValidatedInto>();

        // Try to downcast to the ValidatedFrom type, then try validation. Keep the most code possible in non-generic functions.
        match arc_dyn_any_send_sync.downcast::<<ValidatedInto as Validated>::ValidatedFrom>() {
            Ok(arc_validated_from) => {
                let validate_result =
                    ValidatedInto::try_validate_from_arc(arc_validated_from, produce_resource);
                match validate_result {
                    Ok(validated_into) => self.maybe_produce4_validate_ok(
                        src_ridfmt,
                        resource_source,
                        Arc::new(validated_into),
                    ),
                    Err(e) => self.maybe_produce4_ok_validate_err(e),
                }
            }
            Err(arc_dyn_any) => {
                let valiated_from_typename =
                    std::any::type_name::<<ValidatedInto as Validated>::ValidatedFrom>();
                let valiated_from_typeid =
                    std::any::TypeId::of::<<ValidatedInto as Validated>::ValidatedFrom>();
                self.maybe_produce4_downcast_err(
                    src_ridfmt,
                    resource_source,
                    src_typename,
                    src_typeid,
                    valiated_from_typename,
                    valiated_from_typeid,
                )
            }
        }
    }

    fn maybe_produce4_downcast_err(
        &self,
        src_ridfmt: ResourceIdFormat,
        src_resource_source: ResourceSource,
        src_typename: &'static str,
        src_typeid: TypeId,
        valiated_from_typename: &'static str,
        valiated_from_typeid: TypeId,
    ) -> ResourceProductionResult {
        let src_type = format!("{src_typename} {src_typeid:?}");
        let target_type = format!("{valiated_from_typename} {valiated_from_typename:?}");
        let opt_src_type_expected = Some(target_type.clone());
        let e = ResourceProductionError::CouldntDowncastResource {
            src_ridfmt,
            src_resource_source,
            src_type,
            opt_src_type_expected,
            target_type,
        };
        error!("resourceproducer_validatetoedo: {e:?}");
        Err(e)
    }

    fn maybe_produce4_validate_ok(
        &self,
        src_ridfmt: ResourceIdFormat,
        resource_source: ResourceSource,
        arc_validated: Arc<dyn Resource>,
    ) -> ResourceProductionResult {
        let rsrc = ResourceSource::validated_from(src_ridfmt.fmt, resource_source);
        Ok((arc_validated, rsrc))
    }

    fn maybe_produce4_ok_validate_err(&self, e: EgError) -> ResourceProductionResult {
        let e: ResourceProductionError = e.into();
        error!("{e:?}");
        Err(e)
    }
}

//=================================================================================================|

#[allow(non_snake_case)]
fn gather_resourceproducer_registrations_ValidateToEdo(
    f: &mut dyn for<'a> FnMut(&'a [ResourceProducerRegistration]),
) {
    trace!("gather_resourceproducer_registrations_ValidateToEdo");

    let registration = {
        let name = ResourceProducer_ValidateToEdo::NAME.into();
        let category = ResourceProducerCategory::DefaultProducer;
        let fn_rc_new = ResourceProducer_ValidateToEdo::arc_new;
        ResourceProducerRegistration {
            name,
            category,
            fn_rc_new,
        }
    };
    f(&[registration]);
}

inventory::submit! {
    GatherResourceProducerRegistrationsFnWrapper(gather_resourceproducer_registrations_ValidateToEdo)
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{Context, Result, anyhow, bail, ensure};
    use insta::assert_ron_snapshot;

    use super::*;
    use crate::{eg_config::EgConfig, resource::ElectionDataObjectId as EdoId};

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::resource_provider_validatetoedo::t::t1",
            );
            let eg = eg.as_ref();

            {
                let (dr_rc, dr_src) = eg
                    .produce_resource(&ResourceIdFormat {
                        rid: ResourceId::ElectionDataObject(EdoId::ElectionManifest),
                        fmt: ResourceFormat::SliceBytes,
                    })
                    .await
                    .unwrap();
                assert_ron_snapshot!(dr_rc.rid(), @"ElectionDataObject(ElectionManifest)");
                assert_ron_snapshot!(dr_rc.format(), @r#"SliceBytes"#);
                assert_ron_snapshot!(dr_src, @"ExampleData(SliceBytes)");
                assert_ron_snapshot!(dr_rc.as_slice_bytes().is_some(), @r#"true"#);
                assert_ron_snapshot!(10 < dr_rc.as_slice_bytes().unwrap().len(), @r#"true"#);
                //assert_ron_snapshot!(dr_rc.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()), @r#"Some("{...}")"#);
            }

            {
                let result = eg
                    .produce_resource(&ResourceIdFormat {
                        rid: ResourceId::ElectionDataObject(EdoId::ElectionManifest),
                        fmt: ResourceFormat::ConcreteType,
                    })
                    .await;
                assert_ron_snapshot!(result, @r#"
            Err(NoProducerConfigured(
              ridfmt: ResourceIdFormat(
                id: ElectionDataObject(ElectionManifest),
                fmt: ConcreteType,
              ),
            ))"#);
            }

            /*
            {
                let (dr_rc, dr_src) = eg
                    .produce_resource(&ResourceIdFormat {
                        id: ResourceId::ElectionDataObject(EdoId::ElectionManifest),
                        fmt: ResourceFormat::ValidatedElectionDataObject,
                    })
                    .unwrap();
                assert_ron_snapshot!(dr_rc.rid(), @r#"PersistedElectionDataObject(ElectionManifest)"#);
                assert_ron_snapshot!(dr_rc.format(), @"ValidatedElectionDataObject");
                assert_ron_snapshot!(dr_src, @"ExampleData");
            }
            // */
        });
    }
}
