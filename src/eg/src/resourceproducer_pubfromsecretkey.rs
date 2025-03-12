// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(clippy::let_and_return)] //? TODO: Remove temp development code
#![allow(clippy::needless_lifetimes)] //? TODO: Remove temp development code
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    borrow::{
        Cow,
        //Borrow,
    },
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //hash::{BuildHasher, Hash, Hasher},
    //io::{BufRead, Cursor},
    //iter::zip,
    //marker::PhantomData,
    //path::{Path, PathBuf},
    //process::ExitCode,
    //rc::Rc,
    //str::FromStr,
    sync::{
        Arc,
        //OnceLock,
    },
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use futures_lite::future::{self, FutureExt};
//use hashbrown::HashMap;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use util::abbreviation::Abbreviation;

use crate::{
    eg::Eg,
    guardian::{AsymmetricKeyPart, GuardianIndex, GuardianKeyPartId, GuardianKeyPurpose},
    guardian_secret_key::GuardianSecretKey,
    loadable::KnowsFriendlyTypeName,
    resource::{
        ElectionDataObjectId as EdoId, ProduceResource, ProduceResourceExt, Resource,
        ResourceFormat, ResourceId, ResourceIdFormat,
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
    resource_slicebytes::ResourceSliceBytes,
    serializable::SerializableCanonical,
    validatable::Validated,
};

//=================================================================================================|

/// A [`ResourceProducer`] that, when a Guardian Public Key is requested, attempts to convert
/// it from a secret key, if available.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default, serde::Serialize)]
pub(crate) struct ResourceProducer_PublicFromSecretKey;

impl ResourceProducer_PublicFromSecretKey {
    pub const NAME: &str = "PublicFromSecretKey";

    fn arc_new() -> Arc<dyn ResourceProducer_Any_Debug_Serialize + 'static> {
        let self_ = Self;
        Arc::new(self_)
    }
}

impl ResourceProducer for ResourceProducer_PublicFromSecretKey {
    fn name(&self) -> Cow<'static, str> {
        Self::NAME.into()
    }

    fn fn_rc_new(&self) -> FnNewResourceProducer {
        Self::arc_new
    }

    fn maybe_produce(&self, rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
        let ResourceIdFormat { rid, fmt } = rp_op.requested_ridfmt();

        // We only handle the case of requesting a ValidElectionDataObject, Edo, GuardianKey, Public.
        let opt_ix_purpose: Option<GuardianKeyPartId> = match (fmt, rid) {
            (
                ResourceFormat::ValidElectionDataObject,
                ResourceId::ElectionDataObject(EdoId::GuardianKeyPart(key_part_id)),
            ) => match key_part_id {
                GuardianKeyPartId {
                    asymmetric_key_part: AsymmetricKeyPart::Public,
                    guardian_ix,
                    key_purpose,
                } => Some(*key_part_id),
                _ => None,
            },
            _ => None,
        };

        let Some(key_part_id) = opt_ix_purpose else {
            debug!("Not handling {}", rp_op.requested_ridfmt());
            return None;
        };

        async_global_executor::block_on(self.maybe_extract_guardian_public_key(rp_op, key_part_id))
    }
}

impl ResourceProducer_PublicFromSecretKey {
    #[instrument(
        name = "RP_PublicFromSecretKey::maybe_extract_guardian_public_key",
        fields(rf = trace_display(rp_op.requested_ridfmt().abbreviation())),
        skip(self, rp_op),
        ret
    )]
    async fn maybe_extract_guardian_public_key(
        &self,
        rp_op: &Arc<RpOp>,
        key_part_id: GuardianKeyPartId,
    ) -> Option<ResourceProductionResult> {
        let GuardianKeyPartId {
            guardian_ix,
            key_purpose,
            asymmetric_key_part,
        } = key_part_id;
        tracing::Span::current().record("guardian_ix", tracing::field::display(guardian_ix));
        tracing::Span::current().record("key_purpose", tracing::field::display(key_purpose));
        tracing::Span::current().record(
            "asymmetric_key_part",
            tracing::field::display(asymmetric_key_part),
        );

        if asymmetric_key_part != AsymmetricKeyPart::Public {
            error!(
                name = "RP_PublicFromSecretKey::maybe_extract_guardian_public_key",
                "asymmetric_key_part={asymmetric_key_part}"
            );
            debug_assert_eq!(asymmetric_key_part, AsymmetricKeyPart::Public);
            return None;
        }

        // See if we can obtain a Validated version of the secret key
        let mut request_secret_key_part_id = key_part_id;
        request_secret_key_part_id.asymmetric_key_part = AsymmetricKeyPart::Secret;

        let ridfmt_secretkey_validated = ResourceIdFormat {
            rid: ResourceId::ElectionDataObject(EdoId::GuardianKeyPart(request_secret_key_part_id)),
            fmt: ResourceFormat::ValidElectionDataObject,
        };

        let secret_key_part_production_result = rp_op
            .produce_resource_downcast::<GuardianSecretKey>(&ridfmt_secretkey_validated)
            .await;

        match secret_key_part_production_result {
            Ok((secret_key, resource_source)) => {
                let public_key = secret_key.make_public_key();
                let arc_public_key = Arc::new(public_key);
                let resource_source = ResourceSource::validly_extracted_from(resource_source);
                Some(Ok((arc_public_key, resource_source)))
            }
            Err(ResourceProductionError::NoProducerFound { .. }) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

//=================================================================================================|

fn gather_resourceproducer_registrations_PublicFromSecretKey(
    f: &mut dyn for<'a> FnMut(&'a [ResourceProducerRegistration]),
) {
    f(&[ResourceProducerRegistration::new_defaultproducer(
        ResourceProducer_PublicFromSecretKey::NAME,
        ResourceProducer_PublicFromSecretKey::arc_new,
    )]);
}

inventory::submit! {
    GatherResourceProducerRegistrationsFnWrapper(gather_resourceproducer_registrations_PublicFromSecretKey)
}

//=================================================================================================|
