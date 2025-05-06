// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
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
    borrow::Cow,
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //hash::{BuildHasher, Hash, Hasher},
    //io::{BufRead, Cursor},
    //iter::zip,
    //marker::PhantomData,
    //path::{Path, PathBuf},
    //process::ExitCode,
    sync::Arc,
    //str::FromStr,
    //sync::{
        //Arc,
        //OnceLock,
    //},
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

/// A [`ResourceProducer`] that, when a persisted Edo is requested, attempts to load
/// its [`SliceBytes`] representation and validate it.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default, serde::Serialize)]
pub(crate) struct ResourceProducer_SlicebytesFromValidated;

impl ResourceProducer_SlicebytesFromValidated {
    pub const NAME: &str = "SlicebytesFromValidated";

    fn arc_new() -> Arc<dyn ResourceProducer_Any_Debug_Serialize + 'static> {
        let self_ = Self;
        Arc::new(self_)
    }
}

impl ResourceProducer for ResourceProducer_SlicebytesFromValidated {
    fn name(&self) -> Cow<'static, str> {
        Self::NAME.into()
    }

    fn fn_rc_new(&self) -> FnNewResourceProducer {
        Self::arc_new
    }

    fn maybe_produce(&self, rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
        // We only handle the case of requesting a serialized object from a validated object.
        if rp_op.requested_fmt().as_ref() != &ResourceFormat::SliceBytes {
            return None;
        }

        self.maybe_produce_slicebytes(rp_op)
    }
}

impl ResourceProducer_SlicebytesFromValidated {
    #[instrument(
        name = "RP_SlicebytesFromValidated::maybe_produce_slicebytes",
        level = "debug",
        fields(rf = trace_display(rp_op.requested_ridfmt().abbreviation())),
        skip(self, rp_op),
        ret
    )]
    fn maybe_produce_slicebytes(&self, rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
        //tracing::Span::current().record("rid", tracing::field::display(ridfmt.rid.abbreviation()));
        //tracing::Span::current().record("fmt", tracing::field::display(ridfmt.fmt.abbreviation()));

        // See if we can produce a Validated version of the requested resource
        let ridfmt_validated = ResourceIdFormat {
            rid: rp_op.requested_rid().into_owned(),
            fmt: ResourceFormat::ValidElectionDataObject,
        };
        let resource_production_result =
            async_global_executor::block_on(rp_op.produce_resource(&ridfmt_validated));
        match resource_production_result {
            Err(ResourceProductionError::NoProducerFound { .. }) => None,
            Err(e) => Some(Err(e)),
            Ok((arc_dyn_resource, resource_source)) => {
                let result = self.produce_slicebytes(arc_dyn_resource, resource_source);
                Some(result)
            }
        }
    }

    fn produce_slicebytes(
        &self,
        arc_dyn_validated: Arc<(dyn Resource + 'static)>,
        resource_source: ResourceSource,
    ) -> ResourceProductionResult {
        let ridfmt_src = arc_dyn_validated.ridfmt().into_owned();
        debug!("Using {ridfmt_src} source {resource_source}");

        debug_assert_eq!(ridfmt_src.fmt, ResourceFormat::ValidElectionDataObject);

        let ResourceIdFormat {
            rid: rid_src,
            fmt: fmt_src,
        } = ridfmt_src;

        let dyn_resource: &dyn Resource = arc_dyn_validated.as_ref();
        let dyn_serializablecanonical: &dyn SerializableCanonical =
            dyn_resource.as_dyn_serializable_canonical();
        let vby = dyn_serializablecanonical.to_canonical_bytes()?;

        let slice_bytes = ResourceSliceBytes::new(&rid_src, vby);
        let arc_dyn_resource_slice_bytes: Arc<dyn Resource + '_> = Arc::new(slice_bytes);

        let resource_source = ResourceSource::serialized_from(fmt_src, resource_source);
        Ok((arc_dyn_resource_slice_bytes, resource_source))
    }
}
