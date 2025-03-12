// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::sync::Arc;

use util::abbreviation::Abbreviation;

use crate::{
    resource::{Resource, ResourceFormat, ResourceId, ResourceIdFormat},
    resource_producer::{ResourceProductionResult, ResourceSource},
    serializable::SerializableCanonical,
};

//=================================================================================================|

/// A concrete type that can be used to buffer [`SliceBytes`](ResourceFormat::SliceBytes)-style
/// [`Resource`]s.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct ResourceSliceBytes {
    ridfmt: ResourceIdFormat,
    vby: Vec<u8>,
}

impl ResourceSliceBytes {
    pub fn new(rid: &ResourceId, vby: Vec<u8>) -> Self {
        Self {
            ridfmt: ResourceIdFormat {
                rid: rid.clone(),
                fmt: ResourceFormat::SliceBytes,
            },
            vby,
        }
    }

    #[allow(non_snake_case)]
    pub fn new_from_SerializableCanonical_Resource<T: SerializableCanonical + Resource + ?Sized>(
        resource: &T,
        rpsrc_serialized_from: ResourceSource,
    ) -> ResourceProductionResult {
        let vby = resource.to_canonical_bytes()?;
        let drsb = ResourceSliceBytes::new(resource.rid(), vby);
        let rsrc =
            ResourceSource::serialized_from(ResourceFormat::SliceBytes, rpsrc_serialized_from);
        Ok((Arc::new(drsb), rsrc))
    }
}

impl SerializableCanonical for ResourceSliceBytes {}

crate::impl_MayBeValidatableUnsized_for_non_ValidatableUnsized! { ResourceSliceBytes }

impl Resource for ResourceSliceBytes {
    fn ridfmt(&self) -> &ResourceIdFormat {
        &self.ridfmt
    }

    fn as_slice_bytes(&self) -> Option<&[u8]> {
        Some(&self.vby)
    }
}

impl std::fmt::Debug for ResourceSliceBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use util::hex_dump::HexDump;

        let alternate = f.alternate();

        let mut ds = f.debug_struct("ResourceSliceBytes");
        ds.field("ridfmt", &format_args!("{}", self.ridfmt.abbreviation()));
        if alternate {
            let hd = HexDump::new().line_prefix("    ").group(4);
            ds.field("vby", &format_args!("[\n{}\n]", hd.dump(&self.vby)));
        } else {
            let hd = HexDump::new()
                .show_addr(false)
                .bytes_per_line(32)
                .cnt_bytes_max(32)
                .show_hex(false);
            let s = hd.dump(&self.vby).to_string();
            ds.field("vby", &s);
        }
        ds.finish()
    }
}

impl std::fmt::Display for ResourceSliceBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Debug>::fmt(self, f)
    }
}

//=================================================================================================|

//? TODO impl test
