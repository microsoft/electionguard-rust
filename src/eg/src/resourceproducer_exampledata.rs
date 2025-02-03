// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
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

use std::{
    borrow::Cow,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    rc::Rc,
    //str::FromStr,
    //sync::OnceLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};
//use rand::{distr::Uniform, Rng, RngCore};
use serde::Serialize;
//use static_assertions::assert_obj_safe;
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
use util::abbreviation::Abbreviation;

use crate::{
    eg::Eg,
    errors::{EgError, EgResult},
    fixed_parameters::FixedParameters,
    guardian::try_into_guardian_index,
    guardian_secret_key::GuardianIndex,
    guardian_share::GuardianEncryptedShare,
    resource::{Resource, ResourceFormat, ResourceId, ResourceIdFormat},
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
    validatable::Validated,
    varying_parameters::{BallotChaining, VaryingParameters, VaryingParametersInfo},
};

//=================================================================================================|

pub static EXAMPLE_DEFAULT_N: GuardianIndex = {
    let n = 5;
    GuardianIndex::one_plus_u16(n - 1)
};

pub static EXAMPLE_DEFAULT_K: GuardianIndex = {
    let k = 3;
    GuardianIndex::one_plus_u16(k - 1)
};

/// A built-in [`ResourceProducer`] that provides example data.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ResourceProducer_ExampleData {
    n: GuardianIndex,
    k: GuardianIndex,
}

impl ResourceProducer_ExampleData {
    pub const NAME: &str = "ExampleData";

    pub fn rc_new() -> Rc<dyn ResourceProducer_Any_Debug_Serialize> {
        let self_ = Self::new();
        Rc::new(self_)
    }

    pub fn new() -> Self {
        Self::new_n_k(EXAMPLE_DEFAULT_N, EXAMPLE_DEFAULT_K)
    }

    pub fn new_n_k(n: GuardianIndex, k: GuardianIndex) -> Self {
        Self { n, k }
    }

    pub fn varying_parameter_n(&self) -> GuardianIndex {
        self.n
    }

    pub fn varying_parameter_k(&self) -> GuardianIndex {
        self.k
    }

    fn make_fixed_parameters(eg: &Eg) -> FixedParameters {
        // Unwrap() is justified here because this is test code
        #[allow(clippy::unwrap_used)]
        crate::standard_parameters::make_standard_parameters(eg).unwrap()
    }

    fn make_varying_parameters(&self, eg: &Eg) -> VaryingParameters {
        let varying_parameters_info = VaryingParametersInfo {
            n: self.n,
            k: self.k,
            date: "2023-05-02".to_string(),
            info: "The United Realms of Imaginaria, General Election".to_string(),
            ballot_chaining: BallotChaining::Prohibited,
        };
        // Unwrap() is justified here because this is test code
        #[allow(clippy::unwrap_used)]
        VaryingParameters::try_validate_from(varying_parameters_info, eg).unwrap()
    }
}

impl Default for ResourceProducer_ExampleData {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceProducer for ResourceProducer_ExampleData {
    fn name(&self) -> Cow<'static, str> {
        Self::NAME.into()
    }

    fn fn_rc_new(&self) -> FnNewResourceProducer {
        Self::rc_new
    }

    #[instrument(
        name = "ResourceProducer_ResourceProducer_ExampleData::maybe_produce",
        fields(rf = trace_display(&rp_op.target_ridfmt)),
        skip(self, eg, rp_op),
        ret
    )]
    fn maybe_produce(&self, eg: &Eg, rp_op: &mut RpOp) -> Option<ResourceProductionResult> {
        use ResourceFormat::{ConcreteType, SliceBytes, ValidatedElectionDataObject};
        use ResourceId as ResId;

        use crate::resource::ElectionDataObjectId as EdoId;

        let ResourceIdFormat {
            rid: requested_rid,
            fmt: requested_fmt,
        } = rp_op.target_ridfmt().clone();

        // Types that we can easily produce a validated EDO directly.

        let opt_pr_rc_rsrc: Option<(Rc<dyn Resource>, ResourceSource)> =
            match (requested_rid.clone(), requested_fmt) {
                (ResId::ElectionDataObject(edoid), requested_fmt) => {
                    match (edoid, requested_fmt) {
                        (EdoId::FixedParameters, _requested_fmt) => {
                            let edo = Self::make_fixed_parameters(eg);
                            /*
                            let rc = if requested_fmt == ConcreteType {
                            let rsrc = edo.un_validate(eg)?;
                            Rc::new(rsrc)
                            } else {
                            Rc::new(edo)
                            };
                            // */
                            let rc = Rc::new(edo);
                            Some((rc, ResourceSource::ExampleData(ValidatedElectionDataObject)))
                        }
                        (EdoId::VaryingParameters, _requested_fmt) => {
                            let edo = self.make_varying_parameters(eg);
                            /*
                            let rc = if requested_fmt == ConcreteType {
                            let rsrc = edo.un_validate(eg)?;
                            Rc::new(rsrc)
                            } else {
                            Rc::new(edo)
                            };
                            // */
                            let rc = Rc::new(edo);
                            Some((rc, ResourceSource::ExampleData(ValidatedElectionDataObject)))
                        }
                        _ => None,
                    }
                }
                _ => None,
            };

        if let Some((rc_resource, rsrc)) = opt_pr_rc_rsrc {
            let current_ridfmt = rc_resource.ridfmt().clone();

            if &current_ridfmt == rp_op.target_ridfmt() {
                info!("Successfully produced a {}", current_ridfmt.abbreviation());
                return Some(Ok((rc_resource, rsrc)));
            }

            let ResourceIdFormat {
                rid: current_rid,
                fmt: current_fmt,
            } = current_ridfmt.clone();

            if current_rid != requested_rid {
                let e = ResourceProductionError::UnexpectedRidFmt {
                    requested: rp_op.target_ridfmt().clone(),
                    obtained: current_ridfmt,
                };
                error!("{e}");
                return Some(Err(e));
            }

            if requested_fmt == SliceBytes && current_fmt == ValidatedElectionDataObject {
                let result = ResourceSliceBytes::new_from_SerializableCanonical_Resource(
                    rc_resource.as_ref(),
                    rsrc,
                );

                let opt_result = match result {
                    Ok((rc_slicebytes, rsrc)) => {
                        info!(
                            "From {}, made a ResourceSliceBytes {} {}",
                            current_ridfmt.abbreviation(),
                            rc_slicebytes.ridfmt().abbreviation(),
                            rsrc.abbreviation()
                        );
                        Some(Ok((rc_slicebytes, rsrc)))
                    }
                    Err(e) => {
                        error!("{e}");
                        Some(Err(e))
                    }
                };
                return opt_result;
            }
        }

        None
    }
}

//=================================================================================================|

fn gather_resourceproducer_registrations_ExampleData(
    f: &mut dyn FnMut(&[ResourceProducerRegistration]),
) {
    let registration = {
        let name = ResourceProducer_ExampleData::NAME.into();
        let category = ResourceProducerCategory::GeneratedTestData;
        let fn_rc_new = ResourceProducer_ExampleData::rc_new;
        ResourceProducerRegistration {
            name,
            category,
            fn_rc_new,
        }
    };
    f(&[registration]);
}

inventory::submit! {
GatherResourceProducerRegistrationsFnWrapper(gather_resourceproducer_registrations_ExampleData)
}

//=================================================================================================|

static ELECTION_MANIFEST_PRETTY: &str = r#"{
"label": "General Election - The United Realms of Imaginaria",
"contests": [
{ "label": "For President and Vice President of The United Realms of Imaginaria",
"options": [
{ "label": "Thündéroak, Vâlêriana D.\nËverbright, Ålistair R. Jr.\n(Ætherwïng)" },
{ "label": "Stârførge, Cássánder A.\nMøonfire, Célestïa L.\n(Crystâlheärt)" }
]
}, { "label": "Minister of Elemental Resources",
"options": [
{ "label": "Tïtus Stormforge\n(Ætherwïng)" },
{ "label": "Fæ Willowgrove\n(Crystâlheärt)" },
{ "label": "Tèrra Stonebinder\n(Independent)" }
]
}, { "label": "Minister of Arcane Sciences",
"options": [
{ "label": "Élyria Moonshadow\n(Crystâlheärt)", "selection_limit": "CONTEST_LIMIT" },
{ "label": "Archímedes Darkstone\n(Ætherwïng)" },
{ "label": "Seraphína Stormbinder\n(Independent)" },
{ "label": "Gávrïel Runëbørne\n(Stärsky)" }
]
}, { "label": "Minister of Dance",
"options": [
{ "label": "Äeliana Sunsong\n(Crystâlheärt)" },
{ "label": "Thâlia Shadowdance\n(Ætherwïng)" },
{ "label": "Jasper Moonstep\n(Stärsky)" }
]
}, { "label": "Gränd Cøuncil of Arcáne and Technomägical Affairs",
"options": [
{ "label": "Ìgnatius Gearsøul\n(Crystâlheärt)" },
{ "label": "Èlena Wîndwhisper\n(Technocrat)", "selection_limit": 3 },
{ "label": "Bërnard Månesworn\n(Ætherwïng)", "selection_limit": "CONTEST_LIMIT" },
{ "label": "Séraphine Lùmenwing\n(Stärsky)", "selection_limit": 2 },
{ "label": "Nikólai Thunderstrîde\n(Independent)" },
{ "label": "Lïliana Fîrestone\n(Pęacemaker)", "selection_limit": "CONTEST_LIMIT" }
]
}, { "label": "Proposed Amendment No. 1\nEqual Representation for Technological and Magical Profeſsions",
"options": [
{ "label": "For", "selection_limit": "CONTEST_LIMIT" },
{ "label": "Against" }
]
}, { "label": "Privacy Protection in Techno-Magical Communications Act",
"options": [
{ "label": "Prō" },
{ "label": "Ĉontrá" }
]
}, { "label": "Public Transport Modernization and Enchantment Proposal",
"options": [
{ "label": "Prō" },
{ "label": "Ĉontrá" }
]
}, { "label": "Renewable Ætherwind Infrastructure Initiative",
"options": [
{ "label": "Prō" },
{ "label": "Ĉontrá" }
]
}, { "label": "For Librarian-in-Chief of Smoothstone County", "selection_limit": 2147483647,
"options": [
{ "label": "Élise Planetes", "selection_limit": "CONTEST_LIMIT" },
{ "label": "Théodoric Inkdrifter", "selection_limit": 2147483647 } ]
}, { "label": "Silvërspîre County Register of Deeds Sébastian Moonglôw to be retained",
"options": [
{ "label": "Retain", "selection_limit": 375},
{ "label": "Remove", "selection_limit": "CONTEST_LIMIT" } ]
}
],
"ballot_styles": [
{ "label": "Ballot style 1 has 1 contest: 1",
"contests": [1]
}, { "label": "Ballot style 2 has 1 contest: 2",
"contests": [2]
}, { "label": "Ballot style 3 has 1 contest: 3",
"contests": [3]
}, { "label": "Ballot style 4 has 1 contest: 4",
"contests": [4]
}, { "label": "Ballot style 5 has 1 contest: 5",
"contests": [5]
}, { "label": "Ballot style 6 has 1 contest: 6",
"contests": [6]
}, { "label": "Ballot style 7 has 1 contest: 7",
"contests": [7]
}, { "label": "Ballot style 8 has 1 contest: 8",
"contests": [8]
}, { "label": "Ballot style 9 has 1 contest: 9",
"contests": [9]
}, { "label": "Ballot style 10 has 1 contest: 10",
"contests": [10]
}, { "label": "Ballot style 11 has 1 contest: 11",
"contests": [11]
}, { "label": "Ballot style 12 has 2 contests: 1, 2",
"contests": [1, 2]
}, { "label": "Ballot style 13 (Smoothstone County Ballot) has 10 contests: 1 through 10",
"contests": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
}, { "label": "Ballot style 14 (Silvërspîre County Ballot) has 10 contests: 1 through 11, skipping 10",
"contests": [1, 2, 3, 4, 5, 6, 7, 8, 9, 11]
}, { "label": "Ballot style 15 has 2 contests: 1 and 3",
"contests": [1, 3]
}, { "label": "Ballot style 16 has 2 contests: 2 and 3",
"contests": [2, 3]
}, { "label": "Ballot style 17 has 3 contests: 1, 2, and 3",
"contests": [1, 2, 3]
}
]
}
"#;

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use insta::assert_ron_snapshot;

    use super::*;
    use crate::{eg_config::EgConfig, resource::ElectionDataObjectId};

    #[test]
    fn t0() {
        assert_ron_snapshot!(ResourceProducer_ExampleData::new(), @r#"
        ResourceProducer_ExampleData(
          n: 5,
          k: 3,
        )
        "#);
        assert_ron_snapshot!(ResourceProducer_ExampleData::new_n_k(9.try_into().unwrap(), 7.try_into().unwrap()), @r#"
        ResourceProducer_ExampleData(
          n: 9,
          k: 7,
        )
        "#);
    }

    #[test]
    fn t1() {
        let eg = &Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::resourceproducer_exampledata::t::t0",
        );

        use ElectionDataObjectId::*;
        use ResourceId::ElectionDataObject;

        {
            let (dr_rc, dr_src) = eg
                .produce_resource(&ResourceIdFormat {
                    rid: ElectionDataObject(ElectionParameters),
                    fmt: ResourceFormat::SliceBytes,
                })
                .unwrap();
            assert_ron_snapshot!(dr_rc.rid(), @"ElectionDataObject(ElectionParameters)");
            assert_ron_snapshot!(dr_rc.format(), @r#"SliceBytes"#);
            assert_ron_snapshot!(dr_src, @"ExampleData(SliceBytes)");
            assert_ron_snapshot!(dr_rc.as_slice_bytes().is_some(), @r#"true"#);
            assert_ron_snapshot!(10 < dr_rc.as_slice_bytes().unwrap().len(), @r#"true"#);
            //assert_ron_snapshot!(dr_rc.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()), @r#"Some("{...}")"#);
        }

        {
            let (dr_rc, dr_src) = eg
                .produce_resource(&ResourceIdFormat {
                    rid: ElectionDataObject(ElectionManifest),
                    fmt: ResourceFormat::SliceBytes,
                })
                .unwrap();
            assert_ron_snapshot!(dr_rc.rid(), @"ElectionDataObject(ElectionManifest)");
            assert_ron_snapshot!(dr_rc.format(), @r#"SliceBytes"#);
            assert_ron_snapshot!(dr_src, @"ExampleData(SliceBytes)");
            assert_ron_snapshot!(dr_rc.as_slice_bytes().is_some(), @r#"true"#);
            assert_ron_snapshot!(10 < dr_rc.as_slice_bytes().unwrap().len(), @r#"true"#);
            //assert_ron_snapshot!(dr_rc.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()), @r#"Some("{...}")"#);
        }
    }
}
