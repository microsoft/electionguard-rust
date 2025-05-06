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

use std::{borrow::Cow, sync::Arc};

use serde::Serialize;
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
use util::abbreviation::Abbreviation;

use crate::{
    eg::Eg,
    election_manifest::ElectionManifestInfo,
    errors::{EgError, EgResult},
    guardian::GuardianKeyPartId,
    guardian_secret_key::{GuardianIndex, GuardianSecretKey},
    key::AsymmetricKeyPart,
    loadable::LoadableFromStdIoReadValidatable,
    resource::{ProduceResource, ProduceResourceExt, Resource},
    resource_id::{ElectionDataObjectId as EdoId, ResourceFormat, ResourceId, ResourceIdFormat},
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionError,
        ResourceProductionResult, ResourceSource,
    },
    resource_producer_registry::{
        FnNewResourceProducer, GatherResourceProducerRegistrationsFnWrapper,
        ResourceProducerCategory, ResourceProducerRegistration,
    },
    resource_production::RpOp,
    validatable::Validated,
    varying_parameters::{BallotChaining, VaryingParametersInfo},
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

    pub fn arc_new() -> Arc<dyn ResourceProducer_Any_Debug_Serialize + 'static> {
        let self_ = Self::new();
        Arc::new(self_)
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
}

impl Default for ResourceProducer_ExampleData {
    fn default() -> Self {
        Self::new()
    }
}

type Result_ArcDynResource_ProductionErr =
    Result<Arc<(dyn Resource + 'static)>, ResourceProductionError>;
type Opt_Result_ArcDynResource_ProductionErr = Option<Result_ArcDynResource_ProductionErr>;

impl ResourceProducer for ResourceProducer_ExampleData {
    fn name(&self) -> Cow<'static, str> {
        Self::NAME.into()
    }

    fn fn_rc_new(&self) -> FnNewResourceProducer {
        Self::arc_new
    }

    fn maybe_produce(&self, rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
        async_global_executor::block_on(self.maybe_produce_async(rp_op))
    }
}

impl ResourceProducer_ExampleData {
    #[instrument(
        name = "RP_ExampleData",
        level = "debug",
        fields(rf = trace_display(&rp_op.requested_ridfmt().abbreviation())),
        skip(self, rp_op)
    )]
    async fn maybe_produce_async(&self, rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
        use ResourceId as ResId;

        let rp_op = rp_op.as_ref();

        let ResourceIdFormat {
            rid: requested_rid,
            fmt: requested_fmt,
        } = rp_op.requested_ridfmt().into_owned();

        #[allow(clippy::collapsible_match)]
        let opt_result: Opt_Result_ArcDynResource_ProductionErr =
            match (requested_rid.clone(), requested_fmt) {
                (ResId::ElectionDataObject(edo_id), ResourceFormat::ConcreteType) => match edo_id {
                    EdoId::FixedParameters => Some(Self::make_fixed_parameters_info(rp_op)),
                    EdoId::VaryingParameters => Some(self.make_varying_parameters_info()),
                    EdoId::ElectionManifest => Some(Self::make_election_manifest_info()),
                    _ => None,
                },
                (ResId::ElectionDataObject(edo_id), ResourceFormat::ValidElectionDataObject) => {
                    match edo_id {
                        EdoId::GuardianKeyPart(key_part_id) => {
                            match key_part_id.asymmetric_key_part {
                                AsymmetricKeyPart::Secret => Some(
                                    Self::make_guardian_key_part_secret(rp_op, key_part_id).await,
                                ),
                                _ => None,
                            }
                        }
                        _ => None,
                    }
                }
                _ => None,
            };

        opt_result.map(|result| {
            result.map(|arc_resource| {
                let fmt = arc_resource.format().into_owned();
                let resource_source = ResourceSource::ExampleData(fmt);
                (arc_resource, resource_source)
            })
        })
    }

    #[instrument(name = "make_fixed_parameters_info", skip(produce_resource))]
    fn make_fixed_parameters_info(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> Result_ArcDynResource_ProductionErr {
        Ok(crate::standard_parameters::buildcfg_fixed_parameters_info_arc())
    }

    #[instrument(name = "make_varying_parameters_info")]
    fn make_varying_parameters_info(&self) -> Result_ArcDynResource_ProductionErr {
        let varying_parameters_info = VaryingParametersInfo {
            n: self.n,
            k: self.k,
            date: "2023-05-02".to_string(),
            info: "The United Realms of Imaginaria, General Election".to_string(),
            ballot_chaining: BallotChaining::Prohibited,
        };
        Ok(Arc::new(varying_parameters_info))
    }

    #[instrument(name = "make_election_manifest_info")]
    fn make_election_manifest_info() -> Result_ArcDynResource_ProductionErr {
        let election_manifest_info =
            ElectionManifestInfo::from_json_str_validatable(ELECTION_MANIFEST_PRETTY)?;
        Ok(Arc::new(election_manifest_info))
    }

    #[instrument(name = "make_guardian_key_part_secret", skip(rp_op))]
    async fn make_guardian_key_part_secret(
        rp_op: &RpOp,
        key_part_id: GuardianKeyPartId,
    ) -> Result_ArcDynResource_ProductionErr {
        debug!(
            rf = rp_op.trace_field_rf(),
            "vvvvvvvvvvvvvv make_guardian_key_part_secret vvvvvvvvvvvvvv"
        );
        debug!(
            rf = rp_op.trace_field_rf(),
            "rid: {}",
            rp_op.requested_rid()
        );
        debug!(
            rf = rp_op.trace_field_rf(),
            "fmt: {}",
            rp_op.requested_fmt()
        );
        debug!(rf = rp_op.trace_field_rf(), "key_part_id: {key_part_id}");
        let GuardianKeyPartId {
            guardian_ix,
            key_purpose,
            asymmetric_key_part,
        } = key_part_id;
        let name = format!("Example Guardian {guardian_ix}");
        debug!(rf = rp_op.trace_field_rf(), "name: {name}");
        let gsk = GuardianSecretKey::generate(rp_op, guardian_ix, name, key_purpose).await?;
        debug!(
            rf = rp_op.trace_field_rf(),
            "^^^^^^^^^^^^^^ make_guardian_key_part_secret ^^^^^^^^^^^^^^"
        );
        Ok(gsk)
    }
}

//=================================================================================================|

#[allow(non_snake_case)]
fn gather_resourceproducer_registrations_ExampleData(
    f: &mut dyn for<'a> FnMut(&'a [ResourceProducerRegistration]),
) {
    let registration = {
        let name = ResourceProducer_ExampleData::NAME.into();
        let category = ResourceProducerCategory::GeneratedTestData;
        let fn_rc_new = ResourceProducer_ExampleData::arc_new;
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

// "preencrypted_ballots": { "hash_trimming_fn_omega": "two hex characters" },

static ELECTION_MANIFEST_PRETTY: &str = r#"{
  "label": "General Election - The United Realms of Imaginaria",
  "record_undervoted_contest_condition": false,
  "record_undervote_difference": true,
  "preencrypted_ballots": null,
  "contests": [
    {
      "label": "For President and Vice President of The United Realms of Imaginaria",
      "options": [
          { "label": "Thündéroak, Vâlêriana D. (Ëverbright), Ålistair R. Jr. (Ætherwïng)" },
          { "label": "Stârførge, Cássánder A. (Møonfire), Célestïa L. (Crystâlheärt)" } ]
    }, {
      "label": "Minister of Elemental Resources",
        "record_undervoted_contest_condition": false,
        "options": [
          { "label": "Tïtus Stormforge (Ætherwïng)" },
          { "label": "Fæ Willowgrove (Crystâlheärt)" },
          { "label": "Tèrra Stonebinder (Independent)" } ]
    }, {
      "label": "Minister of Arcane Sciences",
      "record_undervoted_contest_condition": true,
      "options": [
          { "label": "Élyria Moonshadow (Crystâlheärt)", "selection_limit": "CONTEST_LIMIT" },
          { "label": "Archímedes Darkstone (Ætherwïng)" },
          { "label": "Seraphína Stormbinder (Independent)" },
          { "label": "Gávrïel Runëbørne (Stärsky)" } ]
    }, {
      "label": "Minister of Dance",
      "record_undervote_difference": true,
      "options": [
          { "label": "Äeliana Sunsong (Crystâlheärt)" },
          { "label": "Thâlia Shadowdance (Ætherwïng)" },
          { "label": "Jasper Moonstep (Stärsky)" } ]
    }, {
      "label": "Gränd Cøuncil of Arcáne and Technomägical Affairs",
      "record_undervote_difference": false,
      "options": [
          { "label": "Ìgnatius Gearsøul (Crystâlheärt)" },
          { "label": "Èlena Wîndwhisper (Technocrat)", "selection_limit": 3 },
          { "label": "Bërnard Månesworn (Ætherwïng)", "selection_limit": "CONTEST_LIMIT" },
          { "label": "Séraphine Lùmenwing (Stärsky)", "selection_limit": 2 },
          { "label": "Nikólai Thunderstrîde (Independent)" },
          { "label": "Lïliana Fîrestone (Pęacemaker)", "selection_limit": "CONTEST_LIMIT" } ]
    }, {
      "label": "Proposed Amendment No. 1 - Equal Representation for Technological and Magical Profeſsions",
      "options": [
          { "label": "For", "selection_limit": "CONTEST_LIMIT" },
          { "label": "Against" } ]
    }, {
      "label": "Privacy Protection in Techno-Magical Communications Act",
      "options": [
          { "label": "Prō" },
          { "label": "Ĉontrá" } ]
    }, {
      "label": "Public Transport Modernization and Enchantment Proposal",
      "options": [
          { "label": "Prō" },
          { "label": "Ĉontrá" } ]
    }, {
      "label": "Renewable Ætherwind Infrastructure Initiative",
      "options": [
          { "label": "Prō" },
          { "label": "Ĉontrá" } ]
    }, {
      "label": "For Librarian-in-Chief of Smoothstone County",
      "selection_limit": 2147483647,
      "options": [
          { "label": "Élise Planetes", "selection_limit": "CONTEST_LIMIT" },
          { "label": "Théodoric Inkdrifter", "selection_limit": 2147483647 } ]
    }, {
      "label": "Silvërspîre County Register of Deeds Sébastian Moonglôw to be retained",
      "options": [
          { "label": "Retain", "selection_limit": 375},
          { "label": "Remove", "selection_limit": "CONTEST_LIMIT" } ]
    }
  ],
  "ballot_styles": [
    {
      "label": "Ballot style 1 has 1 contest: 1",
      "contests": [1]
    }, {
      "label": "Ballot style 2 has 1 contest: 2",
      "contests": [2]
    }, {
      "label": "Ballot style 3 has 1 contest: 3",
      "contests": [3]
    }, {
      "label": "Ballot style 4 has 1 contest: 4",
      "contests": [4]
    }, {
      "label": "Ballot style 5 has 1 contest: 5",
      "contests": [5]
    }, {
      "label": "Ballot style 6 has 1 contest: 6",
      "contests": [6]
    }, {
      "label": "Ballot style 7 has 1 contest: 7",
      "contests": [7]
    }, {
      "label": "Ballot style 8 has 1 contest: 8",
      "contests": [8]
    }, {
      "label": "Ballot style 9 has 1 contest: 9",
      "contests": [9]
    }, {
      "label": "Ballot style 10 has 1 contest: 10",
      "contests": [10]
    }, {
      "label": "Ballot style 11 has 1 contest: 11",
      "contests": [11]
    }, {
      "label": "Ballot style 12 has 2 contests: 1, 2",
      "contests": [1, 2]
    }, {
      "label": "Ballot style 13 (Smoothstone County Ballot) has 10 contests: 1 through 10",
      "contests": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    }, {
      "label": "Ballot style 14 (Silvërspîre County Ballot) has 10 contests: 1 through 11, skipping 10",
      "contests": [1, 2, 3, 4, 5, 6, 7, 8, 9, 11]
    }, {
      "label": "Ballot style 15 has 2 contests: 1 and 3",
      "contests": [1, 3]
    }, {
      "label": "Ballot style 16 has 2 contests: 2 and 3",
      "contests": [2, 3]
    }, {
      "label": "Ballot style 17 has 3 contests: 1, 2, and 3",
      "contests": [1, 2, 3]
    }
  ],
  "voting_device_information_spec": {
    "MayContainVotingDeviceInformation": {
      "VotingDeviceUniqueIdentifier": "Optional",
      "VotingLocationUniqueIdentifier": "Optional"
    }
  }
}
"#;

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use insta::assert_ron_snapshot;

    use super::*;
    use crate::resource::ElectionDataObjectId as EdoId;

    #[test_log::test]
    fn t1() {
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

    #[test_log::test]
    fn t2() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::resourceproducer_exampledata::t::t2",
            );
            let eg = eg.as_ref();

            use EdoId::*;
            use ResourceId::ElectionDataObject;

            {
                let (dr_rc, dr_src) = eg
                    .produce_resource(&ResourceIdFormat {
                        rid: ElectionDataObject(ElectionParameters),
                        fmt: ResourceFormat::SliceBytes,
                    })
                    .await
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
                    .await
                    .unwrap();
                assert_ron_snapshot!(dr_rc.rid(), @"ElectionDataObject(ElectionManifest)");
                assert_ron_snapshot!(dr_rc.format(), @r#"SliceBytes"#);
                assert_ron_snapshot!(dr_src, @"ExampleData(SliceBytes)");
                assert_ron_snapshot!(dr_rc.as_slice_bytes().is_some(), @r#"true"#);
                assert_ron_snapshot!(10 < dr_rc.as_slice_bytes().unwrap().len(), @r#"true"#);
                //assert_ron_snapshot!(dr_rc.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()), @r#"Some("{...}")"#);
            }
        });
    }
}
