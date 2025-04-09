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

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::{
    errors::{EgError, EgResult},
    guardian::{AsymmetricKeyPart, GuardianIndex, GuardianKeyPartId},
    resource::{ElectionDataObjectId, ResourceId},
    resource_category::ResourceCategory,
};

//=================================================================================================|

/// A namespace and path components for a data resource.
///
/// Cf. [`std::path::Path`].
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize
)]
pub struct ResourceNamespacePath {
    pub resource_category: ResourceCategory,
    pub dir_path_components: Vec<Cow<'static, str>>,
    pub filename_base: Cow<'static, str>,
    pub filename_qualifier: Cow<'static, str>,
    pub filename_ext: Cow<'static, str>,
}

impl ResourceNamespacePath {
    /// Ensure the filename contains the 'canonical' qualifier.
    pub fn specify_canonical(&mut self) {
        self.filename_qualifier = "canonical".into();
    }

    /// Ensure the filename contains the 'pretty' qualifier.
    pub fn specify_pretty(&mut self) {
        self.filename_qualifier = "pretty".into();
    }

    /// Returns the filename, constructed by joining with `'.'` the non-empty values `filename_base`,
    /// `filename_qualifier`, and `filename_ext`.
    ///
    /// If `filename_base` is empty, an empty string is returned.
    pub fn filename(&self) -> String {
        let mut s = String::new();
        if !self.filename_base.is_empty() {
            s.push_str(&self.filename_base);

            if !self.filename_qualifier.is_empty() {
                s.push('.');
                s.push_str(&self.filename_qualifier);
            }

            if !self.filename_ext.is_empty() {
                s.push('.');
                s.push_str(&self.filename_ext);
            }
        }
        s
    }
}

impl std::fmt::Display for ResourceNamespacePath {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl TryFrom<&ResourceNamespacePath> for std::path::PathBuf {
    type Error = &'static str;

    /// Attempts to convert a [`ResourceNamespacePath`] into a [`std::path::PathBuf`].
    #[inline]
    fn try_from(drnp: &ResourceNamespacePath) -> Result<Self, Self::Error> {
        use std::borrow::Cow;
        use std::ffi::{OsStr, OsString};
        use std::path::{Path, PathBuf};

        use ResourceCategory::*;

        let mut pb: PathBuf = drnp.resource_category.try_into()?;

        for cow_str in &drnp.dir_path_components {
            if !cow_str.is_empty() {
                pb.push(cow_str.as_ref());
            }
        }

        let filename = drnp.filename();
        if !filename.is_empty() {
            pb.push(filename);
        }

        Ok(pb)
    }
}

//=================================================================================================|

impl ResourceNamespacePath {
    /// Many [`ResourceId`] variants can recommend a [`ResourceNamespacePath`].
    pub fn try_from_resource_id(rid: ResourceId) -> Option<ResourceNamespacePath> {
        use ResourceCategory::*;
        use ResourceId::*;

        match rid {
            ResourceId::ElectionGuardDesignSpecificationVersion => None,
            ResourceId::ElectionDataObject(election_data_object_id) => {
                use ElectionDataObjectId::*;

                #[allow(unreachable_patterns)] //? TODO eventually this becomes unnecessary
                match election_data_object_id {
                    FixedParameters => None,
                    VaryingParameters => None,
                    ElectionParameters => Some((
                        BeforeVotingBegins_Published,
                        vec![],
                        "election_parameters".into(),
                    )),
                    ElectionManifest => Some((
                        BeforeVotingBegins_Published,
                        vec![],
                        "election_manifest".into(),
                    )),
                    Hashes => Some((BeforeVotingBegins_Published, vec![], "hashes".into())),
                    GuardianKeyPart(gkid) => match gkid.asymmetric_key_part {
                        AsymmetricKeyPart::Secret => Some((
                            SecretForGuardian(gkid.guardian_ix),
                            vec![],
                            format!("guardian_{}.SECRET_key", gkid.guardian_ix).into(),
                        )),
                        AsymmetricKeyPart::Public => Some((
                            BeforeVotingBegins_Published,
                            vec!["guardian".into(), format!("{}", gkid.guardian_ix).into()],
                            format!(
                                "guardian_{}.{}.public_key",
                                gkid.guardian_ix, gkid.key_purpose
                            )
                            .into(),
                        )),
                    },
                    JointPublicKey(key_purpose) => Some((
                        BeforeVotingBegins_Published,
                        vec![],
                        format!("joint_public_key_{key_purpose}").into(),
                    )),
                    ExtendedBaseHash => Some((
                        BeforeVotingBegins_Published,
                        vec![],
                        "extended_base_hash".into(),
                    )),
                    PreVotingData => Some((
                        BeforeVotingBegins_Published,
                        vec![],
                        "pre_voting_data".into(),
                    )),

                    #[cfg(feature = "eg-allow-test-data-generation")]
                    GeneratedTestDataVoterSelections(h_seed) => Some((
                        GeneratedTestData,
                        vec!["voter_selections".into()],
                        format!("{h_seed}").into(),
                    )),

                    _ => None, //? TODO eventually this becomes unnecessary
                }
            }
        }
        .map(
            |(resource_namespace, dir_path_components, filename_base)| -> ResourceNamespacePath {
                ResourceNamespacePath {
                    resource_category: resource_namespace,
                    dir_path_components,
                    filename_base,
                    filename_qualifier: Cow::default(),
                    filename_ext: "json".into(),
                }
            },
        )
    }

    /// Many [`ResourceId`] variants constructed from an [`ElectionDataObjectId`] can
    /// recommend a [`ResourceNamespacePath`].
    pub fn try_from_edoid_opt(edo_id: ElectionDataObjectId) -> Option<ResourceNamespacePath> {
        let rid = ResourceId::ElectionDataObject(edo_id);
        ResourceNamespacePath::try_from_resource_id(rid)
    }

    /// Returns a string representation of the path, using the `/` separator regardless of platform.
    ///
    /// This is used for snapshot testing.
    #[cfg(test)]
    pub fn into_xplatform_string_lossy(&self) -> Option<String> {
        std::path::PathBuf::try_from(self).ok().map(|pb| {
            pb.iter()
                .map(|c| c.to_string_lossy())
                .collect::<Vec<_>>()
                .join("/")
        })
    }
}

impl TryFrom<ElectionDataObjectId> for ResourceNamespacePath {
    type Error = EgError;

    /// Attempts to convert a [`ElectionDataObjectId`] into a [`ResourceNamespacePath`].
    #[inline]
    fn try_from(edo_id: ElectionDataObjectId) -> std::result::Result<Self, Self::Error> {
        let rid = ResourceId::ElectionDataObject(edo_id.clone());
        ResourceNamespacePath::try_from_resource_id(rid)
            .ok_or_else(|| EgError::ResourcePathFromEdoId(edo_id))
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, anyhow, bail, ensure};
    use insta::assert_ron_snapshot;

    use super::*;
    use crate::guardian::{AsymmetricKeyPart, GuardianIndex, GuardianKeyPurpose};

    #[test_log::test]
    fn dr_ns_path() {
        use ElectionDataObjectId::*;
        use ResourceId::*;

        {
            let rid = ElectionGuardDesignSpecificationVersion;
            let opt_rnsp = ResourceNamespacePath::try_from_resource_id(rid);
            assert_ron_snapshot!(opt_rnsp, @"None");
        }
        {
            let edoid = FixedParameters;
            let opt_rnsp = ResourceNamespacePath::try_from_edoid_opt(edoid);
            assert_ron_snapshot!(opt_rnsp, @"None");
        }
        {
            let edoid = VaryingParameters;
            let opt_rnsp = ResourceNamespacePath::try_from_edoid_opt(edoid);
            assert_ron_snapshot!(opt_rnsp, @"None");
        }
        {
            let edoid = ElectionParameters;
            let mut rnsp = ResourceNamespacePath::try_from_edoid_opt(edoid).unwrap();
            rnsp.specify_canonical();
            assert_ron_snapshot!(rnsp, @r#"
            ResourceNamespacePath(
              resource_category: BeforeVotingBegins_Published,
              dir_path_components: [],
              filename_base: "election_parameters",
              filename_qualifier: "canonical",
              filename_ext: "json",
            )
            "#);
            assert_ron_snapshot!(rnsp.into_xplatform_string_lossy().unwrap(), @r#""before_voting_begins/published/election_parameters.canonical.json""#);
        }
        {
            let edoid = ElectionManifest;
            let mut rnsp = ResourceNamespacePath::try_from_edoid_opt(edoid).unwrap();
            rnsp.specify_pretty();
            assert_ron_snapshot!(rnsp, @r#"
            ResourceNamespacePath(
              resource_category: BeforeVotingBegins_Published,
              dir_path_components: [],
              filename_base: "election_manifest",
              filename_qualifier: "pretty",
              filename_ext: "json",
            )
            "#);
            assert_ron_snapshot!(rnsp.into_xplatform_string_lossy().unwrap(), @r#""before_voting_begins/published/election_manifest.pretty.json""#);
        }
        {
            let edoid = Hashes;
            let rnsp = ResourceNamespacePath::try_from_edoid_opt(edoid).unwrap();
            assert_ron_snapshot!(rnsp, @r#"
            ResourceNamespacePath(
              resource_category: BeforeVotingBegins_Published,
              dir_path_components: [],
              filename_base: "hashes",
              filename_qualifier: "",
              filename_ext: "json",
            )
            "#);
            assert_ron_snapshot!(rnsp.into_xplatform_string_lossy().unwrap(), @r#""before_voting_begins/published/hashes.json""#);
        }
        {
            let edoid = GuardianKeyPart(GuardianKeyPartId {
                guardian_ix: GuardianIndex::one(),
                key_purpose:
                    GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
                asymmetric_key_part: AsymmetricKeyPart::Secret,
            });
            let rnsp = ResourceNamespacePath::try_from_edoid_opt(edoid).unwrap();
            assert_ron_snapshot!(rnsp, @r#"
            ResourceNamespacePath(
              resource_category: SecretForGuardian(1),
              dir_path_components: [],
              filename_base: "guardian_1.SECRET_key",
              filename_qualifier: "",
              filename_ext: "json",
            )
            "#);
            assert_ron_snapshot!(rnsp.into_xplatform_string_lossy().unwrap(), @r#""SECRET_for_guardian_1/guardian_1.SECRET_key.json""#);
        }
        {
            let edoid = JointPublicKey(
                GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
            );
            let rnsp = ResourceNamespacePath::try_from_edoid_opt(edoid).unwrap();
            assert_ron_snapshot!(rnsp, @r#"
            ResourceNamespacePath(
              resource_category: BeforeVotingBegins_Published,
              dir_path_components: [],
              filename_base: "joint_public_key_encrypt_ballot_numerical_votes_and_additional_data_fields",
              filename_qualifier: "",
              filename_ext: "json",
            )
            "#);
            assert_ron_snapshot!(rnsp.into_xplatform_string_lossy().unwrap(), @r#""before_voting_begins/published/joint_public_key_encrypt_ballot_numerical_votes_and_additional_data_fields.json""#);
        }
        {
            let edoid = ExtendedBaseHash;
            let rnsp = ResourceNamespacePath::try_from_edoid_opt(edoid).unwrap();
            assert_ron_snapshot!(rnsp, @r#"
            ResourceNamespacePath(
              resource_category: BeforeVotingBegins_Published,
              dir_path_components: [],
              filename_base: "extended_base_hash",
              filename_qualifier: "",
              filename_ext: "json",
            )
            "#);
            assert_ron_snapshot!(rnsp.into_xplatform_string_lossy().unwrap(), @r#""before_voting_begins/published/extended_base_hash.json""#);
        }
        {
            let edoid = PreVotingData;
            let rnsp = ResourceNamespacePath::try_from_edoid_opt(edoid).unwrap();
            assert_ron_snapshot!(rnsp, @r#"
            ResourceNamespacePath(
              resource_category: BeforeVotingBegins_Published,
              dir_path_components: [],
              filename_base: "pre_voting_data",
              filename_qualifier: "",
              filename_ext: "json",
            )"#);
            assert_ron_snapshot!(rnsp.into_xplatform_string_lossy().unwrap(), @r#""before_voting_begins/published/pre_voting_data.json""#);
        }
        #[cfg(feature = "eg-allow-test-data-generation")]
        {
            let hv: crate::hash::HValue = std::array::from_fn(|ix| ix as u8 + 0x50).into();
            let edoid = GeneratedTestDataVoterSelections(hv);
            let rnsp = ResourceNamespacePath::try_from_edoid_opt(edoid).unwrap();
            assert_ron_snapshot!(rnsp, @r#"
            ResourceNamespacePath(
              resource_category: GeneratedTestData,
              dir_path_components: [
                "voter_selections",
              ],
              filename_base: "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F",
              filename_qualifier: "",
              filename_ext: "json",
            )
            "#);
            assert_ron_snapshot!(rnsp.into_xplatform_string_lossy().unwrap(), @r#""generated_test_data/voter_selections/505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F.json""#);
        }
    }
}
