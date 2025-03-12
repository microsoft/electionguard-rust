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

use std::string;

use serde::{Deserialize, Serialize};

use crate::{errors::EgError, guardian::GuardianIndex};

//use crate::{};
//use crate::*;

//=================================================================================================|
/// The categories of access with which [`Resource`] may be associated.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    strum::VariantNames
)]
pub enum ResourceCategory {
    /// Generated data for testing only, has no secrecy requrirements.
    #[cfg(feature = "eg-allow-test-data-generation")]
    GeneratedTestData,

    /// The [`Resource`] is a secret held by a specific Guardian.
    /// For example, the [`GuardianSecretKey`](crate::guardian_secret_key::GuardianSecretKey)s
    SecretForGuardian(GuardianIndex),

    /// Data which is expected to be published before voting:
    ///
    /// - The [`ElectionManifest`](crate::election_manifest::ElectionManifest).
    /// - Voting device string
    /// - [`VotingDeviceInformationHash`](crate::voting_device::VotingDeviceInformationHash).
    BeforeVotingBegins_Published,

    /// Pre-encrypted ballots, e.g., sent to voters to enable vote-by-mail.
    /// Expected to be created before voting.
    BeforeVotingEnds_PreencryptedBallots,

    /// The data is generated during voting and published.
    BeforeVotingEnds_Published,

    /// The data is generated during voting and needs to be published for
    /// the tally to be independently verified.
    ///
    /// For example, the [`ElectionRecord`](crate::election_record::ElectionRecord).
    Tally_Published,
}

impl ResourceCategory {
    /// Returns a string representation of the path, using the `/` separator regardless of platform.
    ///
    /// This is used for snapshot testing.
    #[cfg(test)]
    pub fn into_xplatform_string_lossy(self) -> Option<String> {
        std::path::PathBuf::try_from(self).ok().map(|pb| {
            pb.iter()
                .map(|c| c.to_string_lossy())
                .collect::<Vec<_>>()
                .join("/")
        })
    }
}
//-------------------------------------------------------------------------------------------------|
impl TryFrom<ResourceCategory> for std::path::PathBuf {
    type Error = &'static str;

    /// Attempts to convert a [`DataCategory`] into a [`std::path::PathBuf`].
    #[inline]
    fn try_from(val: ResourceCategory) -> Result<Self, Self::Error> {
        use std::borrow::Cow;
        use std::ffi::{OsStr, OsString};
        use std::path::{Path, PathBuf};

        use ResourceCategory::*;

        let a: [Cow<'static, str>; 2] = match val {
            #[cfg(feature = "eg-allow-test-data-generation")]
            GeneratedTestData => ["generated_test_data".into(), "".into()],
            SecretForGuardian(guardian_ix) => [
                format!("SECRET_for_guardian_{guardian_ix}").into(),
                "".into(),
            ],
            BeforeVotingBegins_Published => ["before_voting_begins".into(), "published".into()],
            BeforeVotingEnds_PreencryptedBallots => {
                ["before_voting_ends".into(), "preencrypted_ballots".into()]
            }
            BeforeVotingEnds_Published => ["before_voting_ends".into(), "published".into()],
            Tally_Published => ["tally".into(), "published".into()],
        };

        let mut pb = PathBuf::new();
        for cow_str in a {
            if !cow_str.is_empty() {
                match cow_str {
                    Cow::Borrowed(ref_str) => {
                        pb.push(ref_str);
                    }
                    Cow::Owned(string) => {
                        pb.push(string);
                    }
                }
            }
        }

        Ok(pb)
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{Context, Result, anyhow, bail, ensure};
    use insta::assert_ron_snapshot;
    use strum::VariantNames;

    use super::*;
    use crate::guardian::{AsymmetricKeyPart, GuardianIndex, GuardianKeyPurpose};

    #[test]
    fn t0() {
        use ResourceCategory::*;
        assert_ron_snapshot!(ResourceCategory::VARIANTS, @r#"
        [
          "GeneratedTestData",
          "SecretForGuardian",
          "BeforeVotingBegins_Published",
          "BeforeVotingEnds_PreencryptedBallots",
          "BeforeVotingEnds_Published",
          "Tally_Published",
        ]"#);
    }

    #[test]
    fn t1() {
        use std::path::PathBuf;

        use ResourceCategory::*;

        #[cfg(feature = "eg-allow-test-data-generation")]
        assert_ron_snapshot!(GeneratedTestData.into_xplatform_string_lossy().unwrap(), @r#""generated_test_data""#);

        assert_ron_snapshot!(SecretForGuardian(13.try_into().unwrap()).into_xplatform_string_lossy().unwrap(), @r#""SECRET_for_guardian_13""#);

        assert_ron_snapshot!(BeforeVotingBegins_Published.into_xplatform_string_lossy().unwrap(), @r#""before_voting_begins/published""#);

        assert_ron_snapshot!(BeforeVotingEnds_PreencryptedBallots.into_xplatform_string_lossy().unwrap(), @r#""before_voting_ends/preencrypted_ballots""#);

        assert_ron_snapshot!(BeforeVotingEnds_Published.into_xplatform_string_lossy().unwrap(), @r#""before_voting_ends/published""#);

        assert_ron_snapshot!(Tally_Published.into_xplatform_string_lossy().unwrap(), @r#""tally/published""#);
    }
}
