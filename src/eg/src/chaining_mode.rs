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

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    ballot::HValue_H_I,
    contest_data_fields_ciphertexts::ContestDataFieldsCiphertexts,
    eg::Eg,
    hash::{eg_h, HValue, HVALUE_BYTE_LEN},
    pre_voting_data::PreVotingData,
    voting_device::VotingDeviceInformationHash,
};

//=================================================================================================|

/// EGDS 2.1.0 sec 3.4.4 pg 42:
///
/// "It contains the chaining mode identifier in its first four bytes".
pub const CHAINING_MODE_BYTE_LEN: usize = 4;

/// EGDS 2.1.0 sec 3.4.4 pg 42:
///
/// "It contains the chaining mode identifier in its first four bytes".
pub type ChainingModeByteArray = [u8; CHAINING_MODE_BYTE_LEN];

/// Byte sequence which identifies the chaining mode in use when computing the confirmation code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(serde::Deserialize, serde::Serialize)]
#[repr(u32)]
enum ChainingMode {
    /// "The simplest chaining mode is the no chaining mode, which is identified by the chaining
    /// mode identifier 0x00000000."
    NoChaining = 0x00000000,
}

impl ChainingMode {
    /// The number of bytes of a [`ChainingModeIdentifierByteArray`].
    pub const fn byte_len() -> usize {
        CHAINING_MODE_BYTE_LEN
    }
}

/*
impl From<ChainingMode> for ChainingModeByteArray {
    /// A [`ChainingModeByteArray`] can always be made from a [`ChainingMode`].
    #[inline]
    fn from(src: ChainingMode) -> Self {
        (src as u32).to_be_bytes()
    }
}
// */

impl From<ChainingMode> for [u8; CHAINING_MODE_BYTE_LEN] {
    #[inline]
    fn from(src: ChainingMode) -> Self {
        (src as u32).to_be_bytes()
    }
}

//=================================================================================================|

/// EGDS 2.1.0 sec 3.4.4 pg 42:
///
/// "In any case, the chaining field B_C is a byte array of 36 bytes.
/// It contains the chaining mode identifier in its first four bytes and has space for
/// a hash value in the remaining 32 bytes".
pub const CHAINING_FIELD_BYTE_LEN: usize = CHAINING_MODE_BYTE_LEN + HVALUE_BYTE_LEN;

/// EGDS 2.1.0 sec 3.4.4 pg 42:
pub type ChainingFieldByteArray = [u8; CHAINING_FIELD_BYTE_LEN];

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize, ZeroizeOnDrop)]
pub struct ChainingField(ChainingFieldByteArray);

impl ChainingField {
    /// The number of bytes of a [`ChainingField`].
    pub const fn byte_len() -> usize {
        CHAINING_FIELD_BYTE_LEN
    }

    /// Returns a new [`ChainingField`] value for [`ChainingMode::NoChaining`].
    ///
    /// Should always return [`Some`]. Once const array concatenation is available in stable Rust,
    /// we can probably remove the [`Option`] from the return type.
    ///
    /// - `h_di` - The [`VotingDeviceInformationHash`]
    pub fn new_no_chaining_mode(h_di: &VotingDeviceInformationHash) -> Option<ChainingField> {
        let mut cf_aby = [0u8; CHAINING_FIELD_BYTE_LEN];

        let chaining_mode = ChainingMode::NoChaining;

        {
            let aby_chaining_mode: ChainingModeByteArray = chaining_mode.into();
            let src_slice: &[u8] = aby_chaining_mode.as_ref();
            let dst_slice = &mut cf_aby[0..CHAINING_MODE_BYTE_LEN];
            if src_slice.len() != dst_slice.len() {
                return None;
            }
            dst_slice.copy_from_slice(src_slice);
        }

        {
            let src_slice: &[u8] = h_di.as_ref();
            let dst_slice = &mut cf_aby[CHAINING_MODE_BYTE_LEN..CHAINING_FIELD_BYTE_LEN];
            if src_slice.len() != dst_slice.len() {
                return None;
            }
            dst_slice.copy_from_slice(src_slice);
        }

        let self_ = ChainingField(cf_aby);

        Some(self_)
    }

    /// Returns a ref to an array representing the bytes of the chaining field.
    pub const fn as_array(&self) -> &ChainingFieldByteArray {
        &self.0
    }

    //pub fn new(chaining_mode: ChainingMode, )
}

impl serde::Serialize for ChainingField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        util::serde::serialize_bytes_as_uppercase_hex(self.as_array(), serializer)
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{anyhow, bail, ensure, Context, Result};
    use insta::assert_ron_snapshot;

    use super::*;
    use crate::{
        eg::Eg,
        hash::HValue,
        voting_device::{VotingDeviceInformation, VotingDeviceInformationHash},
    };

    #[test]
    fn t0() {
        assert_ron_snapshot!(
            (CHAINING_MODE_BYTE_LEN, ChainingMode::byte_len()),
            @r#"(4, 4)"#);

        let cm = ChainingMode::NoChaining;
        assert_ron_snapshot!(
            (cm, cm as u32, ChainingModeByteArray::from(cm)),
            @"(NoChaining, 0, (0, 0, 0, 0))");
    }

    #[test]
    fn t1() {
        assert_ron_snapshot!(CHAINING_FIELD_BYTE_LEN, @r#"36"#);
        assert_ron_snapshot!(ChainingField::byte_len(), @r#"36"#);
    }

    #[test]
    fn t2() {
        let eg = &Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::chaining_mode::t::t1",
        );

        let vdi = VotingDeviceInformation::new_empty();

        let h_di =
            VotingDeviceInformationHash::compute_from_voting_device_information(eg, &vdi).unwrap();

        let cf = ChainingField::new_no_chaining_mode(&h_di).unwrap();

        assert_ron_snapshot!(Vec::from(cf.as_array()), @r#"
        "#);

        assert_ron_snapshot!(cf, @r#"
        "#);
    }
}
