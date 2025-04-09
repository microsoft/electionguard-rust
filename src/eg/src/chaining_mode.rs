// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
//#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
//#![allow(dead_code)] //? TODO: Remove temp development code
//#![allow(unused_assignments)] //? TODO: Remove temp development code
//#![allow(unused_braces)] //? TODO: Remove temp development code
//#![allow(unused_imports)] //? TODO: Remove temp development code
//#![allow(unused_mut)] //? TODO: Remove temp development code
//#![allow(unused_variables)] //? TODO: Remove temp development code
//#![allow(unreachable_code)] //? TODO: Remove temp development code
//#![allow(non_camel_case_types)] //? TODO: Remove temp development code
//#![allow(non_snake_case)] //? TODO: Remove temp development code
//#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
//#![allow(noop_method_call)] //? TODO: Remove temp development code

use zeroize::{Zeroize, ZeroizeOnDrop};

use util::hex_dump::HexDump;

use crate::{hash::HVALUE_BYTE_LEN, voting_device::VotingDeviceInformationHash};

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
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    strum_macros::IntoStaticStr
)]
#[derive(serde::Deserialize, serde::Serialize)]
#[repr(u32)]
enum ChainingMode {
    /// "The simplest chaining mode is the no chaining mode, which is identified by the chaining
    /// mode identifier 0x00000000."
    NoChaining = 0x00000000,
}

impl ChainingMode {
    /// The number of bytes of a [`ChainingModeIdentifierByteArray`].
    #[allow(dead_code)]
    pub const fn byte_len() -> usize {
        CHAINING_MODE_BYTE_LEN
    }
}

impl std::fmt::Debug for ChainingMode {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: &'static str = self.into();
        write!(f, "{s} = {:#010X}", *self as u32)
    }
}

impl std::fmt::Display for ChainingMode {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl From<ChainingMode> for [u8; CHAINING_MODE_BYTE_LEN] {
    /// A [`ChainingModeByteArray`] can always be made from a [`ChainingMode`].
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

impl std::fmt::Debug for ChainingField {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for ChainingField {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hd = HexDump::new()
            .show_addr(false)
            .show_ascii(false)
            .group(2)
            .line_prefix("    ")
            .dump(self.as_array());
        writeln!(f, "ChainingField(\n{hd} )")
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use insta::{assert_debug_snapshot, assert_ron_snapshot, assert_snapshot};

    use util::hex_dump::HexDump;

    use super::*;
    use crate::{
        eg::Eg,
        voting_device::{VotingDeviceInformation, VotingDeviceInformationHash},
    };

    #[test_log::test]
    fn t1() {
        assert_ron_snapshot!(
            (CHAINING_MODE_BYTE_LEN, ChainingMode::byte_len()),
            @r#"(4, 4)"#);

        let cm = ChainingMode::NoChaining;

        assert_debug_snapshot!(cm, @r#"
            NoChaining = 0x00000000
        "#);

        assert_snapshot!(cm, @r#"
            NoChaining = 0x00000000
        "#);

        let cmba = ChainingModeByteArray::from(cm);
        assert_snapshot!(
            HexDump::new().show_addr(false).show_ascii(false).group(2).dump(&cmba),
            @"0000 0000");
    }

    #[test_log::test]
    fn t2() {
        assert_ron_snapshot!(CHAINING_FIELD_BYTE_LEN, @r#"36"#);
        assert_ron_snapshot!(ChainingField::byte_len(), @r#"36"#);
    }

    #[test_log::test]
    fn t3() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::chaining_mode::t::t3",
            );
            let eg = eg.as_ref();

            let vdi = VotingDeviceInformation::new_empty();

            let h_di =
                VotingDeviceInformationHash::compute_from_voting_device_information(eg, &vdi)
                    .await
                    .unwrap();

            let cf = ChainingField::new_no_chaining_mode(&h_di).unwrap();

            assert_snapshot!(cf, @r#"
            ChainingField(
                0000 0000 a3f9 c0a4 3411 7058 3cf3 de40
                e1f7 7408 b159 817b 58b1 a375 c920 6f5b
                ec4b 52cc )
            "#);
        });
    }
}
