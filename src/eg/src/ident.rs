// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]

use serde_with::{DisplayFromStr, serde_as};
use unicode_ident::{is_xid_continue, is_xid_start};

//=================================================================================================|

/// An identifier, as defined for canonically serialized structs.
///
/// Identifiers must be:
///
/// - At least one character in length.
/// - The first character must belong to the Unicode `XID_Start` set.
/// - The first character must not be a digit.
/// - Any subsequent characters must belong to the Unicode `XID_Continue` set.
#[serde_as]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(serde::Deserialize, serde::Serialize)]
pub struct Ident(#[serde_as(as = "DisplayFromStr")] String);

impl std::fmt::Debug for Ident {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for Ident {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Ident {
    type Error = &'static str;

    /// Attempts to convert a [`String`] into a [`Ident`].
    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        let mut iter = s.chars();
        if let Some(ch) = iter.next() {
            if is_xid_start(ch) {
                if iter.all(is_xid_continue) {
                    Ok(Self(s))
                } else {
                    Err("Subsequent character not allowed for identifier.")
                }
            } else {
                Err("First character not allowed for identifier.")
            }
        } else {
            Err("Identifier must have at least one character.")
        }
    }
}

impl std::str::FromStr for Ident {
    type Err = &'static str;

    /// Attempts to parse a string `s` to return a [`Ident`].
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
}

impl TryFrom<&str> for Ident {
    type Error = &'static str;

    /// Attempts to convert an [`&str`] into a [`Ident`].
    #[inline]
    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        s.to_owned().try_into()
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use insta::assert_debug_snapshot;

    #[test_log::test]
    fn t0() {
        assert_debug_snapshot!(Ident::try_from(""), @r#"
        Err(
            "Identifier must have at least one character.",
        )
        "#);
        assert_debug_snapshot!(Ident::try_from("x"), @r#"
        Ok(
            x,
        )
        "#);
        assert_debug_snapshot!(Ident::try_from("x1"), @r#"
        Ok(
            x1,
        )
        "#);
    }
}
