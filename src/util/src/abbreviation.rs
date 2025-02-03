// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::borrow::Cow;

//=================================================================================================|

pub trait Abbreviation {
    /// Returns an excessively short string hinting at the value useful only for logging.
    fn abbreviation(&self) -> Cow<'static, str>;
}
