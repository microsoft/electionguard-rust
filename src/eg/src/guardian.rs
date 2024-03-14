// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module implements guardian indices.

use crate::index::Index;

#[doc(hidden)]
/// Tag used to specialize [`Index`] for guardian indices.
pub struct GuardianIndexTag;

/// Guardian `i`.
///
/// Used for:
///
/// - [`VaryingParameters::n`](crate::varying_parameters::VaryingParameters::n), 1 <= [`n`](crate::varying_parameters::VaryingParameters::n) < 2^31.
/// - [`VaryingParameters::k`](crate::varying_parameters::VaryingParameters::k), 1 <= [`k`](crate::varying_parameters::VaryingParameters::k) <= [`n`](crate::varying_parameters::VaryingParameters::n).
/// - [`GuardianSecretKey::i`](crate::guardian_secret_key::GuardianSecretKey::i), 1 <= [`i`](crate::guardian_secret_key::GuardianSecretKey::i) <= [`n`](crate::varying_parameters::VaryingParameters::n).
/// - [`GuardianPublicKey::i`](crate::guardian_public_key::GuardianPublicKey::i), 1 <= [`i`](crate::guardian_public_key::GuardianPublicKey::i) <= [`n`](crate::varying_parameters::VaryingParameters::n).
///
pub type GuardianIndex = Index<GuardianIndexTag>;
