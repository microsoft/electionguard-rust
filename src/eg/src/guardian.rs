// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use crate::index::Index;

/// Tag used to specialize [`Index`] for guardian indices.
pub struct GuardianIndexTag;

/// Guardian `i`.
///
/// Used for:
///
/// - [`crate::varying_parameters::VaryingParameters::n`]: 1 <= n < 2^31.
/// - [`crate::varying_parameters::VaryingParameters::k`], 1 <= k <= [`crate::varying_parameters::VaryingParameters::n`].
/// - [`crate::guardian_secret_key::GuardianSecretKey::i`], 1 <= k <= [`crate::varying_parameters::VaryingParameters::n`].
/// - [`crate::guardian_public_key::GuardianPublicKey::i`], 1 <= k <= [`crate::varying_parameters::VaryingParameters::n`].
///
pub type GuardianIndex = Index<GuardianIndexTag>;
