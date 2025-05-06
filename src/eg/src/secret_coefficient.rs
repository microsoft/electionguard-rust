// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]

use util::csrng::Csrng;

use crate::algebra::{FieldElement, ScalarField};

//=================================================================================================|

/// A polynomial coefficient used to secret key share.
///
/// Corresponds to `a_{i,j}` in EGDS 2.1.0 eq. 7 pg. 22.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SecretCoefficient(pub FieldElement);

impl SecretCoefficient {
    /// Generates a new [`SecretCoefficient`] by picking a random [`FieldElement`].
    pub fn new_random(csrng: &dyn Csrng, field: &ScalarField) -> Self {
        Self(field.random_field_elem(csrng))
    }
}

impl AsRef<FieldElement> for SecretCoefficient {
    #[inline]
    fn as_ref(&self) -> &FieldElement {
        &self.0
    }
}

impl From<FieldElement> for SecretCoefficient {
    /// A [`SecretCoefficient`] can always be made from a [`FieldElement`].
    #[inline]
    fn from(field_elem: FieldElement) -> Self {
        SecretCoefficient(field_elem)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::SecretCoefficient;
    use crate::{algebra::FieldElement, eg::Eg, resource::ProduceResourceExt};

    #[allow(unused_imports)]
    use crate::fixed_parameters::{FixedParametersTrait, FixedParametersTraitExt};

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::secret_coefficient::t::t1",
            );
            let eg = eg.as_ref();
            let csrng = eg.csrng();
            let fixed_parameters = eg.fixed_parameters().await.unwrap();
            let field = fixed_parameters.field();

            for _ in 0..100 {
                let a = SecretCoefficient::new_random(csrng, field);
                let a: &FieldElement = a.as_ref();
                assert!(a.is_valid(field));
            }
        });
    }
}
