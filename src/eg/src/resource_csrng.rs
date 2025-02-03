// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use util::csrng::{Csrng, DeterministicCsrng};

use crate::{
    eg_config::EgConfig,
    resource::{Resource, ResourceFormat, ResourceId, ResourceIdFormat},
    serializable::SerializableCanonical,
};

//=================================================================================================|

/// A Resource concrete type providing a CSRNG. Although a CSPRNG may have the advantage
/// of reproducibility for test code, a CSRNG abstraction is a notionally stateless interface
/// and thus can be used with only a shared reference.
#[allow(non_camel_case_types)]
#[derive(derive_more::Debug, serde::Serialize)]
#[debug("Resource_Csrng {{ DeterministicCsrng }}")]
pub struct Resource_Csrng {
    #[serde(skip)]
    csrng: DeterministicCsrng,
}

impl Resource_Csrng {
    pub fn new(config: &EgConfig) -> Self {
        let csprng = config.make_csprng_builder().finish();
        let csrng = DeterministicCsrng::new(csprng);
        Self { csrng }
    }

    pub fn as_csrng(&self) -> &dyn Csrng {
        &self.csrng
    }
}

impl SerializableCanonical for Resource_Csrng {}

impl Resource for Resource_Csrng {
    fn ridfmt(&self) -> &ResourceIdFormat {
        &ResourceIdFormat {
            rid: ResourceId::Csrng,
            fmt: ResourceFormat::ConcreteType,
        }
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::Result;
    use insta::assert_ron_snapshot;

    use super::*;
    use crate::eg::Eg;

    #[test]
    fn t0() -> Result<()> {
        let eg = &Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::resource_csrng::t::t0",
        );

        let (dr_rc, dr_src) = eg
            .produce_resource(&ResourceIdFormat {
                rid: ResourceId::Csrng,
                fmt: ResourceFormat::ConcreteType,
            })
            .unwrap();
        assert_ron_snapshot!(dr_rc.rid(), @r#"Csrng"#);
        assert_ron_snapshot!(dr_rc.format(), @r#"ConcreteType"#);
        assert_ron_snapshot!(dr_src, @r#"Provided"#);

        let opt_dr_csrng = dr_rc.downcast_ref::<Resource_Csrng>();
        assert_ron_snapshot!(opt_dr_csrng.is_some(), @r#"true"#);

        let dr_csrng = opt_dr_csrng.unwrap();

        fn eq_0_str(a: u128) -> &'static str {
            ["not equals 0_u128", "equals 0_u128"][(a == 0_u128) as usize]
        }
        let csrng = dr_csrng.as_csrng();

        assert_ron_snapshot!(eq_0_str(csrng.next_u128()), @r#""not equals 0_u128""#);
        assert_ron_snapshot!(eq_0_str(csrng.next_u128()), @r#""not equals 0_u128""#);
        assert_ron_snapshot!(eq_0_str(csrng.next_u128()), @r#""not equals 0_u128""#);
        assert_ron_snapshot!(eq_0_str(csrng.next_u128()), @r#""not equals 0_u128""#);

        Ok(())
    }
}
