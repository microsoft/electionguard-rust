// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(clippy::needless_lifetimes)] //? TODO: Remove temp development code
#![allow(clippy::absurd_extreme_comparisons)] //? TODO: Remove temp development code
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

use crate::{
    eg::Eg,
    resource::{
        ElectionDataObjectId as EdoId, Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    serializable::SerializableCanonical,
    validatable::{Validatable, Validated},
};

//=================================================================================================|

/// Specification version qualifier.
#[derive(
    Clone,
    Debug,
    strum_macros::Display,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize
)]
#[allow(non_camel_case_types)]
pub enum ElectionGuard_DesignSpecification_Version_Qualifier {
    /// The released spec version defined in the specification.
    ///
    /// This is the value expected for all real-world use.
    #[strum(to_string = "released specification version")]
    Released_Specification_Version,

    /// Some non-standard spec version.
    ///
    /// For example "Preliminary version of February 4, 2025"
    #[strum(to_string = "NONSTANDARD specification \"{0}\"")]
    Nonstandard_Specification(String),
}

//=================================================================================================|

/// Specification version qualifier.
#[derive(
    Clone,
    Copy,
    Debug,
    strum_macros::Display,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize
)]
#[allow(non_camel_case_types)]
pub enum ElectionGuard_FixedParameters_Kind {
    /// The standard parameters defined in the released specification.
    ///
    /// This is the value expected for all real-world use.
    #[strum(to_string = "standard parameters")]
    Standard_Parameters,

    /// Some parameters that were generated according to the requirements of some spec,
    /// but may not match the standard parameters.
    #[strum(to_string = "NONSTANDARD parameters")]
    Nonstandard_Parameters,

    /// "Toy" parameters defined in the released specification, or other non-serious parameters.
    #[strum(to_string = "TOY parameters FOR TESTING ONLY")]
    Toy_Parameters,
}

//=================================================================================================|

/// `ElectionGuard Design Specification` version information.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ElectionGuard_DesignSpecification_Version {
    /// Version number.
    pub version_number: [usize; 2],

    /// Version qualifier.
    pub qualifier: ElectionGuard_DesignSpecification_Version_Qualifier,

    /// Kind of [`FixedParameters`].
    pub fixed_parameters_kind: ElectionGuard_FixedParameters_Kind,
}

impl std::fmt::Debug for ElectionGuard_DesignSpecification_Version {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("ElectionGuard_DesignSpecification_Version");
        ds.field("version_number", &self.version_number);
        ds.field("qualifier", &self.qualifier);
        ds.field("fixed_parameters_kind", &self.fixed_parameters_kind);
        ds.field("display", &format_args!("{self}"));
        ds.finish()
    }
}

impl std::fmt::Display for ElectionGuard_DesignSpecification_Version {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [m, n] = self.version_number;

        use ElectionGuard_DesignSpecification_Version_Qualifier as Qualifier;
        match &self.qualifier {
            Qualifier::Released_Specification_Version => {
                write!(f, "ElectionGuard Design Specification v{m}.{n}")?;
            }
            Qualifier::Nonstandard_Specification(s) => {
                write!(f, "NONSTANDARD specification `[{m}, {n}] {s}`")?;
            }
        }

        write!(f, " with {}", self.fixed_parameters_kind)
    }
}

impl SerializableCanonical for ElectionGuard_DesignSpecification_Version {}

crate::impl_knows_friendly_type_name! { ElectionGuard_DesignSpecification_Version }

crate::impl_MayBeValidatableUnsized_for_non_ValidatableUnsized! { ElectionGuard_DesignSpecification_Version }

crate::impl_Resource_for_simple_ResourceId_type! {
    ElectionGuard_DesignSpecification_Version,
    ElectionGuardDesignSpecificationVersion, ConcreteType
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use anyhow::{Context, Result, anyhow, bail, ensure};
    use insta::assert_snapshot;

    #[test_log::test]
    fn t1() {
        use ElectionGuard_DesignSpecification_Version_Qualifier::*;
        assert_snapshot!(Released_Specification_Version, @"released specification version");

        let nonstandard_specification_string = "xyz".to_string();
        assert_snapshot!(Nonstandard_Specification(nonstandard_specification_string), @r###"NONSTANDARD specification "xyz""###);
    }

    #[test_log::test]
    fn t2() {
        use ElectionGuard_FixedParameters_Kind::*;
        assert_snapshot!(Standard_Parameters, @"standard parameters");
        assert_snapshot!(Nonstandard_Parameters, @"NONSTANDARD parameters");
        assert_snapshot!(Toy_Parameters, @"TOY parameters FOR TESTING ONLY");
    }

    #[test_log::test]
    fn t3() {
        let egdsv = ElectionGuard_DesignSpecification_Version {
            version_number: [1234, 56789],
            qualifier:
                ElectionGuard_DesignSpecification_Version_Qualifier::Released_Specification_Version,
            fixed_parameters_kind: ElectionGuard_FixedParameters_Kind::Standard_Parameters,
        };
        assert_snapshot!(egdsv, @"ElectionGuard Design Specification v1234.56789 with standard parameters");

        let egdsv = ElectionGuard_DesignSpecification_Version {
            version_number: [1234, 56789],
            qualifier:
                ElectionGuard_DesignSpecification_Version_Qualifier::Released_Specification_Version,
            fixed_parameters_kind: ElectionGuard_FixedParameters_Kind::Nonstandard_Parameters,
        };
        assert_snapshot!(egdsv, @"ElectionGuard Design Specification v1234.56789 with NONSTANDARD parameters");

        let egdsv = ElectionGuard_DesignSpecification_Version {
            version_number: [1234, 56789],
            qualifier:
                ElectionGuard_DesignSpecification_Version_Qualifier::Released_Specification_Version,
            fixed_parameters_kind: ElectionGuard_FixedParameters_Kind::Toy_Parameters,
        };
        assert_snapshot!(egdsv, @"ElectionGuard Design Specification v1234.56789 with TOY parameters FOR TESTING ONLY");

        let nonstandard_specification_string = "xyz".to_string();
        let egdsv = ElectionGuard_DesignSpecification_Version {
            version_number: [1234, 56789],
            qualifier:
                ElectionGuard_DesignSpecification_Version_Qualifier::Nonstandard_Specification(
                    nonstandard_specification_string.clone(),
                ),
            fixed_parameters_kind: ElectionGuard_FixedParameters_Kind::Standard_Parameters,
        };
        assert_snapshot!(egdsv, @"NONSTANDARD specification `[1234, 56789] xyz` with standard parameters");

        let egdsv = ElectionGuard_DesignSpecification_Version {
            version_number: [1234, 56789],
            qualifier:
                ElectionGuard_DesignSpecification_Version_Qualifier::Nonstandard_Specification(
                    nonstandard_specification_string.clone(),
                ),
            fixed_parameters_kind: ElectionGuard_FixedParameters_Kind::Nonstandard_Parameters,
        };
        assert_snapshot!(egdsv, @"NONSTANDARD specification `[1234, 56789] xyz` with NONSTANDARD parameters");

        let egdsv = ElectionGuard_DesignSpecification_Version {
            version_number: [1234, 56789],
            qualifier:
                ElectionGuard_DesignSpecification_Version_Qualifier::Nonstandard_Specification(
                    nonstandard_specification_string,
                ),
            fixed_parameters_kind: ElectionGuard_FixedParameters_Kind::Toy_Parameters,
        };
        assert_snapshot!(egdsv, @"NONSTANDARD specification `[1234, 56789] xyz` with TOY parameters FOR TESTING ONLY");
    }
}
