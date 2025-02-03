// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides the standard [`FixedParameters`].
//! For more details see Section `3.1.1` of the Electionguard specification `2.0.0`. [TODO fix ref]

use num_bigint::BigUint;
use num_traits::Num;
use util::algebra::{Group, ScalarField};

use crate::{
    eg::Eg,
    errors::{EgError, EgResult},
    fixed_parameters::{
        ElectionGuardDesignSpecificationVersion, FixedParameterGenerationParameters,
        FixedParameters, FixedParametersInfo, NumsNumber,
    },
    resource::ElectionDataObjectId as EdoId,
    validatable::Validated,
};

/// Standard parameters for the current version.
pub fn make_standard_parameters(eg: &Eg) -> EgResult<FixedParameters> {
    // The current version is EGDS 2.1
    make_standard_parameters_egds_v2_1(eg)
}

/// Standard parameters, "ElectionGuard Design Specification 2.1 of 2024-08-12"
pub fn make_standard_parameters_egds_v2_1(eg: &Eg) -> EgResult<FixedParameters> {
    let opt_eg_design_specification_version =
        Some(ElectionGuardDesignSpecificationVersion { number: [2, 1] });

    let generation_parameters = FixedParameterGenerationParameters {
        q_bits_total: 256,
        p_bits_total: 4096,
        p_bits_msb_fixed_1: 256,
        p_middle_bits_source: Some(NumsNumber::ln_2),
        p_bits_lsb_fixed_1: 256,
    };

    let field = ScalarField::new_unchecked(hex_to_biguint(
        "
        FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFF43",
    ));

    let group = Group::new_unchecked(
        hex_to_biguint(
            "
            FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
            B17217F7 D1CF79AB C9E3B398 03F2F6AF 40F34326 7298B62D 8A0D175B 8BAAFA2B
            E7B87620 6DEBAC98 559552FB 4AFA1B10 ED2EAE35 C1382144 27573B29 1169B825
            3E96CA16 224AE8C5 1ACBDA11 317C387E B9EA9BC3 B136603B 256FA0EC 7657F74B
            72CE87B1 9D6548CA F5DFA6BD 38303248 655FA187 2F20E3A2 DA2D97C5 0F3FD5C6
            07F4CA11 FB5BFB90 610D30F8 8FE551A2 EE569D6D FC1EFA15 7D2E23DE 1400B396
            17460775 DB8990E5 C943E732 B479CD33 CCCC4E65 9393514C 4C1A1E0B D1D6095D
            25669B33 3564A337 6A9C7F8A 5E148E82 074DB601 5CFE7AA3 0C480A54 17350D2C
            955D5179 B1E17B9D AE313CDB 6C606CB1 078F735D 1B2DB31B 5F50B518 5064C18B
            4D162DB3 B365853D 7598A195 1AE273EE 5570B6C6 8F969834 96D4E6D3 30AF889B
            44A02554 731CDC8E A17293D1 228A4EF9 8D6F5177 FBCF0755 268A5C1F 9538B982
            61AFFD44 6B1CA3CF 5E9222B8 8C66D3C5 422183ED C9942109 0BBB16FA F3D949F2
            36E02B20 CEE886B9 05C128D5 3D0BD2F9 62136319 6AF50302 0060E499 08391A0C
            57339BA2 BEBA7D05 2AC5B61C C4E9207C EF2F0CE2 D7373958 D7622658 90445744
            FB5F2DA4 B7510058 92D35689 0DEFE9CA D9B9D4B7 13E06162 A2D8FDD0 DF2FD608
            FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF",
        ),
        hex_to_biguint(
            "
            FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFF43",
        ),
        hex_to_biguint(
            "
                36036FED 214F3B50 DC566D3A 312FE413 1FEE1C2B CE6D02EA 39B477AC 05F7F885
                F38CFE77 A7E45ACF 4029114C 4D7A9BFE 058BF2F9 95D2479D 3DDA618F FD910D3C
                4236AB2C FDD783A5 016F7465 CF59BBF4 5D24A22F 130F2D04 FE93B2D5 8BB9C1D1
                D27FC9A1 7D2AF49A 779F3FFB DCA22900 C14202EE 6C996160 34BE35CB CDD3E7BB
                7996ADFE 534B63CC A41E21FF 5DC778EB B1B86C53 BFBE9998 7D7AEA07 56237FB4
                0922139F 90A62F2A A8D9AD34 DFF799E3 3C857A64 68D001AC F3B681DB 87DC4242
                755E2AC5 A5027DB8 1984F033 C4D17837 1F273DBB 4FCEA1E6 28C23E52 759BC776
                5728035C EA26B44C 49A65666 889820A4 5C33DD37 EA4A1D00 CB62305C D541BE1E
                8A92685A 07012B1A 20A746C3 591A2DB3 815000D2 AACCFE43 DC49E828 C1ED7387
                466AFD8E 4BF19355 93B2A442 EEC271C5 0AD39F73 3797A1EA 11802A25 57916534
                662A6B7E 9A9E449A 24C8CFF8 09E79A4D 806EB681 119330E6 C57985E3 9B200B48
                93639FDF DEA49F76 AD1ACD99 7EBA1365 7541E79E C57437E5 04EDA9DD 01106151
                6C643FB3 0D6D58AF CCD28B73 FEDA29EC 12B01A5E B86399A5 93A9D5F4 50DE39CB
                92962C5E C6925348 DB54D128 FD99C14B 457F883E C20112A7 5A6A0581 D3D80A3B
                4EF09EC8 6F9552FF DA1653F1 33AA2534 983A6F31 B0EE4697 935A6B1E A2F75B85
                E7EBA151 BA486094 D68722B0 54633FEC 51CA3F29 B31E77E3 17B178B6 B9D8AE0F",
        ),
    );

    let fixed_parameters_info = FixedParametersInfo::new(
        opt_eg_design_specification_version,
        generation_parameters,
        field,
        group,
    );

    let fixed_parameters = FixedParameters::try_validate_from(fixed_parameters_info, eg)?;

    Ok(fixed_parameters)
}

fn hex_to_biguint(s: &str) -> BigUint {
    let s = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();

    // `unwrap()` is justified here because `s` is fixed at compile time.
    #[allow(clippy::unwrap_used)]
    BigUint::from_str_radix(s.as_str(), 16).unwrap()
}

#[allow(clippy::unwrap_used)]
#[cfg(feature = "eg-allow-toy-parameters")]
pub mod test_parameter_do_not_use_in_production {
    use lazy_static::lazy_static;
    use util::algebra::{Group, ScalarField};

    use super::hex_to_biguint;
    use crate::{
        eg::Eg,
        fixed_parameters::{
            FixedParameterGenerationParameters, FixedParameters, FixedParametersInfo,
        },
        validatable::Validated,
    };

    lazy_static! {
        /// Standard parameters, ElectionGuard latest (currently v2.1).
        pub static ref TOY_PARAMETERS_01: FixedParameters = make_toy_parameters_1();
    }

    pub fn make_toy_parameters_1() -> FixedParameters {
        let eg = &Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::standard_parameters::t::make_toy_parameters_1",
        );

        let opt_eg_design_specification_version = None;
        let generation_parameters = FixedParameterGenerationParameters {
            q_bits_total: 7,
            p_bits_total: 16,
            p_bits_msb_fixed_1: 0,
            p_middle_bits_source: None,
            p_bits_lsb_fixed_1: 0,
        };

        let field = ScalarField::new_unchecked(hex_to_biguint("007F"));

        let group = Group::new_unchecked(
            hex_to_biguint("E72F"),
            hex_to_biguint("007F"),
            hex_to_biguint("7F68"),
        );

        let fixed_parameters_info = FixedParametersInfo::new(
            opt_eg_design_specification_version,
            generation_parameters,
            field,
            group,
        );

        FixedParameters::try_validate_from(fixed_parameters_info, eg).unwrap()
    }
}

//-------------------------------------------------------------------------------------------------|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::ElectionGuardDesignSpecificationVersion;
    use crate::{eg::Eg, errors::EgResult, validatable::Validated};

    /// Validate the standard parameters v2.1.
    //? TODO #[cfg(not(debug_assertions))] // This test is too slow without optimizations.
    #[test]
    fn make_standard_parameters_egds_v2_1() -> EgResult<()> {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::standard_parameters::t::make_standard_parameters_egds_v2_1",
        );

        let standard_parameters = super::make_standard_parameters_egds_v2_1(&eg)?;
        assert!(matches!(
            standard_parameters.opt_eg_design_specification_version(),
            Some(ElectionGuardDesignSpecificationVersion { number: [2, 1] })
        ));

        assert!(standard_parameters.re_validate(&eg).is_ok());

        Ok(())
    }

    /// Validate the result of [`make_standard_parameters()`].
    //? TODO #[cfg(not(debug_assertions))] // This test is too slow without optimizations.
    #[test]
    fn make_standard_parameters() -> EgResult<()> {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::standard_parameters::t::make_standard_parameters",
        );

        let standard_parameters = super::make_standard_parameters(&eg)?;
        assert!(matches!(
            standard_parameters.opt_eg_design_specification_version(),
            Some(ElectionGuardDesignSpecificationVersion { number: [2, 1] })
        ));

        assert!(standard_parameters.re_validate(&eg).is_ok());

        Ok(())
    }
}
