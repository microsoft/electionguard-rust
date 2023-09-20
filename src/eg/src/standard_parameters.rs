// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::Num;

use util::prime::BigUintPrime;

use crate::fixed_parameters::{
    ElectionGuardDesignSpecificationVersion, FixedParameterGenerationParameters, FixedParameters,
    NumsNumber, OfficialReleaseKind, OfficialVersion,
};

lazy_static! {
    /// Standard parameters, ElectionGuard latest (currently v2.0).
    pub static ref STANDARD_PARAMETERS: FixedParameters = make_standard_parameters_MSR_ElectionGuard_Design_Specification_v2_0();
}

/// Standard parameters, "MSR ElectionGuard Design Specification 2.0 of 2023-08-16"
#[allow(non_snake_case)]
pub fn make_standard_parameters_MSR_ElectionGuard_Design_Specification_v2_0() -> FixedParameters {
    let egds_ver = ElectionGuardDesignSpecificationVersion::Official(OfficialVersion {
        version: [2, 0],
        release: OfficialReleaseKind::Release,
    });

    FixedParameters {
        opt_ElectionGuard_Design_Specification: Some(egds_ver),

        generation_parameters: FixedParameterGenerationParameters {
            q_bits_total: 256,
            p_bits_total: 4096,
            p_bits_msb_fixed_1: 256,
            p_middle_bits_source: NumsNumber::ln_2,
            p_bits_lsb_fixed_1: 256,
        },
        p: BigUintPrime::new_unchecked_the_caller_guarantees_that_this_number_is_prime(
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
        ),
        q: BigUintPrime::new_unchecked_the_caller_guarantees_that_this_number_is_prime(
            hex_to_biguint(
                "
                FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFF43",
            ),
        ),
        r: hex_to_biguint(
            "
                1
                00000000 00000000 00000000 00000000 00000000 00000000 00000000 000000BC
                B17217F7 D1CF79AB C9E3B398 03F2F6AF 40F34326 7298B62D 8A0D175B 8BAB857A
                E8F42816 5418806C 62B0EA36 355A3A73 E0C74198 5BF6A0E3 130179BF 2F0B43E3
                3AD86292 3861B8C9 F768C416 9519600B AD06093F 964B27E0 2D868312 31A9160D
                E48F4DA5 3D8AB5E6 9E386B69 4BEC1AE7 22D47579 249D5424 767C5C33 B9151E07
                C5C11D10 6AC446D3 30B47DB5 9D352E47 A53157DE 04461900 F6FE360D B897DF53
                16D87C94 AE71DAD0 BE84B647 C4BCF818 C23A2D4E BB53C702 A5C8062D 19F5E9B5
                033A94F7 FF732F54 12971286 9D97B8C9 6C412921 A9D86797 70F499A0 41C297CF
                F79D4C91 49EB6CAF 67B9EA3D C563D965 F3AAD137 7FF22DE9 C3E62068 DD0ED615
                1C37B4F7 4634C2BD 09DA912F D599F433 3A8D2CC0 05627DCA 37BAD43E 64A39631
                19C0BFE3 4810A21E E7CFC421 D53398CB C7A95B3B F585E5A0 4B790E2F E1FE9BC2
                64FDA810 9F6454A0 82F5EFB2 F37EA237 AA29DF32 0D6EA860 C41A9054 CCD24876
                C6253F66 7BFB0139 B5531FF3 01899612 02FD2B0D 55A75272 C7FD7334 3F7899BC
                A0B36A4C 470A64A0 09244C84 E77CEBC9 2417D5BB 13BF1816 7D8033EB 6C4DD787
                9FD4A7F5 29FD4A7F 529FD4A7 F529FD4A 7F529FD4 A7F529FD 4A7F529F D4A7F52A",
        ),
        g: hex_to_biguint(
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
    }
}

fn hex_to_biguint(s: &str) -> BigUint {
    let s = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();

    // `unwrap()` is justified here because `s` is fixed at compile time.
    #[allow(clippy::unwrap_used)]
    BigUint::from_str_radix(s.as_str(), 16).unwrap()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;

    /// Validate the standard parameters v2.0.
    #[cfg(not(debug_assertions))] // This test is too slow without optimizations.
    #[test]
    fn standard_parameters_v2_0() {
        let mut csprng = util::csprng::Csprng::new(b"test::standard_parameters_v2_0");

        let fixed_params = make_standard_parameters_MSR_ElectionGuard_Design_Specification_v2_0();
        assert!(matches!(
            fixed_params.opt_ElectionGuard_Design_Specification,
            Some(ElectionGuardDesignSpecificationVersion::Official(
                OfficialVersion {
                    version: [2, 0],
                    release: OfficialReleaseKind::Release
                }
            ))
        ));
        assert!(fixed_params.validate(&mut csprng).is_ok());
    }

    /// Verify that `pub static STANDARD_PARAMETERS` reflect the latest version (currently v2.0).
    #[test]
    fn standard_parameters_pub_static() {
        // Latest standard parameters are v2.0.
        assert_eq!(
            &*STANDARD_PARAMETERS,
            &make_standard_parameters_MSR_ElectionGuard_Design_Specification_v2_0()
        );
    }
}
