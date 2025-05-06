// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides the standard [`FixedParameters`].
//!
//! For details, see ElectionGuard Design Specification v2.1.0:
//!
//! - Sec 3.1.1 pg. 14 Standard Baseline Cryptographic Parameters
//! - Appendix pg. 101 Reduced Parameters—Using a 3072-Bit Prime
//! - Appendix pg. 102 Toy Parameters for Testing Purposes Only

use std::sync::Arc;

use cfg_if::cfg_if;
use num_bigint::BigUint;
use static_assertions::{const_assert, const_assert_eq};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

use util::base16::hex_to_biguint;

use crate::{
    algebra::{Group, ScalarField},
    eg::Eg,
    egds_version::{
        ElectionGuard_DesignSpecification_Version,
        ElectionGuard_DesignSpecification_Version_Qualifier,
    },
    errors::{EgError, EgResult},
    fixed_parameters::{
        FixedParameterGenerationParameters, FixedParameters, FixedParametersInfo,
        FixedParametersTrait, FixedParametersTraitExt, NumsNumber,
    },
    resource::ElectionDataObjectId as EdoId,
    resource::{ProduceResource, ProduceResourceExt},
    validatable::Validated,
};

//=================================================================================================|

#[macro_export]
macro_rules! cfg_parameter {
    ( q_bits_total         ) => { cfg_parameter2!( @all [ p1  ] ) };
    ( ReprTypeQ            ) => { cfg_parameter2!( @all [ p2  ] ) };
    ( p_bits_total         ) => { cfg_parameter2!( @all [ p3  ] ) };
    ( ReprTypeP            ) => { cfg_parameter2!( @all [ p4  ] ) };
    ( p_bits_msb_fixed_1   ) => { cfg_parameter2!( @all [ p5  ] ) };
    ( p_middle_bits_source ) => { cfg_parameter2!( @all [ p6  ] ) };
    ( p_bits_lsb_fixed_1   ) => { cfg_parameter2!( @all [ p7  ] ) };
    ( q                    ) => { cfg_parameter2!( @all [ p8  ] ) };
    ( p                    ) => { cfg_parameter2!( @all [ p9  ] ) };
    ( g                    ) => { cfg_parameter2!( @all [ p10 ] ) };
    ( r                    ) => { cfg_parameter2!( @all [ p11 ] ) };
}

#[cfg(feature = "eg-use-toy-params-q7p16")]
macro_rules! cfg_parameter2 {
    ( @all [ $pn:ident ] ) => {
        cfg_parameter3!( @extract (
            7,  u8,                                 // q bits and type
            16, u16,                                // p bits and type
            3, None, 3,                             // p msb fixed 1's, middle bits src, lsb fixed 1's
            0x_7F_u8,                               // q
            0x_E72F_u16,                            // p
            0x_7F68_u16,                            // g
            0x_01D2_u16,                            // r
        ) $pn )
    };
}

#[cfg(feature = "eg-use-toy-params-q16p32")]
macro_rules! cfg_parameter2 {
    ( @all [ $pn:ident ] ) => {
        cfg_parameter3!( @extract (
            16, u16,                                // q bits and type
            32, u32,                                // p bits and type
            4, None, 4,                             // p msb fixed 1's, middle bits src, lsb fixed 1's
            0x_FFF1_u16,                            // q
            0x_FB2B_475F_u32,                       // p
            0x_1D97_3E8E_u32,                       // g
            0x_0000_FB3E_u32,                       // r
        ) $pn )
    };
}

#[cfg(feature = "eg-use-toy-params-q16p48")]
macro_rules! cfg_parameter2 {
    ( @all [ $pn:ident ] ) => {
        cfg_parameter3!( @extract (
            16, u16,                                // q bits and type
            48, u64,                                // p bits and type
            8, None, 8,                             // p msb fixed 1's, middle bits src, lsb fixed 1's
            0x_FFF1_u16,                            // q
            0x_0000FF93_DF533BFF_u64,               // p
            0x_00006341_7ADFC7BA_u64,               // g
            0x_00000000_FFA2D9DE_u64,               // r
        ) $pn )
    };
}

#[cfg(feature = "eg-use-toy-params-q24p64")]
macro_rules! cfg_parameter2 {
    ( @all [ $pn:ident ] ) => {
        cfg_parameter3!( @extract (
            24, u32,                                // q bits and type
            64, u64,                                // p bits and type
            24, None, 24,                           // p msb fixed 1's, middle bits src, lsb fixed 1's
            0x_FFFFFFFD_u32,                        // q
            0x_FFF93F35_6A395FFF_u128,              // p
            0x_CCCCA8BC_C08F3688_u128,              // g
            0x_000000FF_F9423556_u128,              // r
        ) $pn )
    };
}

#[cfg(feature = "eg-use-toy-params-q32p96")]
macro_rules! cfg_parameter2 {
    ( @all [ $pn:ident ] ) => {
        cfg_parameter3!( @extract (
            32, u32,                                // q bits and type
            96, u128,                               // p bits and type
            16, None, 16,                           // p msb fixed 1's, middle bits src, lsb fixed 1's
            0x_FFFFFFFB_u32,                        // q
            0x_FFFF93C4_6882B6AA_F57CFFFF_u128,     // p
            0x_C469034B_2CE5EC6E_1970350A_u128,     // g
            0x_00000000_FFFF93C9_6880999A_u128,     // r
        ) $pn )
    };
}

#[cfg(feature = "eg-use-toy-params-q32p128")]
macro_rules! cfg_parameter2 {
    ( @all [ $pn:ident ] ) => {
        cfg_parameter3!( @extract (
            32,  u32,                                    // q bits and type
            128, u128,                                   // p bits and type
            32, None, 32,                                // p msb fixed 1's, middle bits src, lsb fixed 1's
            0x_FFFFFFFB_u32,                             // q
            0x_FFFFFFFF_93C46B0F_B6C381D8_FFFFFFFF_u128, // p
            0x_29D99524_0DFB12B3_6FD0F8CC E06B657D_u128, // g
            0x_00000001_00000004_93C46B26_9999999A_u128, // r
        ) $pn )
    };
}

#[cfg(feature = "eg-use-toy-params-q48p192")]
macro_rules! cfg_parameter2 {
    ( @all [ $pn:ident ] ) => {
        cfg_parameter3!( @extract (
            48,  u64,                                                      // q bits and type
            192, u128,                                                     // p bits and type
            64, None, 64,                                                  // p msb fixed 1's, middle bits src, lsb fixed 1's
            0x_0000FFFF_FFFFFFC5_u64,                                      // q
            0x_FFFFFFFF_FFFFFFFF_9ECB7796_49D9A82D_FFFFFFFF_FFFFFFFF_u128, // p
            0x_0B5DA090_0B367E3C_92A11019_54DB5E3C_873E929A_0E324F00_u128, // g
            0x_00000000_00010000_0000003A_FFFF9ECB_852F49C3_4115B1E6_u128, // r
        ) $pn )
    };
}

#[cfg(feature = "eg-use-toy-params-q64p256")]
macro_rules! cfg_parameter2 {
    ( @all [ $pn:ident ] ) => {
        cfg_parameter3!( @extract (
            64,  u64,                                                       // q bits and type
            256, BigUint,                                                   // p bits and type
            64, None, 64,                                                   // p msb fixed 1's, middle bits src, lsb fixed 1's
            0x_FFFFFFFF_FFFFFFC5_u64,                                       // q
            hex_to_biguint("
FFFFFFFF FFFFFFFF 93C467E3 7DB1212B 89995855 493FF059 FFFFFFFF FFFFFFFF "), // p
            hex_to_biguint("
3B543166 9E3E4893 DF745C67 CDCFD95C CDDA2248 78A3CD5D 3226F75C C5A95638 "), // g
            hex_to_biguint("
00000000 00000001 00000000 0000003A 93C467E3 7DB12EAB 97DD49C3 4115B1E6 "), // r
        ) $pn )
    };
}

#[cfg(feature = "eg-use-reduced-params-q256p3072")]
macro_rules! cfg_parameter2 {
    ( @all [ $pn:ident ] ) => {
        cfg_parameter3!( @extract (
            256,  BigUint,                                                  // q bits and type
            3072, BigUint,                                                  // p bits and type
            256, None, 256,                                                 // p msb fixed 1's, middle bits src, lsb fixed 1's
            hex_to_biguint("
FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFF43 "), // q
            hex_to_biguint("
FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
B17217F7 D1CF79AB C9E3B398 03F2F6AF 40F34326 7298B62D 8A0D175B 8BAAFA2B
E7B87620 6DEBAC98 559552FB 4AFA1B10 ED2EAE35 C1382144 27573B29 1169B825
3E96CA16 224AE8C5 1ACBDA11 317C387E B9EA9BC3 B136603B 256FA0EC 7657F74B
72CE87B1 9D6548CA F5DFA6BD 38303248 655FA187 2F20E3A2 DA2D97C5 0F3FD5C6
07F4CA11 FB5BFB90 610D30F8 8FE551A2 EE569D6D FC1EFA15 7D2E23DE 1400B396
17460775 DB8990E5 C943E732 B479CD33 CCCC4E65 9393514C 4C1A1E0B D1D6095D
25669B33 3564A337 6A9C7F8A 5E148E82 074DB601 5CFE7AA3 0C480A54 17350D2C
955D5179 B1E17B9D AE313CDB 6C606CB1 078F735D 1B2DB31B 5F50B518 5064C18B
4D162DB3 B365853D 7598A195 1AE273EE 5570B6C6 8F969834 96D4E6D3 30D6E582
CAB40D66 550984EF 0C42A457 4280B378 45189610 AE3E4BB2 2590A08F 6AD27BFB
FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF "), // p
            hex_to_biguint("
4A1523CB 0111B381 04EBCDE5 163F581E EEDD9163 7AC57544 C1D22832 34272732
FF0CD85F 38539544 3F573701 32A237FF 38702AB0 37F35E7C 7003669D 83697BA1
3BED69B6 3C88BD61 0D33C6A8 9E4882EE 6F849F05 06A4A8F0 B169E5CA 000A21DC
16D7DCEC C69E593C 65967739 3B6CE260 D3D6A578 E74E42A1 B2ADE1ED 8627050C
FB59E604 CAC389E9 9161DA6E 6E9407DF 94517864 01003A8B 7626AC5E 90B888EA
BB5E07E9 96B18662 9B17165F D630E139 788F674D FF4978A6 B74C6D02 0A6570CC
7C7A9E38 21283571 BA3FA1FC C6901A8C 28D02EF8 B8C4B019 F7DDADE5 1A089C57
EF90C2CE 50761754 D778BC9A BFD84809 5C4A0ED0 FA7B7AE5 2CDA4BD6 E2CB16F3
8EDC033F 32F259C5 13DD9E0D 1F780886 D71D7DB8 35F3F08D B11CC9CD 41EB0D5A
37AC6DBA 1A1EBA55 C378BC06 95B9D93A A59903EB A1CE5288 6A0BAAFB 15354863
1BCEAC52 07B97205 BE8FDF83 0F27348C 7AE852F9 F8876887 D23B8054 A077DC8A
EC0BF615 A1FA74BC 727014CF AC40E20E A194489F 63A6C224 27CB999C 9D04AA61 "), // g
            hex_to_biguint("
01
00000000 00000000 00000000 00000000 00000000 00000000 00000000 000000BC
B17217F7 D1CF79AB C9E3B398 03F2F6AF 40F34326 7298B62D 8A0D175B 8BAB857A
E8F42816 5418806C 62B0EA36 355A3A73 E0C74198 5BF6A0E3 130179BF 2F0B43E3
3AD86292 3861B8C9 F768C416 9519600B AD06093F 964B27E0 2D868312 31A9160D
E48F4DA5 3D8AB5E6 9E386B69 4BEC1AE7 22D47579 249D5424 767C5C33 B9151E07
C5C11D10 6AC446D3 30B47DB5 9D352E47 A53157DE 04461900 F6FE360D B897DF53
16D87C94 AE71DAD0 BE84B647 C4BCF818 C23A2D4E BB53C702 A5C8062D 19F5E9B5
033A94F7 FF732F54 12971286 9D97B8C9 6C412921 A9D86797 70F499A0 41C297CF
F79D4C91 49EB6CAF 67B9EA3D C563D965 F3AAD137 7FF22DE9 C3E62068 DD0ED615
1C37B4F7 4634C2BD 09DA912F D599F433 3A8D2CC0 05627DCA 37BAD43E 64CAF318
9FD4A7F5 29FD4A7F 529FD4A7 F529FD4A 7F529FD4 A7F529FD 4A7F529F D4A7F52A "), // r
        ) $pn )
    };
}

#[cfg( not( any( feature = "eg-use-toy-params-q7p16",
                 feature = "eg-use-toy-params-q16p32",
                 feature = "eg-use-toy-params-q16p48",
                 feature = "eg-use-toy-params-q24p64",
                 feature = "eg-use-toy-params-q32p96",
                 feature = "eg-use-toy-params-q32p128",
                 feature = "eg-use-toy-params-q48p192",
                 feature = "eg-use-toy-params-q64p256",
                 feature = "eg-use-reduced-params-q256p3072" ) ) )]
macro_rules! cfg_parameter2 {
    ( @all [ $pn:ident ] ) => {
        cfg_parameter3!( @extract (
            256,  BigUint,                                                  // q bits and type
            4096, BigUint,                                                  // p bits and type
            256, Some(NumsNumber::ln_2), 256,                               // p msb fixed 1's, middle bits src, lsb fixed 1's
            hex_to_biguint("
FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFF43 "), // q
            hex_to_biguint("
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
FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF "), // p
            hex_to_biguint("
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
E7EBA151 BA486094 D68722B0 54633FEC 51CA3F29 B31E77E3 17B178B6 B9D8AE0F "), // g
            hex_to_biguint("
01
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
9FD4A7F5 29FD4A7F 529FD4A7 F529FD4A 7F529FD4 A7F529FD 4A7F529F D4A7F52A "), // r
        ) $pn )
    };
}

macro_rules! cfg_parameter3 {
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p1  ) => {  $p1 };
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p2  ) => {  $p2 };
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p3  ) => {  $p3 };
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p4  ) => {  $p4 };
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p5  ) => {  $p5 };
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p6  ) => {  $p6 };
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p7  ) => {  $p7 };
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p8  ) => {  $p8 };
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p9  ) => {  $p9 };
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p10 ) => { $p10 };
    (@extract ( $p1:literal, $p2:ty, $p3:literal, $p4:ty, $p5:literal, $p6:expr, $p7:literal, $p8:expr, $p9:expr, $p10:expr, $p11:expr, ) p11 ) => { $p11 };
}

/// A [`FixedParametersInfo`] structure for the parameters supported by this build.
///
/// The supported parameter set is configured at build time via Cargo feature flags.
///
pub fn buildcfg_fixed_parameters_info() -> &'static FixedParametersInfo {
    // As the docs for [`std::sync::LazyLock`] explain, this is intentionally not dropped.
    static FPI: std::sync::LazyLock<FixedParametersInfo> = std::sync::LazyLock::new(|| {
        let opt_egds_version = Some(crate::EGDS_VERSION.clone());

        let generation_parameters = FixedParameterGenerationParameters {
            q_bits_total: cfg_parameter!(q_bits_total),
            p_bits_total: cfg_parameter!(p_bits_total),
            p_bits_msb_fixed_1: cfg_parameter!(p_bits_msb_fixed_1),
            p_middle_bits_source: cfg_parameter!(p_middle_bits_source),
            p_bits_lsb_fixed_1: cfg_parameter!(p_bits_lsb_fixed_1),
        };

        let q: cfg_parameter!(ReprTypeQ) = cfg_parameter!(q);
        let p: cfg_parameter!(ReprTypeP) = cfg_parameter!(p);
        let g: cfg_parameter!(ReprTypeP) = cfg_parameter!(g);

        #[allow(clippy::clone_on_copy)]
        let field = ScalarField::new_unchecked(q.clone());

        let group = Group::new_unchecked(p, q, g);

        FixedParametersInfo::new(opt_egds_version, generation_parameters, field, group)
    });
    &FPI
}

/// A [`FixedParametersInfo`] structure for the parameters supported by this build.
///
/// The supported parameter set is configured at build time via Cargo feature flags.
///
pub fn buildcfg_fixed_parameters_info_arc() -> Arc<FixedParametersInfo> {
    // As the docs for [`std::sync::LazyLock`] explain, this is intentionally not dropped.
    static ARC_FPI: std::sync::LazyLock<Arc<FixedParametersInfo>> =
        std::sync::LazyLock::new(|| Arc::new(buildcfg_fixed_parameters_info().clone()));
    let arc_fpi: &Arc<FixedParametersInfo> = &ARC_FPI;
    arc_fpi.clone()
}

/// Produces a [`FixedParameters`] structure for the parameters supported by this build.
///
/// The supported parameter set is configured at build time via Cargo feature flags.
#[instrument(
    name = "eg::standard_parameters::make_buildcfg_fixedparameters",
    level = "debug",
    skip(produce_resource)
)]
pub fn buildcfg_fixed_parameters(
    produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
) -> EgResult<FixedParameters> {
    let arc_fixed_parameters_info = buildcfg_fixed_parameters_info_arc();
    FixedParameters::try_validate_from_arc(arc_fixed_parameters_info, produce_resource)
}

cfg_if! {
    if #[cfg( feature = "eg-use-reduced-params-q256p3072" )]
    {
    }
    else if #[cfg( any(
        feature = "eg-use-toy-params-q7p16",
        feature = "eg-use-toy-params-q16p32",
        feature = "eg-use-toy-params-q16p48",
        feature = "eg-use-toy-params-q24p64",
        feature = "eg-use-toy-params-q32p96",
        feature = "eg-use-toy-params-q32p128",
        feature = "eg-use-toy-params-q48p192",
        feature = "eg-use-toy-params-q64p256" ) )]
    {
    }
    else {
        const_assert_eq!(cfg_parameter!(q_bits_total), 256);
        const_assert_eq!(cfg_parameter!(p_bits_total), 4096);
    }
}

/// Length of the byte array representation of parameter `q` as specified in
/// EGDS 2.1.0 Section 3.1.1 Standard Baseline Cryptographic Parameters pg. 14 eq. 3.
///
/// This value is unaffected by Cargo feature flags.
pub static EGDS_V2_1_0_RELEASED_STANDARD_PARAMS_Q_LEN_BYTES: usize = 32;

/// Length of the byte array representation of parameter `p` as it is specified in
/// EGDS 2.1.0 Section 3.1.1 Standard Baseline Cryptographic Parameters pg. 14.
///
/// This value is unaffected by Cargo feature flags.
pub static EGDS_V2_1_0_RELEASED_STANDARD_PARAMS_P_LEN_BYTES: usize = 512;

//-------------------------------------------------------------------------------------------------|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;

    use crate::egds_version::ElectionGuard_FixedParameters_Kind;

    /// Validate the result of [`make_buildcfg_fixedparametersinfo()`].
    #[test_log::test]
    fn t_buildcfg_fixedparametersinfo() {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::standard_parameters::t::make_standard_parameters",
        );
        let eg = eg.as_ref();

        let fixed_parameters = buildcfg_fixed_parameters(eg).unwrap();
        check_buildcfg_fixed_parameters(&fixed_parameters);
    }

    cfg_if! {
        if #[cfg( any( feature = "eg-use-toy-params-q7p16",
                       feature = "eg-use-toy-params-q16p32",
                       feature = "eg-use-toy-params-q16p48",
                       feature = "eg-use-toy-params-q24p64",
                       feature = "eg-use-toy-params-q32p96",
                       feature = "eg-use-toy-params-q32p128",
                       feature = "eg-use-toy-params-q48p192",
                       feature = "eg-use-toy-params-q64p256",
                       feature = "eg-use-reduced-params-q256p3072" ) )]
        {
        }
        else {
            /// Validate the standard parameters v2.1.
            #[test_log::test]
            fn t_make_standard_parameters_egds_v2_1() {
                let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                    "eg::standard_parameters::t::t_make_standard_parameters_egds_v2_1",
                );
                let eg = eg.as_ref();

                let standard_parameters = buildcfg_fixed_parameters(eg).unwrap();

                check_buildcfg_fixed_parameters(&standard_parameters);

                let egds_version = standard_parameters.opt_egds_version().as_ref().unwrap();
                assert!(matches!(
                    egds_version,
                    ElectionGuard_DesignSpecification_Version {
                        version_number: [ 2, 1 ],
                        qualifier: ElectionGuard_DesignSpecification_Version_Qualifier::Released_Specification_Version,
                        fixed_parameters_kind: ElectionGuard_FixedParameters_Kind::Standard_Parameters,
                    }
                ));

                let generation_parameters = standard_parameters.generation_parameters();
                assert_eq!(generation_parameters.q_bits_total, 256);
                assert_eq!(generation_parameters.p_bits_total, 4096);
            }
        }
    }

    #[allow(clippy::useless_conversion)]
    fn check_buildcfg_fixed_parameters(buildcfg_fixed_parameters: &FixedParameters) {
        let egds_version = buildcfg_fixed_parameters
            .opt_egds_version()
            .as_ref()
            .unwrap();
        assert!(matches!(
            egds_version,
            ElectionGuard_DesignSpecification_Version {
                version_number: [ _, _ ],
                qualifier: ElectionGuard_DesignSpecification_Version_Qualifier::Released_Specification_Version,
                fixed_parameters_kind: ElectionGuard_FixedParameters_Kind::Standard_Parameters,
            }
        ));

        let generation_parameters = buildcfg_fixed_parameters.generation_parameters();
        assert_eq!(
            generation_parameters.q_bits_total,
            cfg_parameter!(q_bits_total)
        );
        assert_eq!(
            generation_parameters.p_bits_total,
            cfg_parameter!(p_bits_total)
        );

        assert_eq!(
            buildcfg_fixed_parameters.q(),
            &BigUint::try_from(cfg_parameter!(q)).unwrap()
        );
        assert_eq!(
            buildcfg_fixed_parameters.p(),
            &BigUint::try_from(cfg_parameter!(p)).unwrap()
        );
        assert_eq!(
            buildcfg_fixed_parameters.g(),
            &BigUint::try_from(cfg_parameter!(g)).unwrap()
        );
    }
}
