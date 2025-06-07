// Copyright (C) Microsoft Corporation. All rights reserved.
//     MIT License
//
//    Copyright (c) Microsoft Corporation.
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE

//     MIT License
//
//    Copyright (c) Microsoft Corporation.
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)] // Those are the best kind

#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code

mod time_fns_00;

//use std::borrow::Cow;
//use std::collections::HashSet;
//use std::convert::AsRef;
//use std::io::{BufRead, Cursor};
//use std::mem::{size_of, size_of_val};
use std::ops::DerefMut;
//use std::path::{Path, PathBuf};
//use std::str::FromStr;
//use std::sync::OnceLock;

use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
use diesel::prelude::*;
use log::{debug, error, info, trace, warn};
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};

pub use fixed_width_nonnegative::types::CowStaticStr;

use fixed_width_nonnegative::{
    power_of_two::TwoRaisedToANonnegativePower,
    types::{
        all_numimpls, all_types, LimbType, NumericImpl, NumericImplExt, Subtype, TypeInfo,
        TypeInfoExt, TypeInfoFixedSizeLimbArray,
    },
};

use fixed_width_nn_bench_db::{
    db::{self, db_conn_lock},
    db_models::*,
};

//=================================================================================================|

fn main() -> Result<()> {
    logging::init("fwnn-bench");
    info!("Program started");
    logging::demo_active_levels();

    let r = main2();
    logging::demo_active_levels();
    match &r {
        Ok(_) => {
            info!("Exit: success");
        }
        Err(e) => {
            error!("{e}");
            for cause in e.chain() {
                error!("cause: {cause}");
            }
        }
    };
    r
}

/*
pub(crate) struct NumimplTypeInfo {
    numimpl_ix: usize,
    numimpl_crate_name: &'static str,
    //numimpl_supported_subtypes: &'static [Subtype],
    numimpl_repr_is_fixed_size_limbs_array: bool,
    //numimpl_can_support_multiple_limb_types: bool,
    //numimpl_supported_limb_types: &'static [LimbType],
    //numimpl_supported_bits: &'static [usize],
    //numimpl_supports_secure_zeroize: bool,
    type_info_ix: usize,
    type_module_name: String,
    type_name: String,
    limb_type: LimbType,
    is_fixed_sized_limb_array: bool,
    subtype: Subtype,
    bits: usize,
    zeroize: bool,
}

impl NumimplTypeInfo {
    #[rustfmt::skip]
    fn to_string(&self) -> String {
/*
  supported_subtypes: {:?},
  can_support_multiple_limb_types: {:?},
  supported_limb_types: {:?},
  supported_bits: {:?},
  supports_secure_zeroize: {:?},
// */
        format!(
r##"NumimplTypeInfo {{
  numimpl_ix: {},
  crate_name: {:?},
  repr_is_fixed_size_limbs_array: {:?},
  type_info_ix: {},
  type_module_name: {:?},
  type_name: {:?},
  limb_type: {:?},
  is_fixed_sized_limb_array: {:?},
  subtype: {:?},
  bits: {:?},
  zeroize: {:?},
}}"##,
            self.numimpl_ix,
            self.numimpl_crate_name,
            //self.numimpl_supported_subtypes,
            self.numimpl_repr_is_fixed_size_limbs_array,
            //self.numimpl_can_support_multiple_limb_types,
            //self.numimpl_supported_limb_types,
            //self.numimpl_supported_bits,
            //self.numimpl_supports_secure_zeroize,
            self.type_info_ix,
            self.type_module_name,
            self.type_name,
            self.limb_type,
            self.is_fixed_sized_limb_array,
            self.subtype,
            self.bits,
            self.zeroize,
        )
    }
}
// */

macro_rules! cb_for_each_nonnegative_type_make_unique_test_mod {
    (
        $test_module_name:ident,
        $numimpl_ix:tt,
        $type_info_ix:tt,
        $module_name:ident,
        $module_name_fq:path,
        $type_name:ident,
        $type_name_fq:path,
        $bits:tt,
    ) => {
        /*
        const TEST_MODULE_NAME: &'static str = stringify!($test_module_name);

        pub(crate) fn new_numimpl_type_info() -> super::super::NumimplTypeInfo {
            use fixed_width_nonnegative::types::{NumericImpl, TypeInfo};
            let numimpl = ::fixed_width_nonnegative::types::all_numimpls()[$numimpl_ix];
            let type_info = ::fixed_width_nonnegative::types::all_types()[$type_info_ix];

            super::super::NumimplTypeInfo {
                numimpl_ix: $numimpl_ix,
                numimpl_crate_name: numimpl.crate_name(),
                //numimpl_supported_subtypes: numimpl.supported_subtypes(),
                numimpl_repr_is_fixed_size_limbs_array: numimpl.repr_is_fixed_size_limbs_array(),
                //numimpl_can_support_multiple_limb_types: numimpl.can_support_multiple_limb_types(),
                //numimpl_supported_limb_types: numimpl.supported_limb_types(),
                //numimpl_supported_bits: numimpl.supported_bits(),
                //numimpl_supports_secure_zeroize: numimpl.supports_secure_zeroize(),
                type_info_ix: $type_info_ix,
                type_module_name: type_info.module_name().to_string(),
                type_name: type_info.type_name().to_string(),
                limb_type: type_info.limb_type(),
                is_fixed_sized_limb_array: type_info.type_info_fsla_opt().is_some(),
                subtype: type_info.subtype(),
                bits: type_info.bits(),
                zeroize: type_info.zeroize(),
            }
        }
        // */
    };
}

mod test_mods {
    fixed_width_nonnegative::for_each_nonnegative_type_make_unique_test_mod!(
        cb_for_each_nonnegative_type_make_unique_test_mod()
    );
}

/*
pub(crate) fn make_numimpl_type_infos() -> Vec<NumimplTypeInfo> {
    let mut v = vec![];
    macro_rules! cb_for_each_nonnegative_type_about_unique_test_mod {
        (
            $test_module_name:ident,
            $numimpl_ix:literal,
            $type_info_ix:literal,
            $module_name:ident,
            $module_name_fq:path,
            $type_name:ident,
            $type_name_fq:path,
            $bits:literal,
        ) => {
            v.push(crate::test_mods::$test_module_name::new_numimpl_type_info());
        };
    }
    fixed_width_nonnegative::for_each_nonnegative_type_about_unique_test_mod!(
        cb_for_each_nonnegative_type_about_unique_test_mod()
    );
    v
}
// */

//=================================================================================================|

/* pub fn all_buildrs_knownfeatures() -> &'static Vec<KnownFeature> {
    static V: OnceLock<Vec<KnownFeature>> = OnceLock::new();
    V.get_or_init(|| {
    })
}
 */

//=================================================================================================|

fn do_stuff() -> Result<()> {
    use fixed_width_nonnegative::power_of_two::*;

    //let R = TwoRaisedToANonnegativePower::new(4096_u16);
    macro_rules! cb_for_each_nonnegative_type_do_stuff {
    (
        $test_module_name:ident,
        $numimpl_ix:literal,
        $type_info_ix:literal,
        $module_name:ident,
        $module_name_fq:path,
        $limb_type:ident,
        $limb_type_fq:path,
        $type_name:ident,
        $type_name_fq:path,
        $bits:tt,
    ) => {{
        const NUMIMPL_IX: usize = $numimpl_ix;
        const MODULE_NAME: &'static str = stringify!($module_name);
        const MODULE_NAME_FQ: &'static str = stringify!($module_name_fq);
        const LIMB_TYPE: &'static str = stringify!($limb_type);
        const LIMB_TYPE_FQ: &'static str = stringify!($limb_type_fq);
        const TYPE_NAME: &'static str = stringify!($type_name);
        const TYPE_NAME_FQ: &'static str = stringify!($type_name_fq);

        debug!("vvvvvvvvvvvvvvvvvv type_name_fq: {TYPE_NAME_FQ}, limb_type: {LIMB_TYPE} vvvvvvvvvvvvvvvvvv");

        fixed_width_nonnegative::bits_eq_4096! { $bits => {
            let all_ones = // $type_name_fq ::all_ones();
            ::fixed_width_nonnegative::basicarray_u64::Nonnegative_4096::all_ones();
            let s = format!("{:0X}", all_ones);
            assert_eq!(s, "F".repeat(4096/4));
        } };

        debug!("^^^^^^^^^^^^^^^^^^ type_name_fq: {TYPE_NAME_FQ}, limb_type: {LIMB_TYPE} ^^^^^^^^^^^^^^^^^^");
    }};
    }
    fixed_width_nonnegative::for_each_nonnegative_type_about_unique_test_mod!(
        cb_for_each_nonnegative_type_do_stuff()
    );

    /*
    macro_rules! cb_for_each_nonnegative_type_do_stuff {
        (
            $test_module_name:ident,
            $numimpl_ix:literal,
            $type_info_ix:literal,
            $module_name:ident,
            $module_name_fq:path,
            $limb_type:ident,
            $limb_type_fq:path,
            $type_name:ident,
            $type_name_fq:path,
            $bits:tt,
        ) => {{
            debug!("vvvvvvvvvvvvvvvvvv module_name_fq: {MODULE_NAME_S}, limb_type: {LIMB_TYPE_S} vvvvvvvvvvvvvvvvvv");
            fixed_width_nonnegative::bits_eq_4096! { $bits => {
                let p = standard_parameter_p();

                debug!("p: {p:0wid$X}", wid=TEST_HEXDG);
            } };
            debug!("^^^^^^^^^^^^^^^^^^ module_name_fq: {MODULE_NAME_S}, limb_type: {LIMB_TYPE_S} ^^^^^^^^^^^^^^^^^^");
        }};
    }

    fixed_width_nonnegative::for_each_nonnegative_type_about_unique_test_mod!(
        cb_for_each_nonnegative_type_do_stuff()
    );
    // */

    /*
    macro_rules! cb_for_each_numimpl_limbtype_nonnegative_code_block {
        (
            $module_name_fq:path,
            $limb_type_fq:path,
        ) => {
            debug!("vvvvvvvvvvvvvvvvvv module_name_fq: {MODULE_NAME_S}, limb_type: {LIMB_TYPE_S} vvvvvvvvvvvvvvvvvv");
            debug!("numimpl_ix: {NUMIMPL_IX}");
            debug!("module_name: {MODULE_NAME_S}");
            debug!("module_name_fq: {MODULE_NAME_FQ_S}");
            debug!("limb_type: {LIMB_TYPE_S}");
            debug!("limb_type_fq: {LIMB_TYPE_FQ_S}");

            fixed_width_nonnegative::bits_eq_4096!( $bits => {
                let p = standard_parameter_p();

                debug!("p: {p:0wid$X}", wid=TEST_HEXDG);
            });


            /*
            type Nn256 = type_name_fq_for_bits!(256);
            type BasicarrayNonnegative4096 = type_name_fq_for_bits!(4096);
            type BasicarrayMontgomery4096 = type_name_fq_for_bits!(4096);
            type Numbi256 = ::fixed_width_nonnegative::numbigint::Nonnegative_256;
            type Numbi4096 = ::fixed_width_nonnegative::numbigint::Nonnegative_4096;
            type Crybi256 = ::fixed_width_nonnegative::cryptobigint::Nonnegative_256;
            type Crybi4096 = ::fixed_width_nonnegative::cryptobigint::Nonnegative_4096;
            type CrybiU4096 = ::crypto_bigint::U4096;

            debug!("vvvvvvvvvvvvvvvvvv module_name_fq: {MODULE_NAME_S}, limb_type: {LIMB_TYPE_S} vvvvvvvvvvvvvvvvvv");

            let p_biguint: &'static ::num_bigint::BigUint = ::eg::standard_parameters::STANDARD_PARAMETERS.p.as_ref();
            let p_numbi: Numbi4096 = p_biguint.try_into().unwrap();
            let p: BasicarrayNonnegative4096 = BasicarrayNonnegative4096::from(&p_numbi);
            let p_crybi = Crybi4096::from(&p);
            let p_crybi_u4096: &CrybiU4096 = p_crybi.as_ref();
            //debug!("p_numbi = {p_numbi:X}");
            //debug!("p_crybi = {p_crybi:X}");
            //debug!("p_crybi_u4096 = {p_crybi_u4096:X}");
            debug!("p = {p:X}");

            let residue_params = ::crypto_bigint::modular::runtime_mod::DynResidueParams::new(p_crybi_u4096);
            debug!("residue_params = {residue_params:?}");

            let r_inv = {
                let one = ::crypto_bigint::modular::runtime_mod::DynResidue::one(residue_params);
                let mut r = ::crypto_bigint::modular::runtime_mod::DynResidue::new(&CrybiU4096::MAX, residue_params);
                debug!("================================");
                debug!(".");
                debug!(".");
                debug!(".");
                debug!("R - 1 = 2^4096 - 1 (mod p, reg) = {}", r.retrieve());
                debug!("R - 1 = 2^4096 - 1 (mod p, mgf) = {}", r.as_montgomery());
                r += one;
                debug!("R = 2^4096 (mod p, reg) = {}", r.retrieve());
                debug!("R = 2^4096 (mod p, mgf) = {}", r.as_montgomery());
                let (r_inv, success) = r.invert();
                if ! Into::<bool>::into(success) {
                    bail!("Couldn't invert 1 << 4096?");
                }
                debug!("R^-1 (mod p, reg) = {}", r_inv.retrieve());
                debug!("R^-1 (mod p, mgf) = {}", r_inv.as_montgomery());

                r_inv
            };


            // p =                       FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB17217F7D1CF79ABC9E3B39803F2F6AF40F343267298B62D8A0D175B8BAAFA2BE7B876206DEBAC98559552FB4AFA1B10ED2EAE35C138214427573B291169B8253E96CA16224AE8C51ACBDA11317C387EB9EA9BC3B136603B256FA0EC7657F74B72CE87B19D6548CAF5DFA6BD38303248655FA1872F20E3A2DA2D97C50F3FD5C607F4CA11FB5BFB90610D30F88FE551A2EE569D6DFC1EFA157D2E23DE1400B39617460775DB8990E5C943E732B479CD33CCCC4E659393514C4C1A1E0BD1D6095D25669B333564A3376A9C7F8A5E148E82074DB6015CFE7AA30C480A5417350D2C955D5179B1E17B9DAE313CDB6C606CB1078F735D1B2DB31B5F50B5185064C18B4D162DB3B365853D7598A1951AE273EE5570B6C68F96983496D4E6D330AF889B44A02554731CDC8EA17293D1228A4EF98D6F5177FBCF0755268A5C1F9538B98261AFFD446B1CA3CF5E9222B88C66D3C5422183EDC99421090BBB16FAF3D949F236E02B20CEE886B905C128D53D0BD2F9621363196AF503020060E49908391A0C57339BA2BEBA7D052AC5B61CC4E9207CEF2F0CE2D7373958D762265890445744FB5F2DA4B751005892D356890DEFE9CAD9B9D4B713E06162A2D8FDD0DF2FD608FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            // crybi.params.modulus:     FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB17217F7D1CF79ABC9E3B39803F2F6AF40F343267298B62D8A0D175B8BAAFA2BE7B876206DEBAC98559552FB4AFA1B10ED2EAE35C138214427573B291169B8253E96CA16224AE8C51ACBDA11317C387EB9EA9BC3B136603B256FA0EC7657F74B72CE87B19D6548CAF5DFA6BD38303248655FA1872F20E3A2DA2D97C50F3FD5C607F4CA11FB5BFB90610D30F88FE551A2EE569D6DFC1EFA157D2E23DE1400B39617460775DB8990E5C943E732B479CD33CCCC4E659393514C4C1A1E0BD1D6095D25669B333564A3376A9C7F8A5E148E82074DB6015CFE7AA30C480A5417350D2C955D5179B1E17B9DAE313CDB6C606CB1078F735D1B2DB31B5F50B5185064C18B4D162DB3B365853D7598A1951AE273EE5570B6C68F96983496D4E6D330AF889B44A02554731CDC8EA17293D1228A4EF98D6F5177FBCF0755268A5C1F9538B98261AFFD446B1CA3CF5E9222B88C66D3C5422183EDC99421090BBB16FAF3D949F236E02B20CEE886B905C128D53D0BD2F9621363196AF503020060E49908391A0C57339BA2BEBA7D052AC5B61CC4E9207CEF2F0CE2D7373958D762265890445744FB5F2DA4B751005892D356890DEFE9CAD9B9D4B713E06162A2D8FDD0DF2FD608FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            // R = 2^4096 (mod p, reg) = 00000000000000000000000000000000000000000000000000000000000000004E8DE8082E308654361C4C67FC0D0950BF0CBCD98D6749D275F2E8A4745505D4184789DF92145367AA6AAD04B505E4EF12D151CA3EC7DEBBD8A8C4D6EE9647DAC16935E9DDB5173AE53425EECE83C7814615643C4EC99FC4DA905F1389A808B48D31784E629AB7350A205942C7CFCDB79AA05E78D0DF1C5D25D2683AF0C02A39F80B35EE04A4046F9EF2CF07701AAE5D11A9629203E105EA82D1DC21EBFF4C69E8B9F88A24766F1A36BC18CD4B8632CC3333B19A6C6CAEB3B3E5E1F42E29F6A2DA9964CCCA9B5CC895638075A1EB717DF8B249FEA301855CF3B7F5ABE8CAF2D36AA2AE864E1E846251CEC324939F934EF8708CA2E4D24CE4A0AF4AE7AF9B3E74B2E9D24C4C9A7AC28A675E6AE51D8C11AA8F4939706967CB692B192CCF507764BB5FDAAB8CE323715E8D6C2EDD75B1067290AE880430F8AAD975A3E06AC7467D9E5002BB94E35C30A16DDD4773992C3ABDDE7C12366BDEF6F444E9050C26B60DC91FD4DF31177946FA3ED72AC2F42D069DEC9CE6950AFCFDFF9F1B66F7C6E5F3A8CC645D414582FAD53A49E33B16DF8310D0F31D28C8C6A7289DD9A76FBBA8BB04A0D25B48AEFFA76D2CA976F210163526462B48EC1F9E9D5D27022F20D029F70000000000000000000000000000000000000000000000000000000000000001
            // crybi.params.r:           00000000000000000000000000000000000000000000000000000000000000004E8DE8082E308654361C4C67FC0D0950BF0CBCD98D6749D275F2E8A4745505D4184789DF92145367AA6AAD04B505E4EF12D151CA3EC7DEBBD8A8C4D6EE9647DAC16935E9DDB5173AE53425EECE83C7814615643C4EC99FC4DA905F1389A808B48D31784E629AB7350A205942C7CFCDB79AA05E78D0DF1C5D25D2683AF0C02A39F80B35EE04A4046F9EF2CF07701AAE5D11A9629203E105EA82D1DC21EBFF4C69E8B9F88A24766F1A36BC18CD4B8632CC3333B19A6C6CAEB3B3E5E1F42E29F6A2DA9964CCCA9B5CC895638075A1EB717DF8B249FEA301855CF3B7F5ABE8CAF2D36AA2AE864E1E846251CEC324939F934EF8708CA2E4D24CE4A0AF4AE7AF9B3E74B2E9D24C4C9A7AC28A675E6AE51D8C11AA8F4939706967CB692B192CCF507764BB5FDAAB8CE323715E8D6C2EDD75B1067290AE880430F8AAD975A3E06AC7467D9E5002BB94E35C30A16DDD4773992C3ABDDE7C12366BDEF6F444E9050C26B60DC91FD4DF31177946FA3ED72AC2F42D069DEC9CE6950AFCFDFF9F1B66F7C6E5F3A8CC645D414582FAD53A49E33B16DF8310D0F31D28C8C6A7289DD9A76FBBA8BB04A0D25B48AEFFA76D2CA976F210163526462B48EC1F9E9D5D27022F20D029F70000000000000000000000000000000000000000000000000000000000000001
            // R = 2^4096 (mod p, mgf) = F14289EBCA85CA3DD99E8057F9301CC5A59C92E97A366067294BF176AD7B15C467357D5C8D03E48F5FE7184338D54722033785E8B92E7966250711C96064F9FAA429B1A9DB50E5F2B4D89614AB5B3195B687819C0F4DB64E465562A9036C59723F12460273FEC0085982659BEE81DC629D5E684626E421700E34E572634E8C5E210EB9A77B9C0DCE00CE207A180EA6F244D54F6D620FA96D5C53CDF818DB2F517B2FFEC42B03348DF367646BB1310D58F8EFCA728312FE4A6534A7B68799FE8FA2FA72447B34E7ACCC7FA85041E3345CCA9627DA9AD4577D42A40F807940102482C26C413F3840CA020918EBD0EF401F55FEBC3F958F77EDC375B4DC056376E6EC0085BC30E3921B32D3A3C709C659B42F1101D8BD86609BFB1DA2DC4B0651681AE14D904FC4A65BFB97FE85562BFD5BEE75B5CF711F60EF6B03639559D3517D775D2FDABF5E66790CB814FF2DD13C78830AFBA02B46F4F38CD37F5E31D1C90EF8FA156506E0890360A45E70959193D2ABD481E0D74DD6F99BE046B06366886876B2E6B3DDE588B821F749BE08504A23B70889BADE80A3B3A2184FF606CE3E8ED7AF187D9985D50B3AB751E954C0AAC3C0F4B46B044125D3821429F0F620B6925A22318F1F5D22F317E26C8F869BC48E2F9D4D4E2C0D351E267724FD0AD9B901C4C167EC12749DA449E5FBCB6BF39E2B31CB2A39B46CF6652E5953604AEF4FF2
            // crybi.params.r2:          F14289EBCA85CA3DD99E8057F9301CC5A59C92E97A366067294BF176AD7B15C467357D5C8D03E48F5FE7184338D54722033785E8B92E7966250711C96064F9FAA429B1A9DB50E5F2B4D89614AB5B3195B687819C0F4DB64E465562A9036C59723F12460273FEC0085982659BEE81DC629D5E684626E421700E34E572634E8C5E210EB9A77B9C0DCE00CE207A180EA6F244D54F6D620FA96D5C53CDF818DB2F517B2FFEC42B03348DF367646BB1310D58F8EFCA728312FE4A6534A7B68799FE8FA2FA72447B34E7ACCC7FA85041E3345CCA9627DA9AD4577D42A40F807940102482C26C413F3840CA020918EBD0EF401F55FEBC3F958F77EDC375B4DC056376E6EC0085BC30E3921B32D3A3C709C659B42F1101D8BD86609BFB1DA2DC4B0651681AE14D904FC4A65BFB97FE85562BFD5BEE75B5CF711F60EF6B03639559D3517D775D2FDABF5E66790CB814FF2DD13C78830AFBA02B46F4F38CD37F5E31D1C90EF8FA156506E0890360A45E70959193D2ABD481E0D74DD6F99BE046B06366886876B2E6B3DDE588B821F749BE08504A23B70889BADE80A3B3A2184FF606CE3E8ED7AF187D9985D50B3AB751E954C0AAC3C0F4B46B044125D3821429F0F620B6925A22318F1F5D22F317E26C8F869BC48E2F9D4D4E2C0D351E267724FD0AD9B901C4C167EC12749DA449E5FBCB6BF39E2B31CB2A39B46CF6652E5953604AEF4FF2
            // R^-1 (mod p, reg) =       BF9B405D1C28111D456ACF32DC12355CFED23236158F7D0E08954A8DF3978161E60C086BC1B7D5CEB94BA33E8675144B23A08FEE288C52859F283EA3E0CDEF27CE2135E2D48247EE4C4897B8ADACE025A019A63020896CD0FFFC92402604FD0FE1146BB349EF9E766B3DEFFACB048C233D243D38389A100F02919B124321D9C587DA5666111886886CACB21CFAA4526E9F0906E206150704040E433FC37B76587591D7534B5DCDAF892C63D8B295B043EA4C8B3D45CB41B0881A5DB3E37D76C342942411C34CE98D8357D24304D0978E4EFD12121189E8334DE1AF2FA77E9D961E0FC19A9BDA50823B21301C842CE8D5FBA9E9149DCF6A821B66F2D67443DAB030FE5A4665FA142F3AE8F9D0631147A864223CACDE9DD2C8F279C87953F8158AC35CA846B85C0F9E6BC43CD3844FA27F1D6C91FEC8446C9F3CB57FC3B2877E8C4BA7468278C2E6C30D80131D0547EB2B48C5D64341131B3A19CA9326EEB3B291866E7F060C8DF689CEBAD599DD80E0D094C772ABBD792E61D2352985C38C12B6A6E10DD80DDF25DBF7126F1436115424B5875AB84E78658F510EAA11EB33D370AC8B054454EF7153EC3F9575FC5C6BC5A81827569C0340D0BDFFB1A2CCE93C6172493CFD89771BA4C941CA5AF982EE1E6C14A4AA36071B3AD39091AC0A4AA7ABE24D8629D35172BC29D3B48974E8C869BD8C92FE2E25D9EF35AD380BDE4A14EC
            // R^-1 (mod p, mgf) =       0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
            // crybi.params.r3:          078A8C60FFE1E25D8553E341229ABC896E48D3ED001BC6AE8CCD6929322664C49270F2509032008FC41F7881F9B1E6AF828A5A7C640B6A4496CA20A1F0DB3A3F73B9C643AE72D76C4E9DAAE0E46DB5CFE23669306DC54AFC2EE6A70944D5460D82025A365CE5C4498AF26ACF0508028D4B471F92C158725F6F67C1A347A60374EF24085AF20AE98A83F3C0341809F0E95A28F4CA5C2E2C4A00E97B0F485CB3FE2388B5BFC8B41984EBC4C6BD709C0D1E8C07D971D19DDFC9B597C7D9881CF5039D12399A198E8C2E148E79F3054F727416E6DBC4190649A955C5B2C8552185C378E70724E3FC261AF7949F4FC0B367770E588937BC1B572139603A3E19FDB9CF98642A31156B8F4E6E259F8B2CD14F4B313921BE0DBB7E25AD07D8822A64BF7E2F4A254843C548B1FC2E52C35C4D96C5CD3DFD6A46077AE1E169BAF51A395F317A7EB03E35E09C98933E721624EC6E0D49F705C37FD15ECE0C9CE3B00005CB1B0AD30A09156471B97E043FDE5E94EC334171CE979DFF755E0006C8A3E96769A28143F2214C1FB80D66AD3FE98913D024DA08C2A0A614131BC8815C5B8EE9F55D2D52BF42604CC7D149552376789F8E4DCF6E2EA4FBE899137022BD2DB92EC06734D4D02B8168A06220C2271342BDDC44FADAB14DB89D82172AC52B37D7F3734F9324C2F0992DE9A50334BFCA0CC4AFAAE97D309D7F2C92A876AB4378276B91D0
            // crybi.params.mod_neg_inv: Limb(0x0000000000000001) }

            let q_biguint: &'static ::num_bigint::BigUint = ::eg::standard_parameters::STANDARD_PARAMETERS.q.as_ref();
            let q_numbi: Numbi256 = q_biguint.try_into().unwrap();
            let q: Nn256 = q_numbi.into();
            debug!("q = {q:X}");

            */
            debug!("^^^^^^^^^^^^^^^^^^ module_name_fq: {MODULE_NAME_S}, limb_type: {LIMB_TYPE_S} ^^^^^^^^^^^^^^^^^^");
        };
    }

    fixed_width_nonnegative::for_each_numimpl_limbtype_nonnegative_code_block!(
        cb_for_each_numimpl_limbtype_nonnegative_code_block()
    );
    // */

    Ok(())
}

//=================================================================================================|

fn main2() -> Result<()> {
    info!("main2");

    {
        let pb = dotenvy::dotenv().context("dotenvy::dotenv")?;
        info!("Merged env vars from file: {}", pb.display());
    }

    /*
    let v = make_numimpl_type_infos();
    for numimpl_type_info in v.iter() {
        println!("numimpl_type_info: {}", numimpl_type_info.to_string());
    }
    //do_stuff()?;
    // */

    do_stuff2()?;

    Ok(())
}

//=================================================================================================|

fn do_stuff2() -> Result<()> {
    let exe_id = get_exe_id()?;

    //let conn = &mut *db::db_conn_lock()?;

    use fixed_width_nn_bench_db::db_schema::exes::dsl::*;
    let results = exes
        //.filter(published.eq(true))
        //.limit(5)
        .select(Exe::as_select())
        .load(&mut *db_conn_lock()?)
        .expect("Error loading exes");

    println!("Displaying {} exes", results.len());
    for exe in results {
        println!("id: {:?}, file_name: {:?} file_path: {:?}, file_modified_time: {:?}, file_sha256_uchex: {:?}, len_bytes: {}",
            exe.id,
            exe.file_name,
            exe.file_path,
            exe.file_modified_time,
            exe.file_sha256_uchex,
            exe.file_len_bytes );
    }

    Ok(())
}

//-------------------------------------------------------------------------------------------------|

fn get_exe_id() -> Result<i32> {
    let exe_file_pb = std::env::current_exe()?;
    info!("Exe: {}", exe_file_pb.display());

    let exe_file_metadata = exe_file_pb.metadata()
        .with_context(|| format!("Couldn't get filesystem metadata for exe: {}", exe_file_pb.display()))?;

    let exe_file_name = exe_file_pb.file_name()
        .ok_or_else(||anyhow!("No file name: {}", exe_file_pb.display()))?.to_string_lossy();

    let exe_file_path = exe_file_pb.to_string_lossy();
    
    let exe_file_len_bytes: i64 = exe_file_metadata.len().try_into()?;
    
    let exe_file_modified_time = exe_file_metadata.modified()
        .inspect_err(|err| warn!("Couldn't get modification time for exe: {err}"))
        .map(chrono::DateTime::<chrono::Local>::from)?;
    debug!("Exe modified at: {exe_file_modified_time:?}");

    let (exe_file_len_bytes2, exe_file_sha256) = file_sha_256(&exe_file_pb)?;
    assert_eq!(exe_file_len_bytes2, exe_file_len_bytes);
    let exe_file_sha256_uchex = format!("{:X}", exe_file_sha256);

    let exe = db::create_exe(
        &mut *db_conn_lock()?,
        &exe_file_name,
        &exe_file_path,
        exe_file_modified_time,
        &exe_file_sha256_uchex,
        exe_file_len_bytes )?;

    println!("Exe record: {exe:?}");

    Ok(exe.id)
}

//-------------------------------------------------------------------------------------------------|

fn file_sha_256(
    path: &std::path::Path
) -> Result<(i64, ::fixed_width_nonnegative::basicarray_u64::Nonnegative_256)> {
    use sha2::{Digest, Sha256};
    use std::io::Write;

    let mut f = std::fs::File::open(&path)
        .with_context(|| format!("Couldn't open file for reading: {}", path.display()))?;
    let mut h = Sha256::new();
    let cb = std::io::copy(&mut f, &mut h)
        .with_context(|| format!("Couldn't read file: {}", path.display()))?;
    debug!("cb: {cb} bytes");
    let cb: i64 = cb.try_into()?;
    
    //let result = h.finalize();
    let hash_value: [u8; 32] = h.finalize().into();
    //debug!("hash_value: {hash_value:02X}");

    let hash_value = ::fixed_width_nonnegative::basicarray_u64::Nonnegative_256::from_le_bytes_arr(hash_value);
    debug!("hash_value: {hash_value:X}");

    Ok((cb, hash_value))
}

//-------------------------------------------------------------------------------------------------|
