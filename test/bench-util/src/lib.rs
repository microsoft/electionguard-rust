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


#![allow(clippy::assertions_on_constants)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code

use anyhow::{anyhow, bail, ensure, Context, Result};
use crypto_bigint::Zero;

pub type CheapPrng = rand_pcg::Mcg128Xsl64; // 128 bit size

#[allow(non_snake_case)]
pub fn CheapPrng_new<Seed: AsRef<[u8]>>(seed: &Seed) -> CheapPrng {
    let mut csprng = util::csprng::Csprng::new(seed.as_ref());
    CheapPrng_from_u128(csprng.next_u128())
}

#[allow(non_snake_case)]
pub fn CheapPrng_from_u128(state: u128) -> CheapPrng {
    CheapPrng::new(state)
}

//=================================================================================================|

pub type crybi_U4096 = ::crypto_bigint::U4096;
pub type crybi_DynResidueParams_4096 = ::crypto_bigint::modular::runtime_mod::DynResidueParams<{crybi_U4096::LIMBS}>;
pub type crybi_DynResidue_4096 = ::crypto_bigint::modular::runtime_mod::DynResidue<{crybi_U4096::LIMBS}>;
pub type crybi_Nonnegative_4096 = fixed_width_nonnegative::cryptobigint::Nonnegative_4096;

pub type crybi_Word = ::crypto_bigint::Word;
pub type crybi_U256 = ::crypto_bigint::U256;

//=================================================================================================|

pub fn standard_parameter_p() -> &'static ::fixed_width_nonnegative::basicarray_u64::Nonnegative_4096 {
    use ::std::sync::OnceLock;
    static N: OnceLock<::fixed_width_nonnegative::basicarray_u64::Nonnegative_4096> =
        OnceLock::new();
    N.get_or_init(|| {
        let p_biguint: &'static ::num_bigint::BigUint =
            ::eg::standard_parameters::STANDARD_PARAMETERS.group.modulus();
        let p_numbi: ::fixed_width_nonnegative::numbigint::Nonnegative_4096 =
            p_biguint.try_into().unwrap();
        p_numbi.into()
    })
}

pub fn standard_parameter_p_dynresidueparams() -> &'static crybi_DynResidueParams_4096 {
    use ::std::sync::OnceLock;
    static N: OnceLock<crybi_DynResidueParams_4096> = OnceLock::new();
    N.get_or_init(|| {
        let p: crybi_Nonnegative_4096 = standard_parameter_p().into();
        let p_crybi: &crybi_U4096 = p.as_ref();
        crybi_DynResidueParams_4096::new(p_crybi)
    })
}

pub fn standard_parameter_p_dynresidueparams_cloned() -> crybi_DynResidueParams_4096 {
    standard_parameter_p_dynresidueparams().clone()
}

pub fn standard_parameter_g() -> &'static ::fixed_width_nonnegative::basicarray_u64::Nonnegative_4096 {
    use ::std::sync::OnceLock;
    static N: OnceLock<::fixed_width_nonnegative::basicarray_u64::Nonnegative_4096> =
        OnceLock::new();
    N.get_or_init(|| {
        let p_biguint: &::num_bigint::BigUint = &::eg::standard_parameters::STANDARD_PARAMETERS.g();
        let p_numbi: ::fixed_width_nonnegative::numbigint::Nonnegative_4096 =
            p_biguint.try_into().unwrap();
        p_numbi.into()
    })
}

pub fn standard_parameter_g_dynresidue_mod_p() -> &'static crybi_DynResidue_4096 {
    use ::std::sync::OnceLock;
    static N: OnceLock<crybi_DynResidue_4096> = OnceLock::new();
    N.get_or_init(|| {
        let g_crybi: crybi_Nonnegative_4096 = standard_parameter_g().into();
        let g_crybi: &crybi_U4096 = g_crybi.as_ref();
        let p_crypbi_dynresidueparams = standard_parameter_p_dynresidueparams_cloned();
        crybi_DynResidue_4096::new(&g_crybi, p_crypbi_dynresidueparams)
    })
}

pub fn standard_parameter_q() -> &'static ::fixed_width_nonnegative::basicarray_u64::Nonnegative_256 {
    use ::std::sync::OnceLock;
    static N: OnceLock<::fixed_width_nonnegative::basicarray_u64::Nonnegative_256> =
        OnceLock::new();
    N.get_or_init(|| {
        let q_biguint: &'static ::num_bigint::BigUint =
            ::eg::standard_parameters::STANDARD_PARAMETERS.group.order();
        let q_numbi: ::fixed_width_nonnegative::numbigint::Nonnegative_256 =
            q_biguint.try_into().unwrap();
        q_numbi.into()
    })
}

pub fn standard_parameter_exptable_g_p_4() -> &'static ExpTable4096 {
    use ::std::sync::OnceLock;
    static N: OnceLock<ExpTable4096> = OnceLock::new();
    N.get_or_init(|| {
        let p: crybi_Nonnegative_4096 = standard_parameter_p().into();
        let g: crybi_Nonnegative_4096 = standard_parameter_g().into();
        ExpTable4096::new(
            g,
            standard_parameter_p_dynresidueparams_cloned(),
            4
        ).unwrap()
    })
}

//=================================================================================================|

pub fn eprintln_here() -> &'static bool
{
    use ::std::sync::OnceLock;
    static N: OnceLock<bool> = OnceLock::new();
    N.get_or_init(|| {
        eprintln!("here");
        true
    })
}

pub fn eprintln_there() -> &'static bool
{
    use ::std::sync::OnceLock;
    static N: OnceLock<bool> = OnceLock::new();
    N.get_or_init(|| {
        eprintln!("there");
        true
    })
}

//=================================================================================================|

#[derive(Clone)]
pub struct ExpTable4096 {
    base: crybi_Nonnegative_4096,
    modulus_dynresidueparams: crybi_DynResidueParams_4096,
    bits_per_col: u8,
    base_crybi_dynresidue: crybi_DynResidue_4096,
    cols: u16,
    rows: u16,
    bits_mask: crybi_Word,
    v: Vec<crybi_DynResidue_4096>,
}

impl ExpTable4096 {
    pub fn new(
        base: crybi_Nonnegative_4096,
        modulus_dynresidueparams: crybi_DynResidueParams_4096,
        bits_per_col: usize,
    ) -> Result<Self> {
        ensure!((1..=15).contains(&bits_per_col));
        let bits_per_col = bits_per_col as u8;
        let bits_per_col_usize: usize = bits_per_col.into();

        let base_crybi_dynresidue = crybi_DynResidue_4096::new(
            base.as_ref(), modulus_dynresidueparams);

        let exponent_bits: u16 = crybi_U256::BITS.try_into()?;
        ensure!(exponent_bits != 0);

        let cols = exponent_bits.div_ceil(bits_per_col.into());
        ensure!(cols != 0);

        let rows: u16 = (1_u32 << bits_per_col).try_into()?;
        ensure!(rows != 0);
        let rows: u16 = rows.try_into()?;

        let mut v = Vec::with_capacity(rows as usize * cols as usize);

        let one = crybi_DynResidue_4096::new(&crybi_U4096::ONE, modulus_dynresidueparams);

        for col in 0_u16..cols {
            let mut shift = 0_usize;

            v.push(one);

            for row in 1_u16..rows {
                let exponent = crybi_U256::from(row) << shift;
                v.push(base_crybi_dynresidue.pow(&exponent));
            }

            shift += bits_per_col_usize;
        }

        let bits_mask = (crybi_Word::from(1_u8) << bits_per_col) - 1;

        Ok(ExpTable4096 {
            base,
            modulus_dynresidueparams,
            bits_per_col,
            base_crybi_dynresidue,
            cols,
            rows,
            bits_mask,
            v,
        })
    }

    pub fn pow(&self, exp: crybi_U256) -> Result<crybi_DynResidue_4096> {
        let mut exp = exp;
        let mut exponent_bits: u16 = exp.bits().try_into()?;

        let bits_per_col_usize: usize = self.bits_per_col.into();
        assert!(bits_per_col_usize < std::mem::size_of::<::crypto_bigint::Word>()*8);

        let mut n = crybi_DynResidue_4096::new(&crybi_U4096::ONE, self.modulus_dynresidueparams);

        let rows: usize = self.rows.into();

        let mut col_ix = 0_usize;
        while exponent_bits != 0 {
            let row_ix = (exp.as_words()[0] & self.bits_mask) as usize;

            debug_assert!((0..rows).contains(&row_ix));

            let ix = col_ix*rows + row_ix;
            debug_assert!(ix < self.v.len());

            n *= self.v[ix];

            exp >>= self.bits_per_col.into();
            exponent_bits = exponent_bits.saturating_sub(self.bits_per_col.into());
            col_ix += 1;
        }

        Ok(n)
    }

    /// Gets something from the table. This is so the compiler can't optimize stuff out.
    pub fn get_something<R: ::rand::Rng>(&self, rng: &mut R) -> u64 {
        use ::rand::Rng;
        if self.v.len() != 0 {
            let ix = rng.gen_range(0..self.v.len());
            let dynresidue = &self.v[ix];
            let words = dynresidue.as_montgomery().as_words();
            if words.len() != 0 {
                let ix = rng.gen_range(0..words.len());
                return words[ix] as u64
            }
        }
        0_u64
    }
}
