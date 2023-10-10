// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

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

// use std::{borrow::Borrow, rc::Rc};

// use num_bigint::BigUint;
// use num_traits::Num;

// use serde::{Deserialize, Serialize};
// use util::bitwise::{pad_with_zeros, xor};
// use util::{
//     csprng::Csprng,
//     z_mul_prime::{ZMulPrime, ZMulPrimeElem},
// };

// use crate::hash::{eg_h, HVALUE_BYTE_LEN};
// use crate::{
//     election_parameters::ElectionParameters, fixed_parameters::FixedParameters, hash::HValue,
//     nizk::ProofGuardian,
// };
// pub struct Guardian {
//     /// Sequence order
//     pub i: usize,

//     /// Random polynomial
//     pub poly: Polynomial,

//     /// Commitment to the random polynomial
//     pub commitment: Vec<BigUint>,
// }

// #[derive(Debug)]
// pub struct GuardianShare {
//     pub i: u16,
//     c0: BigUint,
//     c1: BigUint,
//     c2: BigUint,
// }

// pub struct Polynomial {
//     q: BigUint,
//     a: Vec<BigUint>,
// }

// impl Serialize for Polynomial {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::ser::Serializer,
//     {
//         (
//             format!("{:0>16}", self.q.to_str_radix(16)),
//             self.a
//                 .iter()
//                 .map(|a| format!("{:0>16}", a.to_str_radix(16)))
//                 .collect::<Vec<String>>(),
//         )
//             .serialize(serializer)
//     }
// }

// impl<'de> Deserialize<'de> for Polynomial {
//     fn deserialize<D>(deserializer: D) -> Result<Polynomial, D::Error>
//     where
//         D: serde::de::Deserializer<'de>,
//     {
//         match <(String, Vec<String>)>::deserialize(deserializer) {
//             Ok((q, a)) => Ok(Polynomial {
//                 q: BigUint::from_str_radix(&q, 16).unwrap(),
//                 a: a.iter()
//                     .map(|a| BigUint::from_str_radix(a, 16).unwrap())
//                     .collect(),
//             }),
//             Err(e) => Err(e),
//         }
//     }
// }

// // /// Aggregates public keys from guardians
// // pub fn aggregate_public_keys(
// //     fixed_parameters: &FixedParameters,
// //     capital_k_i: &[PublicKey],
// // ) -> BigUint {
// //     let mut capital_k = BigUint::from(1 as u8);
// //     for capital_k_i_j in capital_k_i {
// //         capital_k = (&capital_k * &capital_k_i_j.0) % fixed_parameters.p.as_ref();
// //     }
// //     capital_k
// // }

// pub fn verify_share_from(
//     fixed_parameters: &FixedParameters,
//     l: usize,
//     p_i_of_l: &BigUint,
//     capital_k_i: &[BigUint],
// ) -> bool {
//     let lhs = fixed_parameters
//         .g
//         .modpow(p_i_of_l, fixed_parameters.p.borrow());

//     let mut rhs = BigUint::from(1 as u8);
//     let l = BigUint::from(l as usize);
//     for j in 0..capital_k_i.len() {
//         rhs = (rhs * capital_k_i[j].modpow(&l.pow(j as u32), fixed_parameters.p.borrow()))
//             % fixed_parameters.p.as_ref();
//     }

//     lhs == rhs
// }

// impl Serialize for GuardianShare {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::ser::Serializer,
//     {
//         (
//             self.i,
//             self.c0.to_str_radix(16),
//             self.c1.to_str_radix(16),
//             self.c2.to_str_radix(16),
//         )
//             .serialize(serializer)
//     }
// }

// impl<'de> Deserialize<'de> for GuardianShare {
//     fn deserialize<D>(deserializer: D) -> Result<GuardianShare, D::Error>
//     where
//         D: serde::de::Deserializer<'de>,
//     {
//         match <(u16, String, String, String)>::deserialize(deserializer) {
//             Ok((i, c0, c1, c2)) => Ok(GuardianShare {
//                 i: i,
//                 c0: BigUint::from_str_radix(&c0, 16).unwrap(),
//                 c1: BigUint::from_str_radix(&c1, 16).unwrap(),
//                 c2: BigUint::from_str_radix(&c2, 16).unwrap(),
//             }),
//             Err(e) => Err(e),
//         }
//     }
// }

// impl GuardianShare {
//     pub fn to_json(&self) -> String {
//         serde_json::to_string(self).unwrap()
//     }

//     pub fn from_json(json: &str) -> Self {
//         serde_json::from_str(json).unwrap()
//     }
// }

// pub fn shares_to_json(guardian_shares: &[GuardianShare]) -> String {
//     serde_json::to_string(guardian_shares).unwrap()
// }

// pub fn shares_from_json(json: &str) -> Vec<GuardianShare> {
//     serde_json::from_str(json).unwrap()
// }

// impl Polynomial {
//     pub fn new(csprng: &mut Csprng, zmulp: Rc<ZMulPrime>, degree: usize) -> Self {
//         let a = (0..degree + 1)
//             .map(|_| ZMulPrimeElem::new_pick_random(zmulp.clone(), csprng).elem)
//             .collect::<Vec<BigUint>>();
//         Polynomial {
//             a,
//             q: zmulp.p.as_ref().clone(),
//         }
//     }

//     pub fn evaluate(&self, x: &BigUint) -> BigUint {
//         let mut y = BigUint::from(0 as u8);
//         for (j, a_j) in self.a.iter().enumerate() {
//             y = (y + a_j * x.modpow(&BigUint::from(j as usize), &self.q)) % &self.q;
//         }
//         y
//     }

//     pub fn commit(&self, fixed_parameters: &FixedParameters) -> Vec<BigUint> {
//         let mut capital_k = Vec::new();
//         for j in 0..self.a.len() {
//             capital_k.push(
//                 fixed_parameters
//                     .g
//                     .modpow(&self.a[j], fixed_parameters.p.borrow()),
//             );
//         }
//         capital_k
//     }
// }

// impl Serialize for Guardian {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::ser::Serializer,
//     {
//         (
//             self.i,
//             &self.poly,
//             self.commitment
//                 .iter()
//                 .map(|x| x.to_str_radix(16))
//                 .collect::<Vec<String>>(),
//         )
//             .serialize(serializer)
//     }
// }

// impl<'de> Deserialize<'de> for Guardian {
//     fn deserialize<D>(deserializer: D) -> Result<Guardian, D::Error>
//     where
//         D: serde::de::Deserializer<'de>,
//     {
//         match <(usize, Polynomial, Vec<String>)>::deserialize(deserializer) {
//             Ok((i, poly, commitment)) => Ok(Guardian {
//                 i,
//                 poly,
//                 commitment: commitment
//                     .iter()
//                     .map(|x| BigUint::from_str_radix(x, 16).unwrap())
//                     .collect::<Vec<BigUint>>(),
//             }),
//             Err(e) => Err(e),
//         }
//     }
// }

// impl Guardian {
//     pub fn new(csprng: &mut Csprng, election_parameters: &ElectionParameters, i: usize) -> Self {
//         let zmulq = Rc::new(ZMulPrime::new(
//             election_parameters.fixed_parameters.q.clone(),
//         ));
//         let poly = Polynomial::new(
//             csprng,
//             zmulq,
//             election_parameters.varying_parameters.k as usize - 1,
//         );
//         let commitment = poly.commit(&election_parameters.fixed_parameters);
//         Guardian {
//             i,
//             poly,
//             commitment,
//         }
//     }

//     pub fn from_json(s: &str) -> Self {
//         serde_json::from_str(s).unwrap()
//     }

//     pub fn to_json(&self) -> String {
//         serde_json::to_string(self).unwrap()
//     }

//     pub fn public_key(&self) -> PublicKey {
//         PublicKey(self.commitment[0].clone())
//     }

//     fn share_encryption_keys(
//         h_p: &HValue,
//         i: u16,
//         l: u16,
//         capital_k_l: &PublicKey,
//         alpha: &BigUint,
//         beta: &BigUint,
//     ) -> Vec<HValue> {
//         // Equation 14
//         let mut v = vec![0x11];

//         v.extend_from_slice(i.to_be_bytes().as_slice());
//         v.extend_from_slice(l.to_be_bytes().as_slice());
//         v.extend_from_slice(capital_k_l.0.to_bytes_be().as_slice());
//         v.extend_from_slice(alpha.to_bytes_be().as_slice());
//         v.extend_from_slice(beta.to_bytes_be().as_slice());

//         let k_i_l = eg_h(&h_p, &v);

//         let label = "share_enc_keys".as_bytes();
//         let mut context = "share_encrypt".as_bytes().to_vec();
//         context.extend_from_slice(i.to_be_bytes().as_slice());
//         context.extend_from_slice(l.to_be_bytes().as_slice());

//         let mut ret = Vec::new();

//         // Equations 15-16
//         for i in 0..2 {
//             let mut v = vec![i + 1 as u8];
//             v.extend_from_slice(label);
//             v.extend(vec![0x00]);
//             v.extend(context.clone());
//             v.extend(vec![0x02, 0x00]);

//             ret.push(eg_h(&k_i_l, &v));
//         }

//         ret
//     }

//     fn share_mac(k0: HValue, c0: &[u8], c1: &[u8]) -> HValue {
//         let mut v = c0.to_vec();
//         v.extend_from_slice(c1);
//         eg_h(&k0, &v)
//     }

//     pub fn share_for(
//         &self,
//         csprng: &mut Csprng,
//         election_parameters: &ElectionParameters,
//         h_p: &HValue,
//         l: usize,
//         capital_k_l: &PublicKey,
//     ) -> GuardianShare {
//         // let nonce =
//         let zmulq = Rc::new(ZMulPrime::new(
//             election_parameters.fixed_parameters.q.clone(),
//         ));

//         let nonce = ZMulPrimeElem::new_pick_random(zmulq.clone(), csprng);
//         let c0 = election_parameters
//             .fixed_parameters
//             .g
//             .modpow(&nonce.elem, election_parameters.fixed_parameters.p.borrow());
//         let beta = capital_k_l
//             .0
//             .modpow(&nonce.elem, election_parameters.fixed_parameters.p.borrow());

//         let keys =
//             Self::share_encryption_keys(h_p, self.i as u16, l as u16, &capital_k_l, &c0, &beta);

//         let c1 = BigUint::from_bytes_be(
//             xor(
//                 &pad_with_zeros(&self.poly.evaluate(&BigUint::from(l)), HVALUE_BYTE_LEN).as_slice(),
//                 keys[1].0.as_slice(),
//                 32,
//             )
//             .as_slice(),
//         );
//         let c2 = BigUint::from_bytes_be(
//             Self::share_mac(
//                 keys[0],
//                 c0.to_bytes_be().as_slice(),
//                 c1.to_bytes_be().as_slice(),
//             )
//             .0
//             .as_slice(),
//         );

//         GuardianShare {
//             i: l as u16,
//             c0,
//             c1,
//             c2,
//         }
//     }

//     pub fn decrypt_share(
//         &self,
//         election_parameters: &ElectionParameters,
//         h_p: &HValue,
//         l: usize,
//         encrypted_share: &GuardianShare,
//     ) -> BigUint {
//         let beta = encrypted_share.c0.modpow(
//             &self.poly.a[0],
//             election_parameters.fixed_parameters.p.borrow(),
//         );

//         let keys = Self::share_encryption_keys(
//             h_p,
//             l as u16,
//             self.i as u16,
//             &PublicKey(self.commitment[0].clone()),
//             &encrypted_share.c0,
//             &beta,
//         );

//         let mac = BigUint::from_bytes_be(
//             Self::share_mac(
//                 keys[0],
//                 encrypted_share.c0.to_bytes_be().as_slice(),
//                 encrypted_share.c1.to_bytes_be().as_slice(),
//             )
//             .0
//             .as_slice(),
//         );
//         // TODO: Return error
//         if encrypted_share.c2 != mac {
//             // println!("{:?} != {:?}", encrypted_share.c2, mac);
//             BigUint::from(0 as u8)
//         } else {
//             BigUint::from_bytes_be(
//                 xor(
//                     pad_with_zeros(&encrypted_share.c1, HVALUE_BYTE_LEN).as_slice(),
//                     keys[1].0.as_slice(),
//                     32,
//                 )
//                 .as_slice(),
//             )
//         }
//     }

//     pub fn proof_of_knowledge(
//         &self,
//         csprng: &mut Csprng,
//         election_parameters: &ElectionParameters,
//         h_p: HValue,
//         i: u16,
//     ) -> ProofGuardian {
//         let zmulq = Rc::new(ZMulPrime::new(
//             election_parameters.fixed_parameters.q.clone(),
//         ));
//         ProofGuardian::new(
//             csprng,
//             &election_parameters.fixed_parameters,
//             h_p,
//             zmulq,
//             i,
//             election_parameters.varying_parameters.k,
//             self.commitment.as_slice(),
//             self.poly
//                 .a
//                 .iter()
//                 .map(|x| x.clone())
//                 .collect::<Vec<BigUint>>()
//                 .as_slice(),
//         )
//     }

//     pub fn verify_proof_of_knowledge() -> bool {
//         unimplemented!()
//     }
// }
