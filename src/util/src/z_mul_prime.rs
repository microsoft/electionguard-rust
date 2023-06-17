// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::ops::{Mul, Sub, SubAssign};
use std::rc::Rc;
use std::{borrow::Borrow, ops::Add};

use num_bigint::BigUint;
use num_traits::{One, Pow, Zero};

use crate::{csprng::Csprng, prime::BigUintPrime};

// The set {1, 2, 3, ..., p − 1} where p is prime, .
#[derive(Debug, PartialEq, Eq)]
pub struct ZMulPrime {
    pub p: BigUintPrime,
}

impl ZMulPrime {
    pub fn new(p: BigUintPrime) -> ZMulPrime {
        ZMulPrime { p }
    }

    pub fn new_random(bits: usize, csprng: &mut Csprng) -> ZMulPrime {
        let p = BigUintPrime::new_random_prime(bits, csprng);
        ZMulPrime { p }
    }

    pub fn try_new_elem(self: Rc<Self>, n: BigUint) -> Option<ZMulPrimeElem> {
        ZMulPrimeElem::try_new(self, n)
    }

    pub fn pick_random_elem(self: Rc<Self>, csprng: &mut Csprng) -> ZMulPrimeElem {
        ZMulPrimeElem::new_pick_random(self, csprng)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ZMulPrimeElem {
    pub zmulp: Rc<ZMulPrime>,
    pub elem: BigUint,
}

impl ZMulPrimeElem {
    pub fn try_new(zmulp: Rc<ZMulPrime>, n: BigUint) -> Option<ZMulPrimeElem> {
        if n != BigUint::zero() && &n < zmulp.p.borrow() {
            let elem = ZMulPrimeElem { zmulp, elem: n };
            Some(elem)
        } else {
            None
        }
    }

    pub fn new_pick_random(zmulp: Rc<ZMulPrime>, csprng: &mut Csprng) -> ZMulPrimeElem {
        let elem = csprng.next_biguint_range(&BigUint::one(), zmulp.p.borrow());
        ZMulPrimeElem { zmulp, elem }
    }
}

impl Borrow<BigUint> for ZMulPrimeElem {
    #[inline]
    fn borrow(&self) -> &BigUint {
        &self.elem
    }
}

impl<'a, 'b> Pow<&'b BigUint> for &'a ZMulPrimeElem {
    type Output = ZMulPrimeElem;

    fn pow(self: &'a ZMulPrimeElem, exponent: &BigUint) -> Self::Output {
        ZMulPrimeElem {
            zmulp: self.zmulp.clone(),
            elem: self.elem.modpow(exponent, self.zmulp.p.borrow()),
        }
    }
}

impl<'a> Add<&ZMulPrimeElem> for &'a ZMulPrimeElem {
    type Output = ZMulPrimeElem;

    fn add(self: &'a ZMulPrimeElem, other: &ZMulPrimeElem) -> Self::Output {
        ZMulPrimeElem {
            zmulp: self.zmulp.clone(),
            elem: (&self.elem + &other.elem) % self.zmulp.p.as_ref(),
        }
    }
}

// impl Mul<ZMulPrimeElem> for ZMulPrimeElem {
//     type Output = ZMulPrimeElem;

//     fn mul(self, other: ZMulPrimeElem) -> Self::Output {
//         ZMulPrimeElem {
//             zmulp: self.zmulp.clone(),
//             elem: (&self.elem * &other.elem) % self.zmulp.p.as_ref(),
//         }
//     }
// }

impl<'a> Mul<&ZMulPrimeElem> for &'a ZMulPrimeElem {
    type Output = ZMulPrimeElem;

    fn mul(self: &'a ZMulPrimeElem, other: &ZMulPrimeElem) -> Self::Output {
        ZMulPrimeElem {
            zmulp: self.zmulp.clone(),
            elem: (&self.elem * &other.elem) % self.zmulp.p.as_ref(),
        }
    }
}

impl<'a, 'b> Mul<&'b BigUint> for &'a ZMulPrimeElem {
    type Output = ZMulPrimeElem;

    fn mul(self: &'a ZMulPrimeElem, other: &BigUint) -> Self::Output {
        ZMulPrimeElem {
            zmulp: self.zmulp.clone(),
            elem: (&self.elem * other) % self.zmulp.p.as_ref(),
        }
    }
}

impl Sub<&ZMulPrimeElem> for ZMulPrimeElem {
    type Output = ZMulPrimeElem;

    fn sub(self: ZMulPrimeElem, other: &ZMulPrimeElem) -> Self::Output {
        if &self.elem > &other.elem {
            ZMulPrimeElem {
                zmulp: self.zmulp.clone(),
                elem: (&self.elem - &other.elem) % self.zmulp.p.as_ref(),
            }
        } else {
            ZMulPrimeElem {
                zmulp: self.zmulp.clone(),
                elem: self.zmulp.p.as_ref() - ((&other.elem - &self.elem) % self.zmulp.p.as_ref()),
            }
        }
    }
}

impl<'a> Sub<&ZMulPrimeElem> for &'a ZMulPrimeElem {
    type Output = ZMulPrimeElem;

    fn sub(self: &'a ZMulPrimeElem, other: &ZMulPrimeElem) -> Self::Output {
        if &self.elem > &other.elem {
            ZMulPrimeElem {
                zmulp: self.zmulp.clone(),
                elem: (&self.elem - &other.elem) % self.zmulp.p.as_ref(),
            }
        } else {
            ZMulPrimeElem {
                zmulp: self.zmulp.clone(),
                elem: self.zmulp.p.as_ref() - ((&other.elem - &self.elem) % self.zmulp.p.as_ref()),
            }
        }
    }
}

impl SubAssign<ZMulPrimeElem> for ZMulPrimeElem {
    fn sub_assign(&mut self, other: ZMulPrimeElem) {
        if &self.elem > &other.elem {
            self.elem = (&self.elem - &other.elem) % self.zmulp.p.as_ref()
        } else {
            self.elem = self.zmulp.p.as_ref() - ((&other.elem - &self.elem) % self.zmulp.p.as_ref())
        }
    }
}

#[cfg(test)]
mod test_zmulprime {
    use std::rc::Rc;

    use super::*;
    use num_bigint::BigUint;
    use num_traits::One;

    #[test]
    fn test_zmulprime() {
        let max_bits = crate::prime::PRIMES_TABLE_U8_BITS_RANGE.end;
        for bits in 3..max_bits {
            const CNT_ITER_SEEDS: u64 = 1000;
            for iter_seed in 0..CNT_ITER_SEEDS {
                let seed = (bits as u64) * CNT_ITER_SEEDS + iter_seed;
                let mut csprng = Csprng::new(&seed.to_be_bytes());

                let zmulp = Rc::new(ZMulPrime::new_random(bits, &mut csprng));

                let elem = zmulp.clone().pick_random_elem(&mut csprng);

                // Verify that the elem is 1 <= n < p.
                //println!("p={}, elem={}", &zmulp.p, &elem.elem);
                assert!(&BigUint::one() <= &elem.elem);
                assert!(&elem.elem < zmulp.p.borrow());
            }
        }
    }

    #[test]
    fn test_zmulprime_pow() {
        let mut csprng = Csprng::new(b"test_zmulprime_pow");

        for (p, elem, exponent, expected) in [
            (3_u8, 1_u8, 1_u8, 1_u8),
            (3, 1, 2, 1),
            (3, 1, 3, 1),
            (3, 1, 4, 1),
            (3, 2, 1, 2),
            (3, 2, 2, 1),
            (3, 2, 3, 2),
            (3, 2, 4, 1),
            (3, 2, 5, 2),
            (5, 3, 3, 2), // 3^3 (mod 5) = 2
        ] {
            let p: BigUint = p.try_into().unwrap();
            let p = BigUintPrime::new(p, &mut csprng).unwrap();
            let elem: BigUint = elem.try_into().unwrap();
            let exponent: BigUint = exponent.into();

            let zmulp = Rc::new(ZMulPrime::new(p));
            let elem = zmulp.clone().try_new_elem(elem).unwrap();
            let actual = elem.pow(&exponent);

            assert_eq!(&actual.elem, &expected.into());
        }
    }
    #[test]
    fn test_zmulprime_sub() {
        let mut csprng = Csprng::new(0);

        for (a, b, p, expected) in [
            (100u16, 50u16, 997u16, 50u16),
            (500, 300, 997, 200),
            (700, 400, 997, 300),
            (50, 100, 997, 947),
            (300, 500, 997, 797),
            (400, 700, 997, 697),
            (1000, 100, 997, 900),
            (100, 1000, 997, 97),
            (999, 1, 997, 1),
        ] {
            let p: BigUint = p.try_into().unwrap();

            let a = BigUint::from(a) % &p;
            let b: BigUint = BigUint::from(b) % &p;

            let p = BigUintPrime::new(p, &mut csprng).unwrap();

            let zmulp = Rc::new(ZMulPrime::new(p));
            let a = zmulp.clone().try_new_elem(a).unwrap();
            let b = zmulp.clone().try_new_elem(b).unwrap();

            let actual = a - &b;
            assert_eq!(&actual.elem, &expected.into());
        }
    }
}
