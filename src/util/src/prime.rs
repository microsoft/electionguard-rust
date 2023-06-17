// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;
use std::cmp::{PartialEq, PartialOrd};
use std::convert::AsRef;
use std::convert::Into;
use std::convert::TryInto;
use std::fmt::Debug;
use std::num::NonZeroUsize;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::biguint_serde;
use crate::{
    csprng::Csprng,
    integer_util::{cnt_bits_repr_usize, largest_integer_a_such_that_2_to_a_divides_even_n},
};

pub const PRIMES_TABLE_U8: [u8; 54] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

/// The smallest integer whose prime-ness can *not* be resolved by `PRIMES_TABLE_U8`.
pub const PRIMES_TABLE_U8_MAX: usize = 257;

/// The range of bit lengths covered by PRIMES_TABLE_U8.
pub const PRIMES_TABLE_U8_BITS_RANGE: std::ops::Range<usize> = 2..9;

const EXHAUSTIVE_TRIAL_DIVISION_MAX_L2: usize = 20;
const EXHAUSTIVE_TRIAL_DIVISION_MAX: usize = 1 << EXHAUSTIVE_TRIAL_DIVISION_MAX_L2;

const MILLER_RABIN_ITERATIONS: usize = 50;

//? TODO Would prefer to use AsRef instead of Borrow, but it doesn't have
// an automatic `impl AsRef<T> for T`, and we can't `impl AsRef<BigUint> for BigUint`
// since it's in a cargo crate.
// `Borrow` does have a blanket implementation, but now we have to ensure that
// the hash, ord, and eq traits work exactly the same between BigUintPrime and BigUint.

pub fn is_prime<T: Borrow<BigUint>>(n: &T, csprng: &mut Csprng) -> bool {
    //? OPT: Maybe somehow we could defer Csprng creation until we know that we need randomized primality testing.

    let n: &BigUint = n.borrow();

    use num_integer::Roots;

    match TryInto::<u8>::try_into(n) {
        Ok(n) => {
            debug_assert!(
                (n as usize) < PRIMES_TABLE_U8_MAX,
                "n must be found within PRIMES_TABLE_U8"
            );
            PRIMES_TABLE_U8.iter().any(|&p| n == p)
        }
        Err(_) => {
            debug_assert!(n.bits() > 8, "we can assume n is odd or nonprime");
            if n <= &EXHAUSTIVE_TRIAL_DIVISION_MAX.into() {
                // `unwrap()` is justified here because `n` < (value of type `usize`).
                #[allow(clippy::unwrap_used)]
                let n: usize = n.try_into().unwrap();

                if n & 1 == 0 {
                    return false;
                }

                for p in (3..=n.sqrt()).step_by(2) {
                    if n % p == 0 {
                        return false;
                    }
                }

                true
            } else {
                let n: &BigUint = n.borrow();

                if !n.bit(0) {
                    return false;
                }

                miller_rabin(n, MILLER_RABIN_ITERATIONS, csprng)
            }
        }
    }
}

pub fn is_prime_default_csprng<T: Borrow<BigUint>>(n: &T) -> bool {
    let mut csprng = Csprng::new(b"electionguard-rust/util::prime::is_prime_default_csprng");
    is_prime(n, &mut csprng)
}

fn miller_rabin(w: &BigUint, iterations: usize, csprng: &mut Csprng) -> bool {
    // NIST FIPS 186-5 DIGITAL SIGNATURE STANDARD (DSS)
    // B.3.1 Miller-Rabin Probabilistic Primality Test
    // Let DRBG be an approved deterministic random bit generator.

    // Input:
    // 1. w The odd integer to be tested for primality.
    // 2. iterations The number of iterations of the test to be performed; the value
    // shall be consistent with Table B.1.
    use num_integer::Integer;
    assert!(w.is_odd(), "requires w odd");
    assert!(!w.is_one(), "requires 3 <= w");
    assert!(iterations > 0);

    // Output:
    // 1. status The status returned from the validation procedure where status is
    // either PROBABLY PRIME or COMPOSITE.

    // Process:
    // 1. Let a be the largest integer such that 2^a divides w−1.
    let w_minus_1: BigUint = w - 1_u8;
    let a = largest_integer_a_such_that_2_to_a_divides_even_n(&w_minus_1);

    // 2. m = (w−1) / 2^a.
    let m = &w_minus_1 >> a;

    // 3. wlen = len (w).
    // `unwrap()` is justified here because 3 <= `w`.
    #[allow(clippy::unwrap_used)]
    let wlen: NonZeroUsize = NonZeroUsize::new(w.bits() as usize).unwrap();

    let two = BigUint::from(2_u8);

    // 4. For i = 1 to iterations do
    'for_i: for _i in 0..iterations {
        let b = loop {
            // 4.1 Obtain a string b of wlen bits from a DRBG. Convert b to an integer using the
            // algorithm in B.2.1.
            let b = csprng.next_biguint(wlen);

            // 4.2 If ((b ≤ 1) or (b ≥ w − 1)), then go to step 4.1.
            if !(b.is_zero() || b.is_one() || b >= w_minus_1) {
                break b;
            }
        };

        // 4.3 z = b^m mod w.
        let mut z = b.modpow(&m, w);

        // 4.4 If ((z = 1) or (z = w − 1)), then go to step 4.7.
        if z.is_one() || z == w_minus_1 {
            // 4.7 Continue.
            continue 'for_i;
        }

        // 4.5 For j = 1 to a − 1 do.
        for _j in 1..a {
            // 4.5.1 z = z^2 mod w.
            z = z.modpow(&two, w);

            // 4.5.2 If (z = w − 1), then go to step 4.7.
            if z == w_minus_1 {
                // 4.7 Continue.
                continue 'for_i;
            }

            // 4.5.3 If (z = 1), then go to step 4.6.
            if z.is_one() {
                break;
            }
        }

        // 4.6 Return COMPOSITE.
        return false;
    }

    // 5. Return PROBABLY PRIME
    true
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BigUintPrime(BigUint);

impl BigUintPrime {
    // Constructor from BigUint
    pub fn new(p: BigUint, csprng: &mut Csprng) -> Option<BigUintPrime> {
        if is_prime(&p, csprng) {
            Some(BigUintPrime(p))
        } else {
            None
        }
    }

    pub fn new_unchecked_the_caller_guarantees_that_this_number_is_prime(
        p: BigUint,
    ) -> BigUintPrime {
        BigUintPrime(p)
    }

    // Selects a random prime 2^(bits - 1) <= p < 2^bits
    #[allow(clippy::panic)]
    pub fn new_random_prime(bits: usize, csprng: &mut Csprng) -> BigUintPrime {
        if PRIMES_TABLE_U8_BITS_RANGE.contains(&bits) {
            let opt_ix_first_of_bits = PRIMES_TABLE_U8
                .iter()
                .position(|&p| bits == cnt_bits_repr_usize(p as usize));
            let opt_ix_first_past_bits = PRIMES_TABLE_U8
                .iter()
                .position(|&p| bits < cnt_bits_repr_usize(p as usize));

            let range = match (opt_ix_first_of_bits, opt_ix_first_past_bits) {
                (Some(ix_first_of_bits), None) => ix_first_of_bits..PRIMES_TABLE_U8.len(),
                (Some(ix_first_of_bits), Some(ix_first_past_bits)) => {
                    ix_first_of_bits..ix_first_past_bits
                }
                _ => {
                    panic!("shouldn't happen");
                }
            };

            use rand::distributions::{Distribution, Uniform};
            let ix = Uniform::from(range).sample(csprng);

            let p = PRIMES_TABLE_U8[ix];
            assert_eq!(cnt_bits_repr_usize(p as usize), bits);

            BigUintPrime(p.into())
        } else {
            todo!("implement BigUintPrime::new_random_prime for bits > PRIMES_TABLE_U8_BITS_RANGE")
        }
    }
}

impl Serialize for BigUintPrime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        biguint_serde::biguint_serialize(self.as_ref(), serializer)
    }
}

impl<'de> Deserialize<'de> for BigUintPrime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        //? TODO: check that the deserialized number is prime ?
        biguint_serde::biguint_deserialize(deserializer)
            .map(BigUintPrime::new_unchecked_the_caller_guarantees_that_this_number_is_prime)
    }
}

impl From<BigUintPrime> for BigUint {
    #[inline]
    fn from(val: BigUintPrime) -> Self {
        val.0
    }
}

impl AsRef<BigUint> for BigUintPrime {
    #[inline]
    fn as_ref(&self) -> &BigUint {
        &self.0
    }
}

impl Borrow<BigUint> for BigUintPrime {
    #[inline]
    fn borrow(&self) -> &BigUint {
        &self.0
    }
}

#[cfg(test)]
mod test_primes {
    use num_traits::Num;

    use super::*;

    #[test]
    fn test_is_prime() {
        let mut csprng = Csprng::new(b"test_is_prime");

        // Test first 10 integers.
        for (n, expected_prime) in [
            // 0,  1,     2,    3,    4,     5,    6,     7,    8,     9,
            false, false, true, true, false, true, false, true, false, false,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(is_prime(&BigUint::from(n), &mut csprng), expected_prime);
        }

        // Test miscellaneous primes having p-2 and p+2 not prime.
        for p_str in [
            // Within PRIMES_TABLE_U8
            "23",
            "131",
            "173",
            "211",
            "233",
            "251",
            // Below EXHAUSTIVE_TRIAL_DIVISION_MAX
            "257",
            "7901",
            // Mersenne and factorial primes
            "524287",
            "39916801",
            "479001599",
            "2147483647",
            "87178291199",
            "2305843009213693951",
            "618970019642690137449562111",
            "10888869450418352160768000001",
            "162259276829213363391578010288127",
            "265252859812191058636308479999999",
            "263130836933693530167218012159999999",
            "8683317618811886495518194401279999999",
            "170141183460469231731687303715884105727",
        ] {
            let p = BigUint::from_str_radix(p_str, 10).unwrap();

            let mut n = p - BigUint::from(2_u8);
            for expected_prime in (-2..=2).map(|offset| offset == 0) {
                assert_eq!(is_prime(&n, &mut csprng), expected_prime);
                n += BigUint::one();
            }
        }
    }

    #[test]
    fn test_conversion_biguintprime_biguint() {
        let mut csprng = Csprng::new(b"test_conversion_biguintprime_biguint");
        let n = 3_u8;
        let p = BigUintPrime::new(n.into(), &mut csprng).unwrap();
        let b: BigUint = p.into();
        assert_eq!(b, n.into());
    }

    #[test]
    fn test_new_random_prime() {
        let mut csprng = Csprng::new(b"test_new_random_prime");

        for bits in PRIMES_TABLE_U8_BITS_RANGE {
            for _ in 0..100 {
                let p = BigUintPrime::new_random_prime(bits, &mut csprng);
                assert!(is_prime(&p.0, &mut csprng));

                let p: usize = p.0.try_into().unwrap();
                assert_eq!(cnt_bits_repr_usize(p), bits);
            }
        }
    }
}
