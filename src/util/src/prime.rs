// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::num::NonZeroUsize;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};

use crate::{
    csprng::Csprng,
    csrng::{Csrng, DeterministicCsrng},
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

// The log_2 of the largest number for which we'll do exhaustive trial division.
const EXHAUSTIVE_TRIAL_DIVISION_MAX_L2: u8 = 20;

/// The largest number for which the [`is_prime()`] primality test is not probabalistic.
pub const MAX_NON_PROBABALISTIC: u32 = 1_u32 << EXHAUSTIVE_TRIAL_DIVISION_MAX_L2;

/// The number of Miller-Rabin iterations to perform when for a probablistic primality test.
pub const MILLER_RABIN_ITERATIONS: usize = 50;

/// Primality test.
///
/// For numbers above [`MAX_NON_PROBABALISTIC`], the test is probabalistic using
/// [`MILLER_RABIN_ITERATIONS`] of Miller-Rabin.
///
/// Calling this function on very large numbers can get quite expensive.
///
pub fn is_prime<T: Borrow<BigUint>>(n: &T, csrng: &dyn Csrng) -> bool {
    is_prime_impl_(n.borrow(), Some(csrng))
}

fn is_prime_impl_(n: &BigUint, opt_csrng: Option<&dyn Csrng>) -> bool {
    use num_integer::Roots;

    const EXHAUSTIVE_TRIAL_DIVISION_MAX_L2_U64: u64 = EXHAUSTIVE_TRIAL_DIVISION_MAX_L2 as u64;

    let n_low_u32 = n.iter_u32_digits().next().unwrap_or_default();

    let mut is_prime = false;
    match n.bits() {
        0..=1 => {
            // `0` and `1` are not prime
            debug_assert!(!is_prime);
        }
        2 => {
            // `2` and `3` are prime
            is_prime = true
        }
        n_bits => {
            if n_low_u32 % 2 == 0 {
                // Values divisible by 2 are not prime
                debug_assert!(!is_prime);
            } else {
                match n_bits {
                    0..=8 => {
                        let n_u8 = n_low_u32 as u8;
                        for p in PRIMES_TABLE_U8 {
                            match n_u8.cmp(&p) {
                                Ordering::Less => {
                                    break;
                                }
                                Ordering::Equal => {
                                    is_prime = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    9..=EXHAUSTIVE_TRIAL_DIVISION_MAX_L2_U64 => {
                        // Since we use n_low_u32 here,
                        static_assertions::const_assert!(EXHAUSTIVE_TRIAL_DIVISION_MAX_L2 < 32);

                        let n = n_low_u32;
                        let n_sqrt = n.sqrt();

                        is_prime = true;
                        for p in (3_u32..=n_sqrt).step_by(2) {
                            if n % p == 0 {
                                is_prime = false;
                                break;
                            }
                        }
                    }
                    n_bits => {
                        if let Some(csrng) = opt_csrng {
                            is_prime = miller_rabin(n, MILLER_RABIN_ITERATIONS, csrng);
                        } else {
                            let seed =
                                b"electionguard-rust/src/util::prime::is_prime_default_csprng";
                            let builder = Csprng::build().write_bytes(seed).write_u64(n_bits);
                            let csprng_builder = n
                                .iter_u64_digits()
                                .fold(builder, |builder, u| builder.write_u64(u));
                            let csrng: &dyn Csrng =
                                &DeterministicCsrng::new(csprng_builder.finish());
                            is_prime = miller_rabin(n, MILLER_RABIN_ITERATIONS, csrng);
                        }
                    }
                }
            }
        }
    }

    is_prime
}

/// Probabilistic primality test, using a fixed Csprng. For large numbers this call is expensive.
///
/// Internally, the function uses the Miller-Rabin test.
///
pub fn is_prime_default_csprng<T: Borrow<BigUint>>(n: &T) -> bool {
    is_prime_impl_(n.borrow(), None)
}

fn miller_rabin(w: &BigUint, iterations: usize, csrng: &dyn Csrng) -> bool {
    // NIST FIPS 186-5 DIGITAL SIGNATURE STANDARD (DSS)
    // B.3.1 Miller-Rabin Probabilistic Primality Test
    // Let DRBG be an approved deterministic random bit generator.

    // Input:
    // 1. w The odd integer to be tested for primality.
    // 2. iterations The number of iterations of the test to be performed; the value
    // shall be consistent with Table B.1.
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
            let b = csrng.next_biguint(wlen);

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

fn largest_integer_a_such_that_2_to_a_divides_even_n(n: &BigUint) -> u64 {
    assert!(n.is_even(), "requires n even");
    assert!(!n.is_zero(), "requires n > 1");

    // `unwrap()` is justified here because we just verified that 2 <= `n`.
    #[allow(clippy::unwrap_used)]
    n.trailing_zeros().unwrap()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test_primes {
    use num_traits::Num;

    use super::*;
    use crate::csrng::{Csrng, DeterministicCsrng};

    #[test]
    fn test_largest_integer_a_such_that_2_to_a_divides_even_n() {
        for half_n in 1_usize..1000 {
            let n = half_n * 2;

            let a = largest_integer_a_such_that_2_to_a_divides_even_n(&BigUint::from(n));
            assert!(a < 32);
            let two_to_a = 1_usize << a;

            assert!(num_integer::Integer::is_multiple_of(&n, &two_to_a));

            for invalid_a in (a + 1)..32 {
                let two_to_invalid_a = 1_usize << invalid_a;
                if num_integer::Integer::is_multiple_of(&n, &two_to_invalid_a) {
                    println!(
                        "\n\nn={n}, a={a}, invalid_a={invalid_a}, two_to_invalid_a={two_to_invalid_a}\n"
                    );
                }
                assert!(!num_integer::Integer::is_multiple_of(&n, &two_to_invalid_a));
            }
        }
    }

    #[test]
    fn test_is_prime() {
        let csrng: &dyn Csrng = &DeterministicCsrng::from_seed_str("test_is_prime");

        // Test first 10 integers.
        for (n, expected_prime) in [
            // 0,  1,     2,    3,    4,     5,    6,     7,    8,     9,
            false, false, true, true, false, true, false, true, false, false,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!((n, is_prime(&BigUint::from(n), csrng)), (n, expected_prime));
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
                assert_eq!((&n, is_prime(&n, csrng)), (&n, expected_prime));
                n += BigUint::one();
            }
        }
    }
}
