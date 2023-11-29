#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::iter::zip;
use thiserror::Error;
use util::{bitwise::xor, csprng::Csprng, integer_util::to_be_bytes_left_pad};

use crate::{
    election_parameters::ElectionParameters,
    guardian::GuardianIndex,
    guardian_public_key::GuardianPublicKey,
    guardian_secret_key::GuardianSecretKey,
    hash::{eg_h, eg_hmac, HValue},
    hashes::ParameterBaseHash,
};

/// Encrypted guardian share
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianEncryptedShare {
    pub dealer: GuardianIndex,
    pub recipient: GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub c0: BigUint,
    pub c1: HValue,
    pub c2: HValue,
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("The dealer of the ciphertext is {i}, but the public key has index {j}.")]
    DealerIndicesMismatch { i: GuardianIndex, j: GuardianIndex },
    #[error("The recipient of the ciphertext is {i}, but the secret key has index {j}.")]
    RecipientIndicesMismatch { i: GuardianIndex, j: GuardianIndex },
    #[error("The MAC does not verify.")]
    InvalidMAC,
}

impl GuardianEncryptedShare {
    /// This function computes the share encryption secret key as defined in Equation (15)
    /// The arguments are
    /// - h_p - the parameter base hash
    /// - i - the dealer index
    /// - l - the recipient index
    /// - capital_k_l - the recipient public key
    /// - alpha - as in Equation (14)
    /// - beta - as in Equation (14)
    fn secret_key(
        h_p: HValue,
        i: u32,
        l: u32,
        capital_k_l: &BigUint,
        alpha: &BigUint,
        beta: &BigUint,
    ) -> HValue {
        // v = 0x11 | b(i, 4) | b(l, 4) | b(capital_k, 512) | b(alpha,l, 512) | b(beta,l, 512)
        let mut v = vec![0x11];
        v.extend_from_slice(i.to_be_bytes().as_slice());
        v.extend_from_slice(l.to_be_bytes().as_slice());
        v.extend_from_slice(to_be_bytes_left_pad(capital_k_l, 512).as_slice());
        v.extend_from_slice(to_be_bytes_left_pad(alpha, 512).as_slice());
        v.extend_from_slice(to_be_bytes_left_pad(beta, 512).as_slice());
        eg_h(&h_p, &v)
    }

    /// This function computes the MAC key (Equation 16) and the encryption key (Equation 17)
    /// The arguments are
    /// - i - the dealer index
    /// - l - the recipient index
    /// - k_i_l - the secret key as in Equation (15)
    fn mac_and_encryption_key(i: u32, l: u32, k_i_l: &HValue) -> (HValue, HValue) {
        // label = b("share_enc_keys",14)
        let label = "share_enc_keys".as_bytes();
        // context = share_enc_keys("share_encrypt",13) | b(i, 4) | b(l, 4)
        let mut context = "share_encrypt".as_bytes().to_vec();
        context.extend_from_slice(i.to_be_bytes().as_slice());
        context.extend_from_slice(l.to_be_bytes().as_slice());
        // MAC key
        // v = 0x01 | label | 0x00 | context | 0x0200
        let mut v = vec![0x01];
        v.extend_from_slice(label);
        v.push(0x00);
        v.extend(&context);
        v.extend([0x02, 0x00]);
        let k1 = eg_hmac(k_i_l, &v);
        // encryption key
        // v = 0x02 | label | 0x00 | context | 0x0200
        let mut v = vec![0x02];
        v.extend_from_slice(label);
        v.push(0x00);
        v.extend(context);
        v.extend(vec![0x02, 0x00]);
        let k2 = eg_hmac(k_i_l, &v);

        (k1, k2)
    }

    /// This function computes the MAC as in Equation (19)
    /// The arguments are
    /// - k0 - the MAC key
    /// - c0 - ciphertext part 1
    /// - c1 - ciphertext part 2
    fn share_mac(k0: HValue, c0: &[u8], c1: &HValue) -> HValue {
        let mut v = c0.to_vec();
        v.extend_from_slice(c1.0.as_slice());
        eg_hmac(&k0, &v)
    }

    /// This function creates a new [`GuardianEncryptedShare`] of the dealer's secret key for a given recipient.
    /// The arguments are
    /// - csprng - secure randomness generator
    /// - election_parameters - the election parameters
    /// - h_p - the parameter base hash
    /// - dealer_private_key - the dealer's `GuardianSecretKey`
    /// - recipient_public_key - the recipient's `GuardianPublicKey`
    pub fn new(
        csprng: &mut Csprng,
        election_parameters: &ElectionParameters,
        dealer_private_key: &GuardianSecretKey,
        recipient_public_key: &GuardianPublicKey,
    ) -> Self {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let h_p = ParameterBaseHash::compute(fixed_parameters).h_p;

        let i = dealer_private_key.i.get_one_based_u32();
        let l = recipient_public_key.i.get_one_based_u32();
        let q: &BigUint = fixed_parameters.q.as_ref();
        let p: &BigUint = fixed_parameters.p.as_ref();
        let capital_k = recipient_public_key.public_key_k_i_0();

        //Generate alpha and beta (Equation 14)
        let xi = csprng.next_biguint_lt(q);
        let alpha = fixed_parameters.g.modpow(&xi, p);
        let beta = capital_k.modpow(&xi, p);

        let k_i_l = Self::secret_key(h_p, i, l, capital_k, &alpha, &beta);
        let (k0, k1) = Self::mac_and_encryption_key(i, l, &k_i_l);

        //Generate key share as P(l) (cf. Equations 9 and 18) using Horner's method
        let x = &BigUint::from(l);
        let mut p_l = BigUint::from(0_u8);
        for coeff in dealer_private_key.secret_coefficients.0.iter().rev() {
            p_l = (p_l * x + &coeff.0) % q;
        }

        //Ciphertext as in Equation (19)
        let c1 = xor(to_be_bytes_left_pad(&p_l, 32).as_slice(), k1.0.as_slice());
        //The unwrap is justified as the output the XOR will always be 32 bytes.
        #[allow(clippy::unwrap_used)]
        let c1 = HValue(c1[0..32].try_into().unwrap());
        let c2 = Self::share_mac(k0, to_be_bytes_left_pad(&alpha, 512).as_slice(), &c1);

        GuardianEncryptedShare {
            dealer: dealer_private_key.i,
            recipient: recipient_public_key.i,
            c0: alpha,
            c1,
            c2,
        }
    }

    /// This function decrypts and validates a [`GuardianEncryptedShare`].
    /// The arguments are
    /// - self - the encrypted share
    /// - election_parameters - the election parameters
    /// - dealer_public_key - the dealer's `GuardianPublicKey`
    /// - recipient_secret_key - the recipient's `GuardianSecretKey`
    pub fn decrypt_and_validate(
        &self,
        election_parameters: &ElectionParameters,
        dealer_public_key: &GuardianPublicKey,
        recipient_secret_key: &GuardianSecretKey,
    ) -> Result<BigUint, DecryptionError> {
        if self.dealer != dealer_public_key.i {
            return Err(DecryptionError::DealerIndicesMismatch {
                i: self.dealer,
                j: dealer_public_key.i,
            });
        }
        if self.recipient != recipient_secret_key.i {
            return Err(DecryptionError::RecipientIndicesMismatch {
                i: self.dealer,
                j: dealer_public_key.i,
            });
        }

        let i = self.dealer.get_one_based_u32();
        let l = self.recipient.get_one_based_u32();
        let fixed_parameters = &election_parameters.fixed_parameters;
        let h_p = ParameterBaseHash::compute(fixed_parameters).h_p;
        let p: &BigUint = fixed_parameters.p.as_ref();
        let capital_k = &recipient_secret_key.coefficient_commitments.0[0].0;

        let alpha = &self.c0;
        let beta = alpha.modpow(recipient_secret_key.secret_s(), p);
        let k_i_l = Self::secret_key(h_p, i, l, capital_k, alpha, &beta);

        let (k0, k1) = Self::mac_and_encryption_key(i, l, &k_i_l);
        let mac = Self::share_mac(k0, to_be_bytes_left_pad(alpha, 512).as_slice(), &self.c1);

        if mac != self.c2 {
            return Err(DecryptionError::InvalidMAC);
        }

        let p_l_bytes = xor(self.c1.0.as_slice(), k1.0.as_slice());

        Ok(BigUint::from_bytes_be(p_l_bytes.as_slice()))
    }
}

/// A guardian's share of the master secret key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianSecretKeyShare {
    pub i: GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub p_i: BigUint,
}

#[derive(Error, Debug)]
pub enum ShareCombinationError {
    #[error("Public key of guardian {0} is invalid.")]
    InvalidPublicKey(GuardianIndex),
    #[error("Guardian {0} is represented more than once in the guardian public keys.")]
    DuplicateGuardian(GuardianIndex),
    #[error("Guardian {0} is represented more than once in the guardian public keys.")]
    MissingGuardian(String),
    #[error("Could not decrypt and validate share from guardian {0}.")]
    DecryptionError(GuardianIndex),
}

impl GuardianSecretKeyShare {
    /// This function computes a new `GuardianSecretKeyShare` from a list of `GuardianEncryptedShare`
    /// The arguments are
    /// - election_parameters - the election parameters
    /// - h_p - the parameter base hash
    /// - guardian_public_keys - a list of `GuardianPublicKey`
    /// - encrypted_shares - a list of `GuardianEncryptedShare`
    /// - recipient_secret_key - the recipient's `GuardianSecretKey`
    /// This function assumes that i-th encrypted_share and the i-th guardian_public_key are from the same guardian.
    pub fn compute(
        election_parameters: &ElectionParameters,
        guardian_public_keys: &[GuardianPublicKey],
        encrypted_shares: &[GuardianEncryptedShare],
        recipient_secret_key: &GuardianSecretKey,
    ) -> Result<Self, ShareCombinationError> {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;
        let n = varying_parameters.n.get_one_based_usize();

        // Validate every supplied guardian public key.
        for guardian_public_key in guardian_public_keys {
            if guardian_public_key.validate(election_parameters).is_err() {
                return Err(ShareCombinationError::InvalidPublicKey(
                    guardian_public_key.i,
                ));
            }
        }

        // Verify that every guardian is represented exactly once.
        let mut seen = vec![false; n];
        for guardian_public_key in guardian_public_keys {
            let seen_ix = guardian_public_key.i.get_zero_based_usize();
            if seen[seen_ix] {
                return Err(ShareCombinationError::DuplicateGuardian(
                    guardian_public_key.i,
                ));
            }
            seen[seen_ix] = true;
        }

        let missing_guardian_ixs: Vec<usize> = seen
            .iter()
            .enumerate()
            .filter(|&(_ix, &seen)| !seen)
            .map(|(ix, _)| ix)
            .collect();

        if !missing_guardian_ixs.is_empty() {
            let info = missing_guardian_ixs.iter().fold(String::new(), |acc, ix| {
                if acc.is_empty() {
                    (ix + 1).to_string()
                } else {
                    acc + "," + &(ix + 1).to_string()
                }
            });
            return Err(ShareCombinationError::MissingGuardian(info));
        }

        // Decrypt and validate shares
        let mut shares = vec![];
        for (pk, share) in zip(guardian_public_keys, encrypted_shares) {
            let res = share.decrypt_and_validate(election_parameters, pk, recipient_secret_key);
            if res.is_err() {
                return Err(ShareCombinationError::DecryptionError(pk.i));
            }
            shares.push(res.unwrap_or(BigUint::from(0_u8)))
        }

        let key = shares.iter().fold(BigUint::from(0_u8), |mut acc, share| {
            acc += share;
            acc % fixed_parameters.q.as_ref()
        });

        Ok(Self {
            i: recipient_secret_key.i,
            p_i: key,
        })
    }
}

#[cfg(test)]
mod test {
    use num_bigint::{BigInt, BigUint, Sign};
    use num_traits::{One, Zero};
    use std::{iter::zip, mem};
    use util::{csprng::Csprng, prime::BigUintPrime};

    use crate::{
        example_election_parameters::example_election_parameters, guardian::GuardianIndex,
        guardian_secret_key::GuardianSecretKey,
    };

    use super::{GuardianEncryptedShare, GuardianSecretKeyShare};

    #[test]
    fn test_text_encoding() {
        assert_eq!("share_enc_keys".as_bytes().len(), 14);
        assert_eq!("share_encrypt".as_bytes().len(), 13);
    }

    #[test]
    fn test_encryption_decryption() {
        let mut csprng = Csprng::new(b"test_proof_generation");

        let election_parameters = example_election_parameters();

        let index_one = GuardianIndex::from_one_based_index(1).unwrap();
        let index_two = GuardianIndex::from_one_based_index(2).unwrap();
        let sk_one =
            GuardianSecretKey::generate(&mut csprng, &election_parameters, index_one, None);
        let sk_two =
            GuardianSecretKey::generate(&mut csprng, &election_parameters, index_two, None);
        let pk_one = sk_one.make_public_key();
        let pk_two = sk_two.make_public_key();

        let encrypted_share =
            GuardianEncryptedShare::new(&mut csprng, &election_parameters, &sk_one, &pk_two);

        let result = encrypted_share.decrypt_and_validate(&election_parameters, &pk_one, &sk_two);

        assert!(result.is_ok(), "The decrypted share should be valid");
    }

    fn mod_inverse(a_u: &BigUint, m_u: &BigUint) -> Option<BigUint> {
        if m_u.is_zero() {
            return None;
        }
        let m = BigInt::from_biguint(Sign::Plus, m_u.clone());
        let mut t = (BigInt::zero(), BigInt::one());
        let mut r = (m.clone(), BigInt::from_biguint(Sign::Plus, a_u.clone()));
        while !r.1.is_zero() {
            let q = r.0.clone() / r.1.clone();
            //https://docs.rs/num-integer/0.1.45/src/num_integer/lib.rs.html#353
            let f = |mut r: (BigInt, BigInt)| {
                mem::swap(&mut r.0, &mut r.1);
                r.1 = r.1 - q.clone() * r.0.clone();
                r
            };
            r = f(r);
            t = f(t);
        }
        if r.0.is_one() {
            if t.0 < BigInt::zero() {
                return Some((t.0 + m).magnitude().clone());
            }
            return Some(t.0.magnitude().clone());
        }

        None
    }

    #[test]
    fn test_mod_inverse() {
        assert_eq!(
            mod_inverse(&BigUint::from(3_u8), &BigUint::from(11_u8)),
            Some(BigUint::from(4_u8)),
            "The inverse of 3 mod 11 should be 4."
        );
        assert_eq!(
            mod_inverse(&BigUint::from(0_u8), &BigUint::from(11_u8)),
            None,
            "The inverse of 0 mod 11 should not exist."
        );
        assert_eq!(
            mod_inverse(&BigUint::from(3_u8), &BigUint::from(12_u8)),
            None,
            "The inverse of 3 mod 12 should not exist."
        )
    }

    fn lagrange_interpolation_at_zero(xs: &[BigUint], ys: &[BigUint], q: &BigUintPrime) -> BigUint {
        // Lagrange coefficients
        let mut coeffs = vec![];
        for i in xs {
            let b_i = xs
                .iter()
                .filter(|&l| l != i)
                .map(|l| l * mod_inverse(&q.subtract_group_elem(l, i), q.as_ref()).unwrap())
                .fold(BigUint::one(), |mut acc, s| {
                    acc *= s;
                    acc % q.as_ref()
                });
            coeffs.push(b_i);
        }
        zip(coeffs, ys)
            .map(|(c, y)| c * y % q.as_ref())
            .fold(BigUint::zero(), |mut acc, s| {
                acc += s;
                acc % q.as_ref()
            })
    }

    #[test]
    fn test_key_sharing() {
        let mut csprng = Csprng::new(b"test_proof_generation");

        let election_parameters = example_election_parameters();

        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;

        let guardian_secret_keys = varying_parameters
            .each_guardian_i()
            .map(|i| GuardianSecretKey::generate(&mut csprng, &election_parameters, i, None))
            .collect::<Vec<_>>();

        let guardian_public_keys = guardian_secret_keys
            .iter()
            .map(|secret_key| secret_key.make_public_key())
            .collect::<Vec<_>>();

        // Compute secret key shares
        let share_vecs = guardian_public_keys
            .iter()
            .map(|pk| {
                guardian_secret_keys
                    .iter()
                    .map(|dealer_sk| {
                        GuardianEncryptedShare::new(
                            &mut csprng,
                            &election_parameters,
                            dealer_sk,
                            &pk,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let key_shares = zip(&guardian_secret_keys, share_vecs)
            .map(|(sk, shares)| {
                GuardianSecretKeyShare::compute(
                    &election_parameters,
                    &guardian_public_keys,
                    &shares,
                    &sk,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        // Compute joint secret key from secret keys
        let joint_key_1 =
            guardian_secret_keys
                .iter()
                .fold(BigUint::from(0_u8), |mut acc, share| {
                    acc += share.secret_s();
                    acc % fixed_parameters.q.as_ref()
                });

        // Compute joint secret key from shares
        let xs = guardian_public_keys
            .iter()
            .map(|pk| BigUint::from(pk.i.get_one_based_u32()))
            .collect::<Vec<_>>();
        let ys = key_shares.iter().map(|s| s.p_i.clone()).collect::<Vec<_>>();
        let joint_key_2 = lagrange_interpolation_at_zero(&xs, &ys, &fixed_parameters.q);

        assert_eq!(joint_key_1, joint_key_2, "Joint keys should match.")
    }
}
