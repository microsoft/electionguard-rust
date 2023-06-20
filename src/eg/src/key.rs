// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;

use num_bigint::BigUint;

use util::{csprng::Csprng, integer_util::to_be_bytes_left_pad};

use crate::{election_parameters::ElectionParameters, fixed_parameters::FixedParameters};

// pub enum AsymmetricKeyType {
//     Public,
//     Private,
// }

pub struct SecretCoefficient(pub(crate) BigUint);

impl SecretCoefficient {
    /// Returns the `SecretCoefficient` as a big-endian byte array of the correct length for `mod q`.
    pub fn to_be_bytes_len_q(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        fixed_parameters.biguint_to_be_bytes_len_q(&self.0)
    }
}

/// "Each guardian G_i in an election with a decryption threshold of k generates k secret
/// polynomial coefficients a_i,j, for 0 ≤ j < k, by sampling them uniformly, at random in
/// the range 0 ≤ a_i,j < q.
pub struct SecretCoefficients(Vec<SecretCoefficient>);

impl SecretCoefficients {
    pub fn generate(csprng: &mut Csprng, election_parameters: &ElectionParameters) -> Self {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;

        let k = varying_parameters.k as usize;

        SecretCoefficients(
            (0..k)
                .map(|_i| SecretCoefficient(csprng.next_biguint_lt(fixed_parameters.q.borrow())))
                .collect(),
        )
    }
}

#[derive(Clone)]
pub struct CoefficientCommitment(pub(crate) BigUint);

impl CoefficientCommitment {
    /// Returns the `CoefficientCommitment` as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_len_p(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        fixed_parameters.biguint_to_be_bytes_len_p(&self.0)
    }
}

#[derive(Clone)]
pub struct CoefficientCommitments(pub(crate) Vec<CoefficientCommitment>);

impl CoefficientCommitments {
    pub fn new(
        fixed_parameters: &FixedParameters,
        secret_coefficients: &SecretCoefficients,
    ) -> Self {
        CoefficientCommitments(
            secret_coefficients
                .0
                .iter()
                .map(|secret_coefficient| {
                    CoefficientCommitment(
                        fixed_parameters
                            .g
                            .modpow(&secret_coefficient.0, fixed_parameters.p.as_ref()),
                    )
                })
                .collect(),
        )
    }
}

#[derive()]
pub struct PrivateKey {
    /// Secret polynomial coefficients.
    pub(crate) secret_coefficients: SecretCoefficients,

    /// "Published" polynomial coefficient commitments.
    pub(crate) coefficient_commitments: CoefficientCommitments,
}

impl PrivateKey {
    pub fn generate(csprng: &mut Csprng, election_parameters: &ElectionParameters) -> Self {
        let secret_coefficients = SecretCoefficients::generate(csprng, election_parameters);
        assert_ne!(secret_coefficients.0.len(), 0);

        let coefficient_commitments = CoefficientCommitments::new(
            &election_parameters.fixed_parameters,
            &secret_coefficients,
        );
        assert_ne!(secret_coefficients.0.len(), 0);

        PrivateKey {
            secret_coefficients,
            coefficient_commitments,
        }
    }

    pub fn secret_coefficients(&self) -> &SecretCoefficients {
        &self.secret_coefficients
    }

    pub fn secret_s(&self) -> &BigUint {
        &self.secret_coefficients.0[0].0
    }

    pub fn coefficient_commitments(&self) -> &CoefficientCommitments {
        &self.coefficient_commitments
    }

    pub fn make_public_key(&self) -> PublicKey {
        PublicKey {
            coefficient_commitments: self.coefficient_commitments.clone(),
        }
    }
}

#[derive(Clone)]
pub struct PublicKey {
    /// "Published" polynomial coefficient commitments.
    pub(crate) coefficient_commitments: CoefficientCommitments,
}

impl PublicKey {
    pub fn coefficient_commitments(&self) -> &CoefficientCommitments {
        &self.coefficient_commitments
    }

    /// "commitment K_i,0 will serve as the public key for guardian G_i"
    pub fn public_key_k0(&self) -> &BigUint {
        self.coefficient_commitments.0[0].0.borrow()
    }

    /// Returns the public key as a big-endian byte vector of length l_p_bytes.
    pub fn to_be_bytes_len_p(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        //? TODO: Sure would be nice if we could avoid this allocation, but since we
        // store a BigUint representation, its length in bytes may be less than `l_p_bytes`.
        to_be_bytes_left_pad(&self.public_key_k0(), fixed_parameters.l_p_bytes())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::example_election_parameters::example_election_parameters;

    #[test]
    fn test_key_generation() {
        let mut csprng = Csprng::new(b"test_key_generation");

        let election_parameters = example_election_parameters();
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;

        //let hashes = Hashes::new(&election_parameters, &election_manifest);

        let n = varying_parameters.n as usize;
        let k = varying_parameters.k as usize;

        let guardian_private_keys = (0..n)
            .map(|_i| PrivateKey::generate(&mut csprng, &election_parameters))
            .collect::<Vec<_>>();

        let guardian_public_keys = guardian_private_keys
            .iter()
            .map(|private_key| private_key.make_public_key())
            .collect::<Vec<_>>();

        for guardian_private_key in guardian_private_keys.iter() {
            assert_eq!(guardian_private_key.secret_coefficients.0.len(), k);
            assert_eq!(guardian_private_key.coefficient_commitments.0.len(), k);

            for secret_coefficient in guardian_private_key.secret_coefficients.0.iter() {
                assert!(&secret_coefficient.0 < fixed_parameters.q.borrow());
            }

            for coefficient_commitment in guardian_private_key.coefficient_commitments.0.iter() {
                assert!(&coefficient_commitment.0 < fixed_parameters.p.borrow());
            }
        }

        for (i, guardian_public_key) in guardian_public_keys.iter().enumerate() {
            assert_eq!(guardian_public_key.coefficient_commitments.0.len(), k);

            for (j, coefficient_commitment) in guardian_public_key
                .coefficient_commitments
                .0
                .iter()
                .enumerate()
            {
                assert_eq!(
                    &coefficient_commitment.0,
                    &guardian_private_keys[i].coefficient_commitments.0[j].0
                );
            }

            assert_eq!(
                guardian_public_key.public_key_k0(),
                &guardian_public_key.coefficient_commitments.0[0].0
            );
        }
    }
}
