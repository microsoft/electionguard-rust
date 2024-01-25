// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{bail, ensure, Context, Result};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

use crate::{
    election_parameters::ElectionParameters, fixed_parameters::FixedParameters,
    guardian_public_key::GuardianPublicKey, index::Index,
};

/// The joint election public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JointElectionPublicKey {
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub joint_election_public_key: BigUint,
}

/// A 1-based index of a [`Ciphertext`] in the order it is defined in the [`crate::contest_encrypted::ContestEncrypted`].
pub type CiphertextIndex = Index<Ciphertext>;

/// The ciphertext used to store a vote value corresponding to one option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub alpha: BigUint,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub beta: BigUint,
}

/// The encryption nonce used to produce a [`Ciphertext`]
/// Relevant for producing proofs about the plaintext.
#[derive(Debug, Clone)]
pub struct Nonce {
    pub xi: BigUint,
}

impl Nonce {
    pub fn new(xi: BigUint) -> Nonce {
        Nonce { xi }
    }

    pub fn zero() -> Nonce {
        Nonce {
            xi: BigUint::zero(),
        }
    }
}

impl Ciphertext {
    pub fn one() -> Ciphertext {
        Ciphertext {
            alpha: BigUint::one(),
            beta: BigUint::one(),
        }
    }

    pub fn scale(&self, fixed_parameters: &FixedParameters, factor: BigUint) -> Ciphertext {
        let alpha = self.alpha.modpow(&factor, fixed_parameters.p.as_ref());
        let beta = self.beta.modpow(&factor, fixed_parameters.p.as_ref());
        Ciphertext{alpha, beta}
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.alpha == other.alpha && self.beta == other.beta
    }
}

impl JointElectionPublicKey {
    pub fn compute(
        election_parameters: &ElectionParameters,
        guardian_public_keys: &[GuardianPublicKey],
    ) -> Result<Self> {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;
        let n = varying_parameters.n.get_one_based_usize();

        // Validate every supplied guardian public key.
        for guardian_public_key in guardian_public_keys {
            guardian_public_key.validate(election_parameters)?;
        }

        // Verify that every guardian is represented exactly once.
        let mut seen = vec![false; n];
        for guardian_public_key in guardian_public_keys {
            let seen_ix = guardian_public_key.i.get_zero_based_usize();

            ensure!(
                !seen[seen_ix],
                "Guardian {} is represented more than once in the guardian public keys",
                guardian_public_key.i
            );

            seen[seen_ix] = true;
        }

        let missing_guardian_ixs: Vec<usize> = seen
            .iter()
            .enumerate()
            .filter(|&(_ix, &seen)| !seen)
            .map(|(ix, _)| ix)
            .collect();

        if !missing_guardian_ixs.is_empty() {
            //? TODO Consider using `.intersperse(", ")` when it's stable.
            // https://github.com/rust-lang/rust/issues/79524
            let iter = missing_guardian_ixs.iter().enumerate().map(|(n, ix)| {
                let guardian_i = ix + 1;
                if 0 == n {
                    format!("{guardian_i}")
                } else {
                    format!(", {guardian_i}")
                }
            });

            bail!("Guardian(s) {iter:?} are not represented in the guardian public keys");
        }

        let joint_election_public_key = guardian_public_keys.iter().fold(
            BigUint::one(),
            |mut acc, guardian_public_key| -> BigUint {
                acc *= guardian_public_key.public_key_k_i_0();
                acc % fixed_parameters.p.as_ref()
            },
        );

        Ok(Self {
            joint_election_public_key,
        })
    }

    pub fn encrypt_with(
        &self,
        fixed_parameters: &FixedParameters,
        nonce: &BigUint,
        vote: usize,
    ) -> Ciphertext {
        let alpha = fixed_parameters
            .g
            .modpow(nonce, fixed_parameters.p.as_ref());
        let beta = self
            .joint_election_public_key
            .modpow(&(nonce + vote), fixed_parameters.p.as_ref());

        Ciphertext { alpha, beta }
    }

    /// Reads a `JointElectionPublicKey` from a `std::io::Read` and validates it.
    pub fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        election_parameters: &ElectionParameters,
    ) -> Result<Self> {
        let self_: Self =
            serde_json::from_reader(stdioread).context("Reading JointElectionPublicKey")?;

        self_.validate(election_parameters)?;

        Ok(self_)
    }

    /// Verifies that the `JointElectionPublicKey` conforms to the election parameters.
    /// Useful after deserialization.
    pub fn validate(&self, election_parameters: &ElectionParameters) -> Result<()> {
        ensure!(
            election_parameters
                .fixed_parameters
                .is_valid_modp(&self.joint_election_public_key),
            "JointElectionPublicKey is not valid mod p"
        );
        Ok(())
    }

    /// Returns the `JointElectionPublicKey` as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_len_p(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        fixed_parameters.biguint_to_be_bytes_len_p(&self.joint_election_public_key)
    }

    /// Writes a `JointElectionPublicKey` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing JointElectionPublicKey")
    }
}

impl AsRef<BigUint> for JointElectionPublicKey {
    #[inline]
    fn as_ref(&self) -> &BigUint {
        &self.joint_election_public_key
    }
}


#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use num_bigint::BigUint;
    use num_traits::{Zero, One};
    use util::{csprng::Csprng, integer_util::mod_inverse};

    use crate::{example_election_parameters::example_election_parameters, guardian_secret_key::{GuardianSecretKey, SecretCoefficient}, index::Index, fixed_parameters::FixedParameters, discrete_log::DiscreteLog};

    use super::{JointElectionPublicKey, Ciphertext};

    fn g_key(i: u32) -> GuardianSecretKey {
        let mut seed = Vec::new();
        let customization_data = format!("GuardianSecretKeyGenerate({})", i.clone());
        seed.extend_from_slice(&(customization_data.as_bytes().len() as u64).to_be_bytes());
        seed.extend_from_slice(customization_data.as_bytes());

        let mut csprng = Csprng::new(&seed);

        let secret_key = GuardianSecretKey::generate(
            &mut csprng,
            &example_election_parameters(),
            Index::from_one_based_index_const(i).unwrap(),
            None,
        );
        secret_key
    }

    fn decrypt_ciphertext(ciphertext: &Ciphertext, joint_key: &JointElectionPublicKey, s: &SecretCoefficient, fixed_parameters: &FixedParameters) -> BigUint {
        let s = &s.0;
        let p = fixed_parameters.p.as_ref();
        let alpha_s = ciphertext.alpha.modpow(s, p);
        let alpha_s_inv = mod_inverse(&alpha_s, fixed_parameters.p.as_ref()).unwrap();

        let group_msg = &ciphertext.beta * &alpha_s_inv % p;
        let base = &joint_key.joint_election_public_key;
        let dlog = DiscreteLog::new(base, p);
        let plain_text = dlog.find(base, p, &group_msg).unwrap();
        plain_text
    }

    #[test]
    pub fn test_scaling_ciphertext(){
        let election_parameters = example_election_parameters();
        let sks: Vec<_> = (1..6).map(|i|g_key(i)).collect();
        let guardian_public_keys: Vec<_> = sks.iter().map(|sk|sk.make_public_key()).collect();

        let sk = sks.iter().fold(BigUint::zero(), |a,b| a+&b.secret_coefficients.0[0].0);
        let s = SecretCoefficient(sk);

        let joint_election_public_key =
            JointElectionPublicKey::compute(&election_parameters, guardian_public_keys.as_slice())
                .unwrap();
        let nonce = BigUint::from(5u8);
        let encryption = joint_election_public_key.encrypt_with(&election_parameters.fixed_parameters, &nonce, 1);
        let factor = BigUint::new(vec![0, 64u32]); // 2^38
        let factor = factor - BigUint::one(); // 2^38 - 1
        let encryption = encryption.scale(&election_parameters.fixed_parameters, factor.clone());
        let result = decrypt_ciphertext(&encryption, &joint_election_public_key, &s, &election_parameters.fixed_parameters);

        assert_eq!(result, factor);
    }
}