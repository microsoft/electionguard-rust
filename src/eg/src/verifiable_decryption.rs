#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides the implementation of verifiable decryption for [`Ciphertext`]s. For more details see Section `3.6` of the Electionguard specification `2.0.0`.

use crate::{
    discrete_log::DiscreteLog,
    election_parameters::ElectionParameters,
    fixed_parameters::FixedParameters,
    guardian::GuardianIndex,
    guardian_public_key::GuardianPublicKey,
    guardian_share::GuardianSecretKeyShare,
    hash::{eg_h, HValue},
    joint_election_public_key::{Ciphertext, JointElectionPublicKey},
};
use itertools::izip;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use util::{
    csprng::Csprng,
    integer_util::{
        get_single_coefficient, group_lagrange_at_zero, mod_inverse, to_be_bytes_left_pad,
    },
};

/// A decryption share is a guardian's partial decryption of a given ciphertext.
///
/// This corresponds to the `M_i` in Section `3.6.2`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionShare {
    /// The guardian's index
    pub i: GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    /// The decryption share value
    pub m_i: BigUint,
}

impl DecryptionShare {
    /// This function computes the [`DecryptionShare`] for a given [`Ciphertext`] and [`GuardianSecretKeyShare`].
    ///
    /// The arguments are
    /// - `self` - the encrypted share
    /// - `fixed_parameters` - the fixed parameters
    /// - `secret_key_share` - the secret key share
    /// - `ciphertext` - the ElGamal ciphertext
    pub fn from(
        fixed_parameters: &FixedParameters,
        secret_key_share: &GuardianSecretKeyShare,
        ciphertext: &Ciphertext,
    ) -> Self {
        let m_i = ciphertext
            .alpha
            .modpow(&secret_key_share.p_i, fixed_parameters.p.as_ref());
        DecryptionShare {
            i: secret_key_share.i,
            m_i,
        }
    }
}

/// The combined decryption share allows to compute the plain-text from a given ciphertext.
///
/// This corresponds to the `M` in Section `3.6.2`.
pub struct CombinedDecryptionShare(BigUint);

/// Represents errors occurring while combining [`DecryptionShare`]s into a [`CombinedDecryptionShare`].
#[derive(Error, Debug)]
pub enum ShareCombinationError {
    /// Occurs if not enough shares were provided. Combination requires shares from at least `k` out of `n` guardians.
    #[error("Only {l} decryption shares given, but at least {k} required.")]
    NotEnoughShares { l: usize, k: u32 },
    /// Occurs if multiple shares from the same guardian are provided.
    #[error("Guardian {i} is represented more than once in the decryption shares.")]
    DuplicateGuardian { i: GuardianIndex },
}

impl CombinedDecryptionShare {
    /// Computes the combination of [`DecryptionShare`]s.
    ///
    /// The arguments are
    /// - `election_parameters` - the election parameters
    /// - `decryption_shares` - a vector of decryption shares
    ///
    /// The computation follows Equation `68`.
    pub fn combine(
        election_parameters: &ElectionParameters,
        decryption_shares: &[DecryptionShare],
    ) -> Result<Self, ShareCombinationError> {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;
        let n = varying_parameters.n.get_one_based_usize();
        let k = varying_parameters.k.get_one_based_u32();

        let l = decryption_shares.len();
        // Ensure that we have at least k decryption shares
        if l < k as usize {
            return Err(ShareCombinationError::NotEnoughShares { l, k });
        }
        // Verify that every guardian (index) is represented at most once.
        let mut seen = vec![false; n];
        for share in decryption_shares {
            let seen_ix = share.i.get_zero_based_usize();
            if seen[seen_ix] {
                return Err(ShareCombinationError::DuplicateGuardian { i: share.i });
            }
            seen[seen_ix] = true;
        }

        let xs: Vec<_> = decryption_shares
            .iter()
            .map(|s| BigUint::from(s.i.get_one_based_u32()))
            .collect();
        let ys: Vec<_> = decryption_shares.iter().map(|s| s.m_i.clone()).collect();

        Ok(CombinedDecryptionShare(group_lagrange_at_zero(
            &xs,
            &ys,
            &fixed_parameters.q,
            &fixed_parameters.p,
        )))
    }
}

/// The commitment share of a single guardian for a [`DecryptionProof`].
///
/// This corresponds to `(a_i,b_i)` in Equation `69`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofCommitShare {
    /// The guardian's index
    pub i: GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    /// First part of the commit share
    pub a_i: BigUint,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    /// Second part of the commit share
    pub b_i: BigUint,
}

/// The secret state for a commitment share of a single guardian for a [`DecryptionProof`].
///
/// This corresponds to `u_i` as in Equation `69`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofStateShare {
    /// The guardian's index
    pub i: GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    /// The commit state
    pub u_i: BigUint,
}

/// The response share of a single guardian for a [`DecryptionProof`].
///
/// This corresponds to `v_i` as in Equation `73`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofResponseShare {
    /// The guardian's index
    pub i: GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    /// The response share
    pub v_i: BigUint,
}

/// Represents errors occurring while computing a response share.
#[derive(Error, Debug)]
pub enum ResponseShareError {
    /// Occurs if one tries to compute the response from a state share that does not match the secret key share.
    #[error("Indices of key share (here {i}) and state share (here {j}) must match!")]
    KeyStateShareIndexMismatch { i: GuardianIndex, j: GuardianIndex },
}

/// Represents errors occurring while combining the commit and response shares into a single [`DecryptionProof`].
#[derive(Error, Debug)]
pub enum CombineProofError {
    /// Occurs if the input list are not ordered the same way.
    #[error("The given list must be ordered the same way!")]
    IndexMismatch,
    /// Occurs if the joint public key does not match the list of public keys.
    #[error("The given list of public keys does not match the given joint public key!")]
    JointPKMissmatch,
    /// Occurs if the decryption shares could not be combined.
    #[error("Could not combine the given decryption shares: {0}")]
    ShareCombinationError(ShareCombinationError),
    /// Occurs if the commitment and response shares are inconsistent (Checks `9.A` and `9.B`).
    #[error("The commit message ({1}) of guardian {0} is inconsistent!")]
    CommitInconsistency(GuardianIndex, String),
}

/// Proof that a given plaintext is the decryption of a given ciphertext relative to a given public key.
///
/// This is a Sigma protocol for a discrete logarithm relation. It corresponds to the proof from Section `3.6.3`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProof {
    /// Challenge
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub challenge: BigUint,
    /// Response
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub response: BigUint,
}

impl DecryptionProof {
    /// This function generates the commitment share and secret state for a decryption proof.
    ///
    /// The arguments are
    /// - `csprng` - secure randomness generator
    /// - `fixed_parameters` - the fixed parameters
    /// - `ciphertext` - the ElGamal ciphertext
    /// - `i` - the guardian index
    ///
    /// The computation follows Equations `69` and `70`.
    pub fn generate_commit_share(
        csprng: &mut Csprng,
        fixed_parameters: &FixedParameters,
        ciphertext: &Ciphertext,
        i: &GuardianIndex,
    ) -> (DecryptionProofCommitShare, DecryptionProofStateShare) {
        let p = fixed_parameters.p.as_ref();
        let q = fixed_parameters.q.as_ref();
        let g = &fixed_parameters.g;
        let u_i = csprng.next_biguint_lt(q);
        let a_i = g.modpow(&u_i, p);
        let b_i = ciphertext.alpha.modpow(&u_i, p);
        let dcs = DecryptionProofCommitShare { i: *i, a_i, b_i };
        let dss = DecryptionProofStateShare { i: *i, u_i };
        (dcs, dss)
    }

    /// This function computes the challenge for the decryption NIZK.
    ///
    /// The computation corresponds to Equation `71`.
    ///
    /// The arguments are
    /// - `h_e` - the extended bash hash
    /// - `k` - the joint election public key
    /// - `c` - the ciphertext
    /// - `a` - first part of the commit message
    /// - `b` - second part of the commit message
    /// - `m` - combined decryption share
    fn challenge(
        h_e: &HValue,
        k: &JointElectionPublicKey,
        c: &Ciphertext,
        a: &BigUint,
        b: &BigUint,
        m: &CombinedDecryptionShare,
    ) -> BigUint {
        // v = 0x30 | b(k,512) | b(c.A,512)| b(c.B,512) | b(a,512) | b(b,512) | b(m,512)
        let mut v = vec![0x30];
        v.extend_from_slice(to_be_bytes_left_pad(&k.joint_election_public_key, 512).as_slice());
        v.extend_from_slice(to_be_bytes_left_pad(&c.alpha, 512).as_slice());
        v.extend_from_slice(to_be_bytes_left_pad(&c.beta, 512).as_slice());
        v.extend_from_slice(to_be_bytes_left_pad(a, 512).as_slice());
        v.extend_from_slice(to_be_bytes_left_pad(b, 512).as_slice());
        v.extend_from_slice(to_be_bytes_left_pad(&m.0, 512).as_slice());
        let c = eg_h(h_e, &v);
        //The challenge is not reduced modulo q (cf. Section 5.4)
        BigUint::from_bytes_be(c.0.as_slice())
    }

    /// This function computes a guardian's response share for the decryption NIZK.
    ///
    /// This corresponds to the computation specified in Equation `73`.
    ///
    /// The arguments are
    /// - `fixed_parameters` - the fixed parameters
    /// - `h_e` - the extended bash hash
    /// - `k` - the joint election public key
    /// - `m` - combined decryption share
    /// - `ciphertext` - the ciphertext
    /// - `proof_commit_shares` - the shares of the commit message
    /// - `proof_commit_state` - the guardian's commit state
    /// - `secret_key_share` - the guardian's key share
    pub fn generate_response_share(
        fixed_parameters: &FixedParameters,
        h_e: &HValue,
        k: &JointElectionPublicKey,
        ciphertext: &Ciphertext,
        m: &CombinedDecryptionShare,
        proof_commit_shares: &[DecryptionProofCommitShare],
        proof_commit_state: &DecryptionProofStateShare,
        secret_key_share: &GuardianSecretKeyShare,
    ) -> Result<DecryptionProofResponseShare, ResponseShareError> {
        if proof_commit_state.i != secret_key_share.i {
            return Err(ResponseShareError::KeyStateShareIndexMismatch {
                i: proof_commit_state.i,
                j: secret_key_share.i,
            });
        }

        let p = fixed_parameters.p.as_ref();
        let q = fixed_parameters.q.as_ref();

        let (a, b) = proof_commit_shares
            .iter()
            .fold((BigUint::one(), BigUint::one()), |(a, b), share| {
                ((a * share.a_i.clone()) % p, (b * share.b_i.clone()) % p)
            });

        let c = Self::challenge(h_e, k, ciphertext, &a, &b, m);
        let i_big = BigUint::from(proof_commit_state.i.get_one_based_u32());
        let xs: Vec<BigUint> = proof_commit_shares
            .iter()
            .map(|s| BigUint::from(s.i.get_one_based_u32()))
            .collect();
        let w_i = get_single_coefficient(&xs, &i_big, &fixed_parameters.q);
        let c_i = (c * w_i) % q;

        let v_i = fixed_parameters.q.subtract_group_elem(
            &proof_commit_state.u_i,
            &(c_i * secret_key_share.p_i.clone()),
        );
        Ok(DecryptionProofResponseShare {
            i: proof_commit_state.i,
            v_i,
        })
    }

    /// This function computes a decryption proof given the commit and response shares.
    ///
    /// The arguments are
    /// - `election_parameters` - the election parameters
    /// - `h_e` - the extended bash hash
    /// - `joint_key` - the joint election public key
    /// - `ciphertext` - the ciphertext
    /// - `decryption_shares` - the decryption shares
    /// - `proof_commit_shares` - the shares of the commit message
    /// - `proof_response_shares` - the shares of the response
    /// - `guardian_public_keys` - the guardians' public keys
    ///
    /// This function checks that decryption_shares, proof_commit_shares,
    /// proof_response_shares, are *ordered* the same way,
    /// i.e. the i-th element in each list belongs to the same guardian.
    /// The function also checks that guardian_public_keys contains all n public keys.
    pub fn combine_proof(
        election_parameters: &ElectionParameters,
        h_e: &HValue,
        joint_key: &JointElectionPublicKey,
        ciphertext: &Ciphertext,
        decryption_shares: &[DecryptionShare],
        proof_commit_shares: &[DecryptionProofCommitShare],
        proof_response_shares: &[DecryptionProofResponseShare],
        guardian_public_keys: &[GuardianPublicKey],
    ) -> Result<Self, CombineProofError> {
        let fixed_parameters = &election_parameters.fixed_parameters;

        //Check that the indices match
        for (ds, cs, rs) in izip!(
            decryption_shares,
            proof_commit_shares,
            proof_response_shares
        ) {
            if ds.i != cs.i || ds.i != rs.i {
                return Err(CombineProofError::IndexMismatch);
            }
        }

        //Check that the joint key matches the given public keys
        //This also checks that all public keys are given
        let computed_k = JointElectionPublicKey::compute(election_parameters, guardian_public_keys);
        match computed_k {
            Err(_) => return Err(CombineProofError::JointPKMissmatch),
            Ok(some_k) => {
                if some_k != *joint_key {
                    return Err(CombineProofError::JointPKMissmatch);
                }
            }
        }

        let m = CombinedDecryptionShare::combine(election_parameters, decryption_shares);
        let m = match m {
            Ok(res) => res,
            Err(e) => return Err(CombineProofError::ShareCombinationError(e)),
        };

        let p = fixed_parameters.p.as_ref();
        let q = fixed_parameters.q.as_ref();
        let g = &fixed_parameters.g;

        let (a, b) = proof_commit_shares
            .iter()
            .fold((BigUint::one(), BigUint::one()), |(a, b), share| {
                ((a * share.a_i.clone()) % p, (b * share.b_i.clone()) % p)
            });
        let c = Self::challenge(h_e, joint_key, ciphertext, &a, &b, &m);

        let xs: Vec<BigUint> = proof_commit_shares
            .iter()
            .map(|s| BigUint::from(s.i.get_one_based_u32()))
            .collect();
        let mut c_i_vec = vec![];
        for cs in proof_commit_shares {
            let i = BigUint::from(cs.i.get_one_based_u32());
            let w_i = get_single_coefficient(&xs, &i, &fixed_parameters.q);
            let c_i = (c.clone() * w_i) % q;
            c_i_vec.push(c_i);
        }

        // Check Equations (74) and (75)
        for (ds, cs, rs, c_i) in izip!(
            decryption_shares,
            proof_commit_shares,
            proof_response_shares,
            c_i_vec
        ) {
            let g_v = g.modpow(&rs.v_i, p);
            let i = BigUint::from(ds.i.get_one_based_u32());
            let k_prod = guardian_public_keys
                .iter()
                .fold(BigUint::one(), |prod, pk| {
                    let inner_p = pk.coefficient_commitments.0.iter().enumerate().fold(
                        BigUint::one(),
                        |prod, (m, k_m)| {
                            //This is fine as m < k
                            #[allow(clippy::unwrap_used)]
                            let m: u32 = m.try_into().unwrap();
                            (prod * k_m.0.modpow(&i.pow(m), p)) % p
                        },
                    );
                    (prod * inner_p) % p
                });
            let a_i = (g_v * k_prod.modpow(&c_i, p)) % p;

            let a_v = ciphertext.alpha.modpow(&rs.v_i, p);
            let m_c = ds.m_i.modpow(&c_i, p);
            let b_i = (a_v * m_c) % p;

            if a_i != cs.a_i {
                return Err(CombineProofError::CommitInconsistency(
                    ds.i,
                    "a_i != a_i'".into(),
                ));
            }
            if b_i != cs.b_i {
                return Err(CombineProofError::CommitInconsistency(
                    ds.i,
                    "b_i != b_i'".into(),
                ));
            }
        }

        let v = proof_response_shares
            .iter()
            .fold(BigUint::zero(), |sum, rs| (sum + rs.v_i.clone()) % q);

        Ok(DecryptionProof {
            challenge: c,
            response: v,
        })
    }

    /// This function validates a decryption proof.
    ///
    /// The arguments are
    /// - `self` - the decryption proof
    /// - `fixed_parameters` - the fixed parameters
    /// - `h_e` - the extended bash hash
    /// - `joint_key` - the joint election public key
    /// - `ciphertext` - the ciphertext
    /// - `m` - combined decryption share
    pub fn validate(
        &self,
        fixed_parameters: &FixedParameters,
        h_e: &HValue,
        joint_key: &JointElectionPublicKey,
        ciphertext: &Ciphertext,
        m: &CombinedDecryptionShare,
    ) -> bool {
        let g = &fixed_parameters.g;
        let p = fixed_parameters.p.as_ref();

        let key = &joint_key.joint_election_public_key;

        let a = (g.modpow(&self.response, p) * key.modpow(&self.challenge, p)) % p;
        let b = (ciphertext.alpha.modpow(&self.response, p) * m.0.modpow(&self.challenge, p)) % p;

        //Check (9.A)
        if &self.response >= p {
            return false;
        }
        let c = Self::challenge(h_e, joint_key, ciphertext, &a, &b, m);
        //Check (9.B)
        if c != self.challenge {
            return false;
        }
        true
    }
}

/// Represents errors occurring during decryption.
#[derive(Error, Debug)]
pub enum DecryptionError {
    /// Occurs if the combined decryption share has no inverse.
    #[error("The combined decryption share has no inverse!")]
    NoInverse,
    /// Occurs if the computation of the plain-text from `T` and the joint public-key fails.
    #[error("Could not compute the plaintext using dlog!")]
    NoDlog,
}

/// Represents a "in-the-exponent" plain-text with a [`DecryptionProof`].
///
/// This corresponds to `t` and `(c,v)` as in Section `3.6.3`.
pub struct VerifiableDecryption {
    /// The decrypted plain-text
    pub plain_text: BigUint,
    /// The proof of correctness
    pub proof: DecryptionProof,
}

impl VerifiableDecryption {
    /// This function computes a verifiable decryption.
    ///
    /// The arguments are
    /// - `fixed_parameters` - the fixed parameters
    /// - `joint_key` - the joint election public key
    /// - `ciphertext` - the ciphertext
    /// - `m` - combined decryption share
    /// - `proof` - the proof of correctness
    pub fn new(
        fixed_parameters: &FixedParameters,
        joint_key: &JointElectionPublicKey,
        ciphertext: &Ciphertext,
        m: &CombinedDecryptionShare,
        proof: &DecryptionProof,
    ) -> Result<Self, DecryptionError> {
        let m_inv = mod_inverse(&m.0, fixed_parameters.p.as_ref());
        let group_msg = match m_inv {
            None => return Err(DecryptionError::NoInverse),
            Some(m_inv) => (ciphertext.beta.clone() * m_inv) % fixed_parameters.p.as_ref(),
        };
        let base = &joint_key.joint_election_public_key;
        let p = fixed_parameters.p.as_ref();
        let dlog = DiscreteLog::new(base, p);
        let plain_text = match dlog.find(base, p, &group_msg) {
            None => return Err(DecryptionError::NoDlog),
            Some(x) => x,
        };
        Ok(VerifiableDecryption {
            plain_text,
            proof: proof.clone(),
        })
    }

    /// This function checks the correctness of the decryption for given ciphertext and joint public key.
    ///
    /// Arguments are
    /// - `self` - the verifiable decryption
    /// - `fixed_parameters` - the fixed parameters
    /// - `h_e` - the extended bash hash
    /// - `joint_key` - the joint election public key
    /// - `ciphertext` - the ciphertext
    pub fn verify(
        &self,
        fixed_parameters: &FixedParameters,
        h_e: &HValue,
        joint_key: &JointElectionPublicKey,
        ciphertext: &Ciphertext,
    ) -> bool {
        let t = joint_key
            .joint_election_public_key
            .modpow(&self.plain_text, fixed_parameters.p.as_ref());
        let t_inv = mod_inverse(&t, fixed_parameters.p.as_ref());
        let m = match t_inv {
            None => return false,
            Some(t_inv) => (ciphertext.beta.clone() * t_inv) % fixed_parameters.p.as_ref(),
        };
        self.proof.validate(
            fixed_parameters,
            h_e,
            joint_key,
            ciphertext,
            &CombinedDecryptionShare(m),
        )
    }
}

#[cfg(test)]
mod test {
    use num_bigint::BigUint;
    use std::iter::zip;
    use util::csprng::Csprng;

    use crate::{
        election_parameters::ElectionParameters,
        example_election_parameters::example_election_parameters,
        guardian_public_key::GuardianPublicKey,
        guardian_secret_key::GuardianSecretKey,
        guardian_share::{GuardianEncryptedShare, GuardianSecretKeyShare},
        hash::HValue,
        joint_election_public_key::JointElectionPublicKey,
    };

    use super::{CombinedDecryptionShare, DecryptionProof, DecryptionShare, VerifiableDecryption};

    fn key_setup(
        csprng: &mut Csprng,
        election_parameters: &ElectionParameters,
    ) -> (
        JointElectionPublicKey,
        Vec<GuardianPublicKey>,
        Vec<GuardianSecretKeyShare>,
    ) {
        let varying_parameters = &election_parameters.varying_parameters;
        //Setup some keys
        let guardian_secret_keys = varying_parameters
            .each_guardian_i()
            .map(|i| GuardianSecretKey::generate(csprng, &election_parameters, i, None))
            .collect::<Vec<_>>();
        let guardian_public_keys = guardian_secret_keys
            .iter()
            .map(|secret_key| secret_key.make_public_key())
            .collect::<Vec<_>>();
        let share_vecs = guardian_public_keys
            .iter()
            .map(|pk| {
                guardian_secret_keys
                    .iter()
                    .map(|dealer_sk| {
                        GuardianEncryptedShare::new(csprng, &election_parameters, dealer_sk, &pk)
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
        let joint_key =
            JointElectionPublicKey::compute(election_parameters, &guardian_public_keys).unwrap();
        (joint_key, guardian_public_keys, key_shares)
    }

    #[test]
    fn test_decryption_overall() {
        let mut csprng = Csprng::new(b"test_proof_generation");
        let election_parameters = example_election_parameters();
        let fixed_parameters = &election_parameters.fixed_parameters;
        //The exact value does not matter
        let h_e = HValue::default();

        let (joint_key, public_keys, key_shares) = key_setup(&mut csprng, &election_parameters);

        let message: usize = 42;
        let nonce = csprng.next_biguint_lt(fixed_parameters.q.as_ref());
        let ciphertext = joint_key.encrypt_with(fixed_parameters, &nonce, message, false);

        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|ks| DecryptionShare::from(fixed_parameters, ks, &ciphertext))
            .collect();
        let combined_dec_share =
            CombinedDecryptionShare::combine(&election_parameters, &dec_shares).unwrap();

        let mut com_shares = vec![];
        let mut com_states = vec![];
        for ks in key_shares.iter() {
            let (share, state) = DecryptionProof::generate_commit_share(
                &mut csprng,
                fixed_parameters,
                &ciphertext,
                &ks.i,
            );
            com_shares.push(share);
            com_states.push(state);
        }
        let rsp_shares: Vec<_> = com_states
            .iter()
            .zip(&key_shares)
            .map(|(state, key_share)| {
                DecryptionProof::generate_response_share(
                    fixed_parameters,
                    &h_e,
                    &joint_key,
                    &ciphertext,
                    &combined_dec_share,
                    &com_shares,
                    state,
                    &key_share,
                )
                .unwrap()
            })
            .collect();

        let proof = DecryptionProof::combine_proof(
            &election_parameters,
            &h_e,
            &joint_key,
            &ciphertext,
            &dec_shares,
            &com_shares,
            &rsp_shares,
            &public_keys,
        )
        .unwrap();

        let decryption = VerifiableDecryption::new(
            fixed_parameters,
            &joint_key,
            &ciphertext,
            &combined_dec_share,
            &proof,
        )
        .unwrap();

        assert_eq!(
            decryption.plain_text,
            BigUint::from(message),
            "Decryption should match the message."
        );
        assert!(decryption.verify(fixed_parameters, &h_e, &joint_key, &ciphertext))
    }
}
