#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use itertools::izip;
use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use util::{
    csprng::Csprng,
    integer_util::{
        get_single_coefficient, group_lagrange_at_zero, to_be_bytes_left_pad, mod_inverse,
    },
};

use crate::{
    election_parameters::ElectionParameters,
    fixed_parameters::FixedParameters,
    guardian::GuardianIndex,
    guardian_share::GuardianSecretKeyShare,
    hash::{eg_h, HValue},
    joint_election_public_key::{Ciphertext, JointElectionPublicKey}, guardian_public_key::GuardianPublicKey,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionShare {
    pub i: GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub m_i: BigUint,
}

impl DecryptionShare {
    /// This function computes the [`DecryptionShare`] for a given ciphertext and secret key share.
    /// The arguments are
    /// - self - the encrypted share
    /// - fixed_parameters - the fixed parameters
    /// - secret_key_share - the secret key share
    /// - ciphertext - the ElGamal ciphertext
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

pub struct CombinedDecryptionShare(BigUint);

#[derive(Error, Debug)]
pub enum ShareCombinationError {
    #[error("Only {l} {desc} shares given, but at least {k} required.")]
    NotEnoughShares { l: usize, k: u32, desc: String },
    #[error("Guardian {i} is represented more than once in the {desc} shares.")]
    DuplicateGuardian { i: GuardianIndex, desc: String },
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("The decryption share has no inverse!")]
    NoInverse,
}

impl CombinedDecryptionShare {
    /// This functions combines decryption shares (cf. Equation 68 in specs 2.0.0)
    /// The arguments are
    /// - election_parameters - the election parameters
    /// - decryption_shares - a vector of decryption shares
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
            return Err(ShareCombinationError::NotEnoughShares {
                l,
                k,
                desc: "decryption".into(),
            });
        }
        // Verify that every guardian (index) is represented at most once.
        let mut seen = vec![false; n];
        for share in decryption_shares {
            let seen_ix = share.i.get_zero_based_usize();
            if seen[seen_ix] {
                return Err(ShareCombinationError::DuplicateGuardian {
                    i: share.i,
                    desc: "decryption".into(),
                });
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

    pub fn decrypt(
        &self,
        fixed_parameters: &FixedParameters,
        ciphertext: &Ciphertext,        
    ) -> Result<BigUint, DecryptionError> {
        let m_inv = mod_inverse(&self.0, fixed_parameters.p.as_ref());
        match m_inv {
            None =>  Err(DecryptionError::NoInverse),
            Some(m_inv) => Ok((ciphertext.beta.clone() * m_inv) % fixed_parameters.p.as_ref()),
        }
    }
}

/// The commitment share of a single guardian for a DecryptionProof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofCommitShare {
    pub i: GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub a_i: BigUint,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub b_i: BigUint,
}

/// The secret state for a commitment share of a single guardian for a DecryptionProof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofStateShare {
    pub i: GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub u_i: BigUint,
}

/// The response share of a single guardian for a DecryptionProof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofAnswerShare {
    pub i: GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub v_i: BigUint,
}

#[derive(Error, Debug)]
pub enum ResponseShareError {
    #[error("Indices of key share (here {i}) and state share (here {j}) must match!")]
    KeyStateShareIndexMismatch { i: GuardianIndex, j: GuardianIndex },
}

#[derive(Error, Debug)]
pub enum CombineProofError {
    #[error("The given list must be sorted the same way!")]
    IndexMismatch,
    #[error("The given list of public keys does not match the given joint public key!")]
    JointPKMissmatch,
    #[error("Could not combine the given decryption shares.")]
    ShareCombinationError,
    #[error("The commit message of guardian {0} is inconsistent!")]
    CommitInconsistency(GuardianIndex),
}

/// Proof that a given plaintext is the decryption of a given ciphertext relative to a given public key
/// Technically, this is a Sigma protocol for the dlog relation (also known as a Schnor proof)
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
    /// This function generates the commitment share and secret state for a decryption proof (cf. Equations 69 and 70 in the specs 2.0.0)
    /// The arguments are
    /// - csprng - secure randomness generator
    /// - fixed_parameters - the fixed parameters
    /// - ciphertext - the ElGamal ciphertext
    /// - i - the guardian index
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

    /// This function computes the challenge for the decryption NIZK as specified in Equation (71)
    /// The arguments are
    /// - h_e - the extended bash hash
    /// - k - the joint election public key
    /// - c - the ciphertext
    /// - a - first part of the commit message
    /// - b - second part of the commit message
    /// - m - combined decryption share
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

    /// This function computes a guardian's response share for the decryption NIZK as specified in Equation (73)
    /// The arguments are
    /// - fixed_parameters - the fixed parameters
    /// - h_e - the extended bash hash
    /// - k - the joint election public key
    /// - m - combined decryption share
    /// - ciphertext - the ciphertext
    /// - proof_commit_shares - the shares of the commit message
    /// - proof_commit_state - the guardian's commit state
    /// - secret_key_share - the guardian's key share
    pub fn generate_response_share(
        fixed_parameters: &FixedParameters,
        h_e: &HValue,
        k: &JointElectionPublicKey,
        ciphertext: &Ciphertext,
        m: &CombinedDecryptionShare,
        proof_commit_shares: &[DecryptionProofCommitShare],
        proof_commit_state: &DecryptionProofStateShare,
        secret_key_share: &GuardianSecretKeyShare,
    ) -> Result<DecryptionProofAnswerShare, ResponseShareError> {
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
        Ok(DecryptionProofAnswerShare {
            i: proof_commit_state.i,
            v_i,
        })
    }


    /// This function computes a decryption proof given the commit shares and 
    /// The arguments are
    /// - election_parameters - the election parameters
    /// - h_e - the extended bash hash
    /// - joint_key - the joint election public key
    /// - ciphertext - the ciphertext
    /// - decryption_shares - the decryption shares
    /// - proof_commit_shares - the shares of the commit message
    /// - proof_response_shares - the shares of the response
    /// - guardian_public_keys - the guardians' public keys
    /// This function checks that decryption_shares, proof_commit_shares,proof_response_shares, are *sorted* the same way, i.e. the i-th element in each list belongs to the same guardian. The function also checks that guardian_public_keys contains all n public keys. 
    pub fn combine_proof(
        election_parameters: &ElectionParameters,
        h_e: &HValue,
        joint_key: &JointElectionPublicKey,
        ciphertext: &Ciphertext,
        decryption_shares: &[DecryptionShare],
        proof_commit_shares: &[DecryptionProofCommitShare],
        proof_response_shares: &[DecryptionProofAnswerShare],
        guardian_public_keys: &[GuardianPublicKey],
    ) -> Result<Self,CombineProofError> {

        let fixed_parameters = &election_parameters.fixed_parameters;

        //Check that the indices match
        for (ds,cs,rs) in izip!(decryption_shares, proof_commit_shares, proof_response_shares) {
            if ds.i != cs.i || ds.i != rs.i {
                return Err(CombineProofError::IndexMismatch)
            }
        }

        //Check that the joint key matches the given public keys
        //This also checks that all public keys are given
        let computed_k = JointElectionPublicKey::compute(election_parameters, guardian_public_keys);
        match computed_k {
            Err(_) => return Err(CombineProofError::JointPKMissmatch),
            Ok(some_k) => { 
                if some_k != *joint_key {
                    return Err(CombineProofError::JointPKMissmatch)
                }
            },
        }

        let m = CombinedDecryptionShare::combine(election_parameters, decryption_shares);
        let m = match m {
            Ok(res) => res,
            Err(_) => {
                return Err(CombineProofError::ShareCombinationError)
            },
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
        for (ds,cs,rs,c_i) in izip!(decryption_shares, proof_commit_shares, proof_response_shares, c_i_vec) {
            let g_v = g.modpow(&rs.v_i,p);
            let i = BigUint::from(ds.i.get_one_based_u32());
            let k_prod = guardian_public_keys.iter().fold(BigUint::one(), |prod, pk|{
                let inner_p = pk.coefficient_commitments.0.iter().enumerate().fold(BigUint::one(), |prod, (m, k_m)| {
                    //This is fine as m < k
                    #[allow(clippy::unwrap_used)]
                    let m: u32 = m.try_into().unwrap();
                    (prod * k_m.0.modpow(&i.pow(m),p))%p
                });
                (prod * inner_p)%p
            });
            let a_i = (g_v * k_prod.modpow(&c_i, p))%p;

            let a_v = ciphertext.alpha.modpow(&rs.v_i, p);
            let m_c = m.0.modpow(&c_i, p);
            let b_i = (a_v * m_c)%p;

            if a_i != cs.a_i || b_i != cs.b_i {
                return Err(CombineProofError::CommitInconsistency(ds.i));
            }
            
        }

        let v = proof_response_shares.iter().fold(BigUint::one(), |prod, rs| {
            (prod * rs.v_i.clone())%q
        });

        Ok(DecryptionProof{challenge: c, response: v})
    }

    /// This function validates a decryption proof 
    /// The arguments are
    /// - self - the decryption proof
    /// - fixed_parameters - the fixed parameters
    /// - h_e - the extended bash hash
    /// - joint_key - the joint election public key
    /// - ciphertext - the ciphertext
    /// - m - combined decryption share
    pub fn validate(
        &self,
        fixed_parameters: &FixedParameters,
        h_e: &HValue,
        joint_key: &JointElectionPublicKey,
        ciphertext: &Ciphertext,
        m: &CombinedDecryptionShare,
    ) -> bool {
        let g = &fixed_parameters.g;
        let p = &fixed_parameters.p;

        let key = &joint_key.joint_election_public_key;

        let a = (g.modpow(&self.response, p.as_ref()) * key.modpow(&self.challenge, p.as_ref()))%p.as_ref();
        let b = (ciphertext.alpha.modpow(&self.response, p.as_ref()) * m.0.modpow(&self.challenge, p.as_ref()))%p.as_ref();

        //Check (9.A)
        if &self.response >= p.as_ref() {
            return false
        }
        let c = Self::challenge(h_e, &joint_key, ciphertext, &a, &b, m);
        //Check (9.B)
        if c != self.challenge {
            return false
        }
        return true
    }

}


pub struct VerifiedDecryption{
    plain_text: BigUint,
    proof: DecryptionProof,
}

impl VerifiedDecryption {

    pub fn new(
        fixed_parameters: &FixedParameters,
        ciphertext: &Ciphertext,
        m: CombinedDecryptionShare,
        proof: &DecryptionProof
    ) -> Option<Self> {
        let m_inv = mod_inverse(&m.0, fixed_parameters.p.as_ref());
        let plain_text = match m_inv {
            None =>  return None,
            Some(m_inv) => (ciphertext.beta.clone() * m_inv ) % fixed_parameters.p.as_ref(),
        };
        Some(VerifiedDecryption{plain_text, proof:proof.clone()})
    }

    /// This function checks the correctness of the decryption for given ciphertext and joint public key
    /// Arguments are
    /// - self - the verified decryption
    /// - fixed_parameters - the fixed parameters
    /// - h_e - the extended bash hash
    /// - joint_key - the joint election public key
    /// - ciphertext - the ciphertext
    pub fn verify(
        &self,
        fixed_parameters: &FixedParameters,
        h_e: &HValue,
        joint_key: &JointElectionPublicKey,
        ciphertext: &Ciphertext,        
    ) -> bool {
        let t_inv = mod_inverse(&self.plain_text, fixed_parameters.p.as_ref());
        let m = match t_inv {
            None =>  return false,
            Some(t_inv) => (ciphertext.beta.clone() * t_inv ) % fixed_parameters.p.as_ref(),
        };
        return self.proof.validate(fixed_parameters, h_e, joint_key, ciphertext, &CombinedDecryptionShare(m))
    }
}
