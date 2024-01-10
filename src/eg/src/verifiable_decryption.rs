#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides the implementation of verifiable decryption for
//! [`Ciphertext`]s. For more details see Section `3.6` of the Electionguard
//! specification `2.0.0`.

use crate::{
    discrete_log::DiscreteLog,
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    fixed_parameters::FixedParameters,
    guardian::GuardianIndex,
    guardian_public_key::GuardianPublicKey,
    guardian_share::GuardianSecretKeyShare,
    hash::eg_h,
    hashes::Hashes,
    hashes_ext::HashesExt,
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
        get_single_coefficient_at_zero, group_lagrange_at_zero, mod_inverse, to_be_bytes_left_pad,
    },
};

/// A decryption share is a guardian's partial decryption of a given ciphertext.
///
/// This corresponds to the `M_i` in Section `3.6.2`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionShare {
    /// The guardian's index
    pub i:   GuardianIndex,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    /// The decryption share value
    pub m_i: BigUint,
}

impl DecryptionShare {
    /// This function computes the [`DecryptionShare`] for a given
    /// [`Ciphertext`] and [`GuardianSecretKeyShare`].
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

/// The combined decryption share allows to compute the plain-text from a given
/// ciphertext.
///
/// This corresponds to the `M` in Section `3.6.2`.
#[derive(Debug)]
pub struct CombinedDecryptionShare(BigUint);

/// Represents errors occurring while combining [`DecryptionShare`]s into a
/// [`CombinedDecryptionShare`].
#[derive(Error, Debug, PartialEq)]
pub enum ShareCombinationError {
    /// Occurs if not enough shares were provided. Combination requires shares
    /// from at least `k` out of `n` guardians.
    #[error("Only {l} decryption shares given, but at least {k} required.")]
    NotEnoughShares { l: usize, k: u32 },
    /// Occurs if the guardian index is out of bounds.
    #[error("Guardian {i} is has an index bigger than {n}")]
    InvalidGuardian { i: GuardianIndex, n: GuardianIndex },
    /// Occurs if multiple shares from the same guardian are provided.
    #[error("Guardian {i} is represented more than once in the decryption shares.")]
    DuplicateGuardian { i: GuardianIndex },
    /// Occurs if the Lagrange interpolation fails.
    #[error("Could not compute the polynomial interpolation.")]
    InterpolationFailure,
}

impl CombinedDecryptionShare {
    /// Computes the combination of [`DecryptionShare`]s.
    ///
    /// The arguments are
    /// - `election_parameters` - the election parameters
    /// - `decryption_shares` - a vector of decryption shares
    ///
    /// The computation follows Equation `68`.
    pub fn combine<'a, I>(
        election_parameters: &ElectionParameters,
        decryption_shares: I,
    ) -> Result<Self, ShareCombinationError>
    where
        I: IntoIterator<Item = &'a DecryptionShare>,
        I::IntoIter: ExactSizeIterator, {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;
        let n = varying_parameters.n.get_one_based_usize();
        let k = varying_parameters.k.get_one_based_u32();

        let decryption_shares = decryption_shares.into_iter();
        let l = decryption_shares.len();
        // Ensure that we have at least k decryption shares
        if l < k as usize {
            return Err(ShareCombinationError::NotEnoughShares { l, k });
        }
        // Verify that every guardian (index) is represented at most once and that all
        // guardians indices are within the bounds.
        let mut seen = vec![false; n];
        let mut xs = Vec::with_capacity(l);
        let mut ys = Vec::with_capacity(l);
        for share in decryption_shares {
            let seen_ix = share.i.get_zero_based_usize();
            if seen_ix >= n {
                return Err(ShareCombinationError::InvalidGuardian {
                    i: share.i,
                    n: varying_parameters.n,
                });
            }
            if seen[seen_ix] {
                return Err(ShareCombinationError::DuplicateGuardian { i: share.i });
            }
            seen[seen_ix] = true;
            xs.push(BigUint::from(share.i.get_one_based_u32()));
            ys.push(share.m_i.clone());
        }

        let m = group_lagrange_at_zero(&xs, &ys, &fixed_parameters.q, &fixed_parameters.p);

        match m {
            // This should not happen
            None => Err(ShareCombinationError::InterpolationFailure),
            Some(m) => Ok(CombinedDecryptionShare(m)),
        }
    }
}

/// The commitment share of a single guardian for a [`DecryptionProof`].
///
/// This corresponds to `(a_i,b_i)` in Equation `69`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofCommitShare {
    /// The guardian's index
    pub i:   GuardianIndex,
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

/// The secret state for a commitment share of a single guardian for a
/// [`DecryptionProof`].
///
/// This corresponds to `u_i` as in Equation `69`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofStateShare {
    /// The guardian's index
    pub i:   GuardianIndex,
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
    pub i:   GuardianIndex,
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
    /// Occurs if one tries to compute the response from a state share that does
    /// not match the secret key share.
    #[error("Indices of key share (here {i}) and state share (here {j}) must match!")]
    KeyStateShareIndexMismatch { i: GuardianIndex, j: GuardianIndex },
    /// Occurs if the Lagrange coefficient can not be computed.
    #[error("Computation of the Lagrange coefficient failed.")]
    CoefficientFailure,
}

/// Represents errors occurring while combining the commit and response shares
/// into a single [`DecryptionProof`].
#[derive(Error, Debug)]
pub enum CombineProofError {
    /// Occurs if the input list are not of the same length
    #[error("The given lists must be of the same length!")]
    ListLengthMismatch,
    /// Occurs if the input list are not ordered the same way.
    #[error("The given lists must be ordered the same way!")]
    IndexMismatch,
    /// Occurs if the joint public key does not match the list of public keys.
    #[error("Could not compute the joint public key from the list of public keys!")]
    JointPKFailure,
    /// Occurs if the decryption shares could not be combined.
    #[error("Could not combine the given decryption shares: {0}")]
    ShareCombinationError(ShareCombinationError),
    /// Occurs if the commitment and response shares are inconsistent (Checks
    /// `9.A` and `9.B`).
    #[error("The commit message ({1}) of guardian {0} is inconsistent!")]
    CommitInconsistency(GuardianIndex, String),
    /// Occurs if the Lagrange coefficient can not be computed.
    #[error("Computation of the Lagrange coefficient failed!")]
    CoefficientFailure,
}

/// Proof that a given plaintext is the decryption of a given ciphertext
/// relative to a given public key.
///
/// This is a Sigma protocol for a discrete logarithm relation. It corresponds
/// to the proof from Section `3.6.3`.
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
    pub response:  BigUint,
}

impl DecryptionProof {
    /// This function generates the commitment share and secret state for a
    /// decryption proof.
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
        h_e: &HashesExt,
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
        let c = eg_h(&h_e.h_e, &v);
        // The challenge is not reduced modulo q (cf. Section 5.4)
        BigUint::from_bytes_be(c.0.as_slice())
    }

    /// This function computes a guardian's response share for the decryption
    /// NIZK.
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
        h_e: &HashesExt,
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
        let w_i = match get_single_coefficient_at_zero(&xs, &i_big, &fixed_parameters.q) {
            Some(w_i) => w_i,
            None => return Err(ResponseShareError::CoefficientFailure),
        };

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

    /// This function computes a decryption proof given the commit and response
    /// shares.
    ///
    /// The arguments are
    /// - `election_parameters` - the election parameters
    /// - `h_e` - the extended bash hash
    /// - `ciphertext` - the ciphertext
    /// - `decryption_shares` - the decryption shares
    /// - `proof_commit_shares` - the shares of the commit message
    /// - `proof_response_shares` - the shares of the response
    /// - `guardian_public_keys` - the guardians' public keys
    ///
    /// This function checks that `decryption_shares`, `proof_commit_shares`,
    /// `proof_response_shares`, are *ordered* the same way,
    /// i.e. the i-th element in each list belongs to the same guardian.
    /// The function also checks that `guardian_public_keys` contains all n
    /// public keys.
    pub fn combine_proof<'a, Shares, CommitShares, ResponseShares>(
        election_parameters: &ElectionParameters,
        h_e: &HashesExt,
        ciphertext: &Ciphertext,
        decryption_shares: Shares,
        proof_commit_shares: CommitShares,
        proof_response_shares: ResponseShares,
        guardian_public_keys: &[GuardianPublicKey],
    ) -> Result<Self, CombineProofError>
    where
        Shares: IntoIterator<Item = &'a DecryptionShare>,
        CommitShares: IntoIterator<Item = &'a DecryptionProofCommitShare>,
        ResponseShares: IntoIterator<Item = &'a DecryptionProofResponseShare>,
        Shares::IntoIter: ExactSizeIterator + Clone,
        CommitShares::IntoIter: ExactSizeIterator + Clone,
        ResponseShares::IntoIter: ExactSizeIterator, {
        let fixed_parameters = &election_parameters.fixed_parameters;

        let decryption_shares = decryption_shares.into_iter();
        let proof_commit_shares = proof_commit_shares.into_iter();
        let proof_response_shares = proof_response_shares.into_iter();

        if decryption_shares.len() != proof_commit_shares.len()
            || decryption_shares.len() != proof_response_shares.len()
        {
            return Err(CombineProofError::ListLengthMismatch);
        }

        // Check that the joint key matches the given public keys
        // This also checks that all public keys are given
        let joint_key =
            match JointElectionPublicKey::compute(election_parameters, guardian_public_keys) {
                Err(_) => return Err(CombineProofError::JointPKFailure),
                Ok(pk) => pk,
            };

        let m = CombinedDecryptionShare::combine(election_parameters, decryption_shares.clone());
        let m = match m {
            Ok(res) => res,
            Err(e) => return Err(CombineProofError::ShareCombinationError(e)),
        };

        let p = fixed_parameters.p.as_ref();
        let q = fixed_parameters.q.as_ref();
        let g = &fixed_parameters.g;

        let mut xs = Vec::with_capacity(proof_commit_shares.len());
        let (a, b) =
            proof_commit_shares
                .clone()
                .fold((BigUint::one(), BigUint::one()), |(a, b), share| {
                    xs.push(BigUint::from(share.i.get_one_based_u32()));
                    ((a * share.a_i.clone()) % p, (b * share.b_i.clone()) % p)
                });
        let c = Self::challenge(h_e, &joint_key, ciphertext, &a, &b, &m);

        // The response.
        let mut v = BigUint::zero();

        // Check Equations (74) and (75)
        for (ds, cs, rs) in izip!(
            decryption_shares,
            proof_commit_shares,
            proof_response_shares,
        ) {
            // Check that the indices match
            if ds.i != cs.i || ds.i != rs.i {
                return Err(CombineProofError::IndexMismatch);
            }
            let g_v = g.modpow(&rs.v_i, p);
            let i = BigUint::from(ds.i.get_one_based_u32());

            let w_i = match get_single_coefficient_at_zero(&xs, &i, &fixed_parameters.q) {
                Some(w_i) => w_i,
                None => return Err(CombineProofError::CoefficientFailure),
            };
            let c_i = (c.clone() * w_i) % q;

            let k_prod = guardian_public_keys
                .iter()
                .fold(BigUint::one(), |prod, pk| {
                    let inner_p = pk.coefficient_commitments.0.iter().enumerate().fold(
                        BigUint::one(),
                        |prod, (m, k_m)| {
                            // This is fine as m < k
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
            v = (v + rs.v_i.clone()) % q;
        }

        Ok(DecryptionProof {
            challenge: c,
            response:  v,
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
        h_e: &HashesExt,
        joint_key: &JointElectionPublicKey,
        ciphertext: &Ciphertext,
        m: &CombinedDecryptionShare,
    ) -> bool {
        let g = &fixed_parameters.g;
        let p = fixed_parameters.p.as_ref();
        let q = fixed_parameters.q.as_ref();

        let key = &joint_key.joint_election_public_key;

        let a = (g.modpow(&self.response, p) * key.modpow(&self.challenge, p)) % p;
        let b = (ciphertext.alpha.modpow(&self.response, p) * m.0.modpow(&self.challenge, p)) % p;

        // Check (9.A)
        if &self.response >= q {
            return false;
        }
        let c = Self::challenge(h_e, joint_key, ciphertext, &a, &b, m);
        // Check (9.B)
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
    /// Occurs if the computation of the plain-text from `T` and the joint
    /// public-key fails.
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
    pub proof:      DecryptionProof,
}

/// Decryption posted by the guardian together with a commitment.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DecryptionShareResult {
    pub share:        DecryptionShare,
    pub proof_commit: DecryptionProofCommitShare,
}

#[derive(Error, Debug)]
pub enum ComputeDecryptionError {
    #[error("Failed to decrypt: {0}")]
    Decryption(#[from] DecryptionError),
    #[error("Failed to combine shares: {0}")]
    CombineShares(#[from] ShareCombinationError),
    #[error("Failed to combine proof shares: {0}")]
    CombineProofShares(#[from] CombineProofError),
    #[error("One or more input parameters were not hashable.")]
    InvalidParameters,
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

    /// This function computes a verifiable decryption together
    /// with proofs.
    ///
    /// The arguments are
    /// - `fixed_parameters` - the fixed parameters
    /// - `joint_key` - the joint election public key
    /// - `ciphertext` - the ciphertext
    /// - `m` - combined decryption share
    /// - `proof` - the proof of correctness
    pub fn compute<'a, Shares, Proofs>(
        manifest: &ElectionManifest,
        parameters: &ElectionParameters,
        guardian_public_keys: &[GuardianPublicKey],
        ciphertext: &Ciphertext,
        decryptions: Shares,
        response_shares: Proofs,
    ) -> Result<Self, ComputeDecryptionError> where
        Shares: IntoIterator<Item=&'a DecryptionShareResult>,
        Shares::IntoIter: ExactSizeIterator + Clone,
        Proofs: IntoIterator<Item=&'a DecryptionProofResponseShare>,
        Proofs::IntoIter: ExactSizeIterator,
    {
        let decryptions = decryptions.into_iter();
        let m = CombinedDecryptionShare::combine(
            parameters,
            decryptions.clone().map(|d| &d.share),
        )?;

        let Ok(hashes) = Hashes::compute(parameters, manifest) else {
            return Err(ComputeDecryptionError::InvalidParameters);
        };

        let Ok(joint_election_public_key) = JointElectionPublicKey::compute(parameters, guardian_public_keys) else {
            return Err(CombineProofError::JointPKFailure.into());
        };

        let hashes_ext = HashesExt::compute(
            parameters,
            &hashes,
            &joint_election_public_key,
            guardian_public_keys,
        );

        let proof = DecryptionProof::combine_proof(
            parameters,
            &hashes_ext,
            ciphertext,
            decryptions.clone().map(|d| &d.share),
            decryptions.map(|d| &d.proof_commit),
            response_shares,
            guardian_public_keys,
        )?;

        let r = Self::new(
            &parameters.fixed_parameters,
            &joint_election_public_key,
            ciphertext,
            &m,
            &proof,
        )?;
        Ok(r)
    }

    /// This function checks the correctness of the decryption for given
    /// ciphertext and joint public key.
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
        h_e: &HashesExt,
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
    use util::{csprng::Csprng, prime::BigUintPrime};

    use crate::{
        election_parameters::ElectionParameters,
        example_election_manifest,
        example_election_parameters::example_election_parameters,
        fixed_parameters::{FixedParameterGenerationParameters, FixedParameters, NumsNumber},
        guardian::GuardianIndex,
        guardian_public_key::GuardianPublicKey,
        guardian_secret_key::GuardianSecretKey,
        guardian_share::{GuardianEncryptedShare, GuardianSecretKeyShare},
        hashes::Hashes,
        hashes_ext::HashesExt,
        joint_election_public_key::JointElectionPublicKey,
        varying_parameters::{BallotChaining, VaryingParameters},
        verifiable_decryption::ShareCombinationError,
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
        // Setup some keys
        let guardian_secret_keys = varying_parameters
            .each_guardian_i()
            .map(|i| GuardianSecretKey::generate(csprng, election_parameters, i, None))
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
                        GuardianEncryptedShare::new(csprng, election_parameters, dealer_sk, pk)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let key_shares = zip(&guardian_secret_keys, share_vecs)
            .map(|(sk, shares)| {
                GuardianSecretKeyShare::compute(
                    election_parameters,
                    &guardian_public_keys,
                    &shares,
                    sk,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let joint_key =
            JointElectionPublicKey::compute(election_parameters, &guardian_public_keys).unwrap();
        (joint_key, guardian_public_keys, key_shares)
    }

    fn get_toy_parameters() -> FixedParameters {
        FixedParameters {
            opt_ElectionGuard_Design_Specification: None,
            generation_parameters: FixedParameterGenerationParameters {
                q_bits_total:         7,
                p_bits_total:         16,
                p_bits_msb_fixed_1:   0,
                p_middle_bits_source: NumsNumber::ln_2,
                p_bits_lsb_fixed_1:   0,
            },
            p: BigUintPrime::new_unchecked_the_caller_guarantees_that_this_number_is_prime(
                BigUint::from(59183_u32),
            ),
            q: BigUintPrime::new_unchecked_the_caller_guarantees_that_this_number_is_prime(
                BigUint::from(127_u8),
            ),
            r: BigUint::from(466_u32),
            g: BigUint::from(32616_u32),
        }
    }

    #[test]
    fn test_decryption_share_combination() {
        // Toy parameters according to specs
        let fixed_parameters = get_toy_parameters();
        let varying_parameters = VaryingParameters {
            n:               GuardianIndex::from_one_based_index(3).unwrap(),
            k:               GuardianIndex::from_one_based_index(3).unwrap(),
            date:            "2023-05-02".to_string(),
            info:            "The test election".to_string(),
            ballot_chaining: BallotChaining::Prohibited,
        };
        let election_parameters = ElectionParameters {
            fixed_parameters,
            varying_parameters,
        };
        let p = &election_parameters.fixed_parameters.p;
        let g = &election_parameters.fixed_parameters.g;

        // Using x^2-1 as polynomial
        let decryption_shares = [
            DecryptionShare {
                i:   GuardianIndex::from_one_based_index(1).unwrap(),
                m_i: g.modpow(&BigUint::from(0_u8), p.as_ref()),
            },
            DecryptionShare {
                i:   GuardianIndex::from_one_based_index(2).unwrap(),
                m_i: g.modpow(&BigUint::from(3_u8), p.as_ref()),
            },
            DecryptionShare {
                i:   GuardianIndex::from_one_based_index(3).unwrap(),
                m_i: g.modpow(&BigUint::from(8_u8), p.as_ref()),
            },
        ];
        let exp_m = CombinedDecryptionShare(g.modpow(&BigUint::from(126_u8), p.as_ref()));

        assert_eq!(
            CombinedDecryptionShare::combine(&election_parameters, &decryption_shares)
                .unwrap()
                .0,
            exp_m.0
        );

        assert_eq!(
            CombinedDecryptionShare::combine(&election_parameters, &decryption_shares[0..2])
                .unwrap_err(),
            ShareCombinationError::NotEnoughShares { l: 2, k: 3 }
        );

        let decryption_shares = [
            DecryptionShare {
                i:   GuardianIndex::from_one_based_index(1).unwrap(),
                m_i: g.modpow(&BigUint::from(0_u8), p.as_ref()),
            },
            DecryptionShare {
                i:   GuardianIndex::from_one_based_index(2).unwrap(),
                m_i: g.modpow(&BigUint::from(3_u8), p.as_ref()),
            },
            DecryptionShare {
                i:   GuardianIndex::from_one_based_index(4).unwrap(),
                m_i: g.modpow(&BigUint::from(8_u8), p.as_ref()),
            },
        ];
        assert_eq!(
            CombinedDecryptionShare::combine(&election_parameters, &decryption_shares).unwrap_err(),
            ShareCombinationError::InvalidGuardian {
                i: GuardianIndex::from_one_based_index(4).unwrap(),
                n: GuardianIndex::from_one_based_index(3).unwrap(),
            }
        );

        let decryption_shares = [
            DecryptionShare {
                i:   GuardianIndex::from_one_based_index(1).unwrap(),
                m_i: g.modpow(&BigUint::from(0_u8), p.as_ref()),
            },
            DecryptionShare {
                i:   GuardianIndex::from_one_based_index(2).unwrap(),
                m_i: g.modpow(&BigUint::from(3_u8), p.as_ref()),
            },
            DecryptionShare {
                i:   GuardianIndex::from_one_based_index(2).unwrap(),
                m_i: g.modpow(&BigUint::from(8_u8), p.as_ref()),
            },
        ];
        assert_eq!(
            CombinedDecryptionShare::combine(&election_parameters, &decryption_shares).unwrap_err(),
            ShareCombinationError::DuplicateGuardian {
                i: GuardianIndex::from_one_based_index(2).unwrap(),
            }
        );
    }

    #[test]
    fn test_decryption_overall() {
        let mut csprng = Csprng::new(b"test_proof_generation");
        let election_parameters = example_election_parameters();
        let fixed_parameters = &election_parameters.fixed_parameters;
        let (joint_key, public_keys, key_shares) = key_setup(&mut csprng, &election_parameters);

        let hashes = Hashes::compute(
            &election_parameters,
            &example_election_manifest::example_election_manifest(),
        )
        .unwrap();

        let h_e = HashesExt::compute(&election_parameters, &hashes, &joint_key, &public_keys);

        let message: usize = 42;
        let nonce = csprng.next_biguint_lt(fixed_parameters.q.as_ref());
        let ciphertext = joint_key.encrypt_with(fixed_parameters, &nonce, message);

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
                    key_share,
                )
                .unwrap()
            })
            .collect();

        let proof = DecryptionProof::combine_proof(
            &election_parameters,
            &h_e,
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
