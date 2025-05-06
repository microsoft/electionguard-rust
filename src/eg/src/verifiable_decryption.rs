#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides the implementation of verifiable decryption for
//! [`Ciphertext`]s. For more details see
//! Section `3.6` of the Electionguard specification `2.0.0`. [TODO fix ref]

use std::sync::Arc;

use itertools::izip;
use serde::{Deserialize, Serialize};
use util::csrng::Csrng;

use crate::{
    algebra::{FieldElement, Group, GroupElement, ScalarField},
    algebra_utils::{DiscreteLog, get_single_coefficient_at_zero, group_lagrange_at_zero},
    ciphertext::Ciphertext,
    contest::ContestIndex,
    contest_data_fields::ContestDataFieldIndex,
    election_parameters::ElectionParameters,
    errors::{EgError, EgResult},
    extended_base_hash::ExtendedBaseHash_H_E,
    fixed_parameters::{FixedParameters, FixedParametersTrait, FixedParametersTraitExt},
    guardian::GuardianIndex,
    guardian_public_key::GuardianPublicKey,
    guardian_public_key_trait::GuardianKeyInfoTrait,
    hash::{HValue, eg_h},
    hashes::Hashes,
    //? interguardian_share::GuardianSecretKeyShare,
    joint_public_key::JointPublicKey,
    key::KeyPurpose,
    pre_voting_data::PreVotingData,
    resource::{self, ProduceResource, ProduceResourceExt},
};

//=================================================================================================|

/// A decryption share is a guardian's partial decryption of a given ciphertext.
///
/// This corresponds to the `M_i` in Section `3.6.2`. [TODO fix ref]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionShare {
    /// The guardian's index
    pub guardian_ix: GuardianIndex,

    /// The decryption share value
    pub m_i: GroupElement,
}

impl DecryptionShare {
    /*
    /// Computes the [`DecryptionShare`] for a given
    /// [`Ciphertext`] and [`GuardianSecretKeyShare`].
    ///
    /// The arguments are
    /// - `self` - the Guardian secret key share
    /// - `fixed_parameters` - the fixed parameters
    /// - `secret_key_share` - the secret key share
    /// - `ciphertext` - the ElGamal ciphertext
    pub fn from(
        fixed_parameters: &FixedParameters,
        secret_key_share: &GuardianSecretKeyShare,
        ciphertext: &Ciphertext,
    ) -> Self {
        let group = fixed_parameters.group();
        let m_i = ciphertext.alpha.exp(&secret_key_share.z_i, group);
        DecryptionShare {
            guardian_ix: secret_key_share.guardian_ix,
            m_i,
        }
    }
    // */
}

/// Represents errors occurring while combining [`DecryptionShare`]s
/// into a  [`CombinedDecryptionShare`].
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum DecryptionShareCombinationError {
    /// Occurs if not enough shares were provided. Combination requires [`GuardianSecretKeyShare`]s
    /// from at least [`k`](crate::varying_parameters::VaryingParameters) out of
    /// [`n`](crate::varying_parameters::VaryingParameters) Guardians.
    #[error("Only {l} decryption shares given, but at least {k} required.")]
    NotEnoughShares { l: usize, k: GuardianIndex },

    /// Occurs if a Guardian claims to have a [`GuardianIndex`] is larger than
    /// [`n`](crate::varying_parameters::VaryingParameters).
    #[error("Guardian {i} is has an index bigger than {n}")]
    InvalidGuardianIndex { i: GuardianIndex, n: GuardianIndex },

    /// Occurs if multiple shares from the same guardian are provided.
    #[error("Guardian {i} is represented more than once in the decryption shares.")]
    DuplicateGuardian { i: GuardianIndex },

    /// Occurs if the Lagrange interpolation fails.
    #[error("Could not compute the polynomial interpolation.")]
    InterpolationFailure,
}

/// The combined decryption share allows to compute the plain-text from a given
/// ciphertext.
///
/// This corresponds to the `M` in Section `3.6.2`.
#[derive(Debug)]
pub struct CombinedDecryptionShare(GroupElement);

impl CombinedDecryptionShare {
    /// Computes the combination of [`DecryptionShare`]s.
    ///
    /// The arguments are
    /// - `election_parameters` - the election parameters
    /// - `decryption_shares` - a vector of decryption shares
    ///
    /// The computation follows Equation `68`. [TODO fix ref]
    pub fn combine<'a, I>(
        election_parameters: &ElectionParameters,
        decryption_shares: I,
    ) -> Result<Self, DecryptionShareCombinationError>
    where
        I: IntoIterator<Item = &'a DecryptionShare>,
        I::IntoIter: ExactSizeIterator,
    {
        let fixed_parameters = election_parameters.fixed_parameters();
        let field = fixed_parameters.field();
        let group = fixed_parameters.group();

        let varying_parameters = election_parameters.varying_parameters();
        let n = varying_parameters.n();
        let k = varying_parameters.k();

        let n_usize = n.get_one_based_usize();
        //let k_usize = k.get_one_based_usize();

        let decryption_shares = decryption_shares.into_iter();
        let l = decryption_shares.len();
        // Ensure that we have at least k decryption shares
        if l < k.get_one_based_usize() {
            return Err(DecryptionShareCombinationError::NotEnoughShares { l, k });
        }
        // Verify that every guardian (index) is represented at most once and that all
        // guardians indices are within the bounds.
        let mut seen = vec![false; n_usize];
        let mut xs = Vec::with_capacity(l);
        let mut ys = Vec::with_capacity(l);
        for share in decryption_shares {
            let seen_ix = share.guardian_ix.get_zero_based_usize();
            if seen_ix >= n_usize {
                return Err(DecryptionShareCombinationError::InvalidGuardianIndex {
                    i: share.guardian_ix,
                    n,
                });
            }
            if seen[seen_ix] {
                return Err(DecryptionShareCombinationError::DuplicateGuardian {
                    i: share.guardian_ix,
                });
            }
            seen[seen_ix] = true;
            xs.push(FieldElement::from(
                share.guardian_ix.get_one_based_u32(),
                field,
            ));
            ys.push(share.m_i.clone());
        }

        group_lagrange_at_zero(&xs, &ys, field, group)
            .ok_or(DecryptionShareCombinationError::InterpolationFailure)
            .map(CombinedDecryptionShare)
    }
}

/// The commitment share of a single guardian for a [`DecryptionProof`].
///
/// EGDS 2.1.0 sec. 3.6.5 `Proof of Correctness - NIZK Proof`` eq. 87 pg. 47
///
/// - `(a_i, b_i)`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofCommitShare {
    /// The Guardian's index
    pub i: GuardianIndex,

    /// `a_i`
    pub a_i: GroupElement,

    /// `b_i`
    pub b_i: GroupElement,
}

/// The secret state for a commitment share of a single guardian for a
/// [`DecryptionProof`].
///
/// EGDS 2.1.0 sec. 3.6.5 `Proof of Correctness - NIZK Proof`` eq. 87 pg. 47
///
/// - `u_i`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofStateShare {
    /// The Guardian's index
    pub i: GuardianIndex,

    /// Random value `u_i` in `Z_q`.
    pub u_i: FieldElement,
}

/// The response share of a single Guardian for a [`DecryptionProof`].
///
/// EGDS 2.1.0 sec. 3.6.5 `Proof of Correctness - NIZK Proof`` eq. 92 pg. 48
///
/// - `v_i`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProofResponseShare {
    /// The guardian's index
    pub i: GuardianIndex,

    /// The response share
    pub v_i: FieldElement,
}

/// Represents errors occurring while computing a response share.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum ResponseShareError {
    /// Occurs if one tries to compute the response from a state share that does
    /// not match the secret key share.
    #[error("Indices of key share (here {i}) and state share (here {j}) must match!")]
    KeyStateShareIndexMismatch { i: GuardianIndex, j: GuardianIndex },

    /// Occurs if the Lagrange coefficient can not be computed.
    #[error("Computation of the Lagrange coefficient failed.")]
    CoefficientFailure,

    #[error("Response share error: {0}")]
    EgError(#[from] Box<EgError>),
}

impl From<EgError> for ResponseShareError {
    fn from(e: EgError) -> Self {
        ResponseShareError::EgError(Box::new(e))
    }
}

/// Represents errors occurring while combining the commit and response shares
/// into a single [`DecryptionProof`].
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
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
    ShareCombinationError(DecryptionShareCombinationError),

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
/// to the proof from EGDS 2.1.0 Section 3.6.5.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProof {
    /// Challenge
    pub challenge: FieldElement,

    /// Response
    pub response: FieldElement,
}

impl DecryptionProof {
    /// Generates the commitment share and secret state for a
    /// decryption proof.
    ///
    /// The arguments are
    /// - `csrng` - secure randomness generator
    /// - `fixed_parameters` - the fixed parameters
    /// - `ciphertext` - the ElGamal ciphertext
    /// - `i` - the guardian index
    ///
    /// The computation follows EGDS 2.1.0 sec 3.6.5 eq. 87 and 88.
    pub fn generate_commit_share(
        csrng: &dyn Csrng,
        fixed_parameters: &FixedParameters,
        ciphertext: &Ciphertext,
        guardian_ix: GuardianIndex,
    ) -> (DecryptionProofCommitShare, DecryptionProofStateShare) {
        let group = fixed_parameters.group();
        let field = fixed_parameters.field();

        let u_i = field.random_field_elem(csrng);
        let a_i = group.g_exp(&u_i);
        let b_i = ciphertext.alpha.exp(&u_i, group);
        let dcs = DecryptionProofCommitShare {
            i: guardian_ix,
            a_i,
            b_i,
        };
        let dss = DecryptionProofStateShare {
            i: guardian_ix,
            u_i,
        };
        (dcs, dss)
    }

    /// Computes the challenge for the decryption NIZK.
    ///
    /// The computation corresponds to EGDS 2.1.0 sec 3.6.5 eq. 90.
    ///
    /// The arguments are
    /// - `fixed_parameters` - the fixed parameters
    /// - `h_e` - the extended bash hash
    /// - `contest_ix` - context index
    /// - `contest_data_field_ix` - selectable option or additional data field index
    /// - `j` - the coefficient index
    /// - `c` - the ciphertext
    /// - `a` - first part of the commit message
    /// - `b` - second part of the commit message
    /// - `m` - combined decryption share
    #[allow(clippy::too_many_arguments)]
    fn challenge(
        fixed_parameters: &FixedParameters,
        h_e: &ExtendedBaseHash_H_E,
        contest_ix: ContestIndex,
        contest_data_field_ix: ContestDataFieldIndex,
        c: &Ciphertext,
        a: &GroupElement,
        b: &GroupElement,
        m: &CombinedDecryptionShare,
    ) -> FieldElement {
        let field = fixed_parameters.field();
        let group = fixed_parameters.group();

        let expected_len = 2569; // EGDS 2.1.0 pg. 77 (90)

        // v = 0x31 | b(ind_c(Λ), 4) | b(ind_o(λ), 4)
        // | b(c.A, 512) | b(c.B, 512)
        // | b(a, 512) | b(b, 512) | b(m, 512)
        let mut v = Vec::with_capacity(expected_len);
        v.push(0x31);
        v.extend(contest_ix.get_one_based_u32().to_be_bytes());
        v.extend(contest_data_field_ix.get_one_based_u32().to_be_bytes());
        v.extend_from_slice(c.alpha.to_be_bytes_left_pad(group).as_slice());
        v.extend_from_slice(c.beta.to_be_bytes_left_pad(group).as_slice());
        v.extend_from_slice(a.to_be_bytes_left_pad(group).as_slice());
        v.extend_from_slice(b.to_be_bytes_left_pad(group).as_slice());
        v.extend_from_slice(m.0.to_be_bytes_left_pad(group).as_slice());
        assert_eq!(v.len(), expected_len);

        let c = eg_h(h_e, &v);
        // TODO The challenge is not reduced modulo q (cf. Section 5.4)
        FieldElement::from_bytes_be(c.0.as_slice(), field)
    }

    /*
    /// Computes a guardian's response share for the decryption NIZK.
    ///
    /// EGDS 2.1.0 sec. 3.6.5 `Proof of Correctness - NIZK Proof`, pg. 48, eq. 89 - 92
    ///
    ///
    /// The arguments are
    /// - `produce_resource` - common resource data provider
    /// - `contest_ix` - context index
    /// - `contest_data_field_ix` - selectable option or additional data field index
    /// - `ciphertext` - the ciphertext
    /// - `m` - combined decryption share
    /// - `proof_commit_shares` - the shares of the commit message
    /// - `proof_commit_state` - the guardian's commit state
    /// - `secret_key_share` - the guardian's key share
    #[allow(clippy::too_many_arguments)]
    pub async fn generate_response_share(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        contest_ix: ContestIndex,
        contest_data_field_ix: ContestDataFieldIndex,
        ciphertext: &Ciphertext,
        m: &CombinedDecryptionShare,
        proof_commit_shares: &[DecryptionProofCommitShare],
        proof_commit_state: &DecryptionProofStateShare,
        secret_key_share: &GuardianSecretKeyShare,
    ) -> Result<DecryptionProofResponseShare, ResponseShareError> {
        let election_parameters = produce_resource
            .election_parameters()
            .await
            .map_err(ResponseShareError::from)?;
        let fixed_parameters = election_parameters.fixed_parameters();
        let group = fixed_parameters.group();
        let field = fixed_parameters.field();

        let extended_base_hash = produce_resource
            .extended_base_hash()
            .await
            .map_err(ResponseShareError::from)?;

        if proof_commit_state.i != secret_key_share.guardian_ix {
            return Err(ResponseShareError::KeyStateShareIndexMismatch {
                i: proof_commit_state.i,
                j: secret_key_share.guardian_ix,
            });
        }

        // EGDS 2.1.0 Sec 3.6.5 eq. 89
        let (a, b) = proof_commit_shares
            .iter()
            .fold((Group::one(), Group::one()), |(a, b), share| {
                (a.mul(&share.a_i, group), b.mul(&share.b_i, group))
            });

        // EGDS 2.1.0 Sec 3.6.5 eq. 90
        let c = Self::challenge(
            fixed_parameters,
            extended_base_hash.h_e(),
            contest_ix,
            contest_data_field_ix,
            ciphertext,
            &a,
            &b,
            m,
        );

        // EGDS 2.1.0 Sec 3.6.5 eq. 91
        let i_scalar = FieldElement::from(proof_commit_state.i.get_one_based_u32(), field);
        let xs: Vec<FieldElement> = proof_commit_shares
            .iter()
            .map(|s| FieldElement::from(s.i.get_one_based_u32(), field))
            .collect();
        let w_i = match get_single_coefficient_at_zero(&xs, &i_scalar, field) {
            Some(w_i) => w_i,
            None => return Err(ResponseShareError::CoefficientFailure),
        };
        let c_i = c.mul(&w_i, field);

        // EGDS 2.1.0 Sec 3.6.5 eq. 92
        // v_i = (u_i - c_i*z_i)
        let v_i = proof_commit_state
            .u_i
            .sub(&c_i.mul(&secret_key_share.z_i, field), field);

        Ok(DecryptionProofResponseShare {
            i: proof_commit_state.i,
            v_i,
        })
    }
    // */

    /// Computes a decryption proof given the commit and response
    /// shares.
    ///
    /// The arguments are:
    ///
    /// - `produce_resource` - common resource data provider
    /// - `contest_ix` - context index
    /// - `contest_data_field_ix` - selectable option or additional data field index
    /// - `ciphertext` - the ciphertext
    /// - `decryption_shares` - the decryption shares
    /// - `proof_commit_shares` - the shares of the commit message
    /// - `proof_response_shares` - the shares of the response
    /// - `guardian_public_keys` - the guardians' public keys
    ///
    /// Checks that `decryption_shares`, `proof_commit_shares`,
    /// `proof_response_shares`, are *ordered* the same way,
    /// i.e. the i-th element in each list belongs to the same guardian.
    /// The function also checks that `guardian_public_keys` contains all n
    /// public keys.
    #[allow(clippy::too_many_arguments)]
    pub async fn combine_proof<'a, Shares, CommitShares, ResponseShares>(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        contest_ix: ContestIndex,
        contest_data_field_ix: ContestDataFieldIndex,
        ciphertext: &Ciphertext,
        decryption_shares: Shares,
        proof_commit_shares: CommitShares,
        proof_response_shares: ResponseShares,
        guardian_public_keys: &[&GuardianPublicKey],
    ) -> EgResult<Self>
    where
        Shares: IntoIterator<Item = &'a DecryptionShare>,
        CommitShares: IntoIterator<Item = &'a DecryptionProofCommitShare>,
        ResponseShares: IntoIterator<Item = &'a DecryptionProofResponseShare>,
        Shares::IntoIter: ExactSizeIterator + Clone,
        CommitShares::IntoIter: ExactSizeIterator + Clone,
        ResponseShares::IntoIter: ExactSizeIterator,
    {
        let election_parameters = produce_resource.election_parameters().await?;
        let election_parameters = election_parameters.as_ref();
        let fixed_parameters = election_parameters.fixed_parameters();
        let group = fixed_parameters.group();
        let field = fixed_parameters.field();

        let extended_base_hash = produce_resource.extended_base_hash().await?;
        let extended_base_hash = extended_base_hash.as_ref();
        let h_e = extended_base_hash.h_e();

        let decryption_shares = decryption_shares.into_iter();
        let proof_commit_shares = proof_commit_shares.into_iter();
        let proof_response_shares = proof_response_shares.into_iter();

        if decryption_shares.len() != proof_commit_shares.len()
            || decryption_shares.len() != proof_response_shares.len()
        {
            return Err(CombineProofError::ListLengthMismatch.into());
        }

        // Check that the joint key matches the given public keys
        // This also checks that all public keys are given
        let m = CombinedDecryptionShare::combine(election_parameters, decryption_shares.clone());
        let m = match m {
            Ok(res) => res,
            Err(e) => return Err(CombineProofError::ShareCombinationError(e).into()),
        };

        let (a, b) = proof_commit_shares
            .clone()
            .fold((Group::one(), Group::one()), |(a, b), share| {
                (a.mul(&share.a_i, group), b.mul(&share.b_i, group))
            });
        let c = Self::challenge(
            fixed_parameters,
            h_e,
            contest_ix,
            contest_data_field_ix,
            ciphertext,
            &a,
            &b,
            &m,
        );

        let xs: Vec<FieldElement> = proof_commit_shares
            .clone()
            .map(|s| FieldElement::from(s.i.get_one_based_u32(), field))
            .collect();
        let mut c_i_vec = vec![];
        for cs in proof_commit_shares.clone() {
            let i = cs.i.get_one_based_u32();
            let i = FieldElement::from(i, field);
            let w_i = match get_single_coefficient_at_zero(&xs, &i, field) {
                Some(w_i) => w_i,
                None => return Err(CombineProofError::CoefficientFailure.into()),
            };
            let c_i = c.mul(&w_i, field);
            c_i_vec.push(c_i);
        }

        let mut v = ScalarField::zero();

        // EGDS 2.1.0 Sec 3.6.5 eq. 94 and 95
        for (ds, cs, rs, c_i) in izip!(
            decryption_shares,
            proof_commit_shares,
            proof_response_shares,
            c_i_vec
        ) {
            let g_v = group.g_exp(&rs.v_i);
            let i_scalar = FieldElement::from(ds.guardian_ix.get_one_based_u32(), field);
            let k_prod = guardian_public_keys.iter().fold(Group::one(), |prod, pk| {
                let inner_p = pk.coefficient_commitments().iter().enumerate().fold(
                    Group::one(),
                    |prod, (m, k_m)| {
                        let i_pow_m = i_scalar.pow(m, field);
                        prod.mul(&k_m.0.exp(&i_pow_m, group), group)
                    },
                );
                prod.mul(&inner_p, group)
            });
            let a_i = g_v.mul(&k_prod.exp(&c_i, group), group);
            let a_v = ciphertext.alpha.exp(&rs.v_i, group);
            let m_c = ds.m_i.exp(&c_i, group);
            let b_i = a_v.mul(&m_c, group);

            if a_i != cs.a_i {
                return Err(CombineProofError::CommitInconsistency(
                    ds.guardian_ix,
                    "a_i != a_i'".into(),
                )
                .into());
            }
            if b_i != cs.b_i {
                return Err(CombineProofError::CommitInconsistency(
                    ds.guardian_ix,
                    "b_i != b_i'".into(),
                )
                .into());
            }
            v = v.add(&rs.v_i, field);
        }

        Ok(DecryptionProof {
            challenge: c,
            response: v,
        })
    }

    /// Validates a decryption proof.
    ///
    /// The arguments are
    /// - `self` - the decryption proof
    /// - `fixed_parameters` - the fixed parameters
    /// - `h_e` - the extended base hash
    /// - `jpk` - the joint public key
    /// - `contest_ix` - context index
    /// - `contest_data_field_ix` - selectable option or additional data field index
    /// - `ciphertext` - the ciphertext
    /// - `m` - combined decryption share
    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        &self,
        fixed_parameters: &FixedParameters,
        h_e: &ExtendedBaseHash_H_E,
        jpk: &JointPublicKey,
        contest_ix: ContestIndex,
        contest_data_field_ix: ContestDataFieldIndex,
        ciphertext: &Ciphertext,
        m: &CombinedDecryptionShare,
    ) -> bool {
        let group = fixed_parameters.group();
        let field = fixed_parameters.field();

        let jpk_group_elem = &jpk.group_element;

        let a = group
            .g_exp(&self.response)
            .mul(&jpk_group_elem.exp(&self.challenge, group), group);
        let a_v = ciphertext.alpha.exp(&self.response, group);
        let m_c = m.0.exp(&self.challenge, group);
        let b = a_v.mul(&m_c, group);

        //Check (9.A)
        if !self.response.is_valid(field) {
            return false;
        }

        let c = Self::challenge(
            fixed_parameters,
            h_e,
            contest_ix,
            contest_data_field_ix,
            ciphertext,
            &a,
            &b,
            m,
        );

        //Check (9.B)
        if c != self.challenge {
            return false;
        }
        true
    }
}

/// Represents errors occurring during decryption.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum DecryptionError {
    /// Occurs if the combined decryption share has no inverse.
    #[error("The combined decryption share has no inverse!")]
    NoInverse,

    /// Occurs if the computation of the plain-text from `T` and the joint
    /// public-key fails.
    #[error("Could not compute the plaintext using dlog!")]
    NoDlog,
}

/// Decryption posted by the guardian together with a commitment.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DecryptionShareResult {
    pub share: DecryptionShare,
    pub proof_commit: DecryptionProofCommitShare,
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum ComputeDecryptionError {
    #[error("Failed to decrypt: {0}")]
    Decryption(#[from] DecryptionError),

    #[error("Failed to combine shares: {0}")]
    CombineShares(#[from] DecryptionShareCombinationError),

    #[error("Failed to combine proof shares: {0}")]
    CombineProofShares(#[from] CombineProofError),

    #[error("One or more input election_parameters were not hashable.")]
    InvalidParameters,
}

/// Represents a "in-the-exponent" plaintext with a [`DecryptionProof`].
///
/// This corresponds to `t` and `(c,v)` as in Section `3.6.3`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifiableDecryption {
    /// The decrypted plain-text
    pub plaintext: FieldElement,

    /// The proof of correctness
    pub proof: DecryptionProof,
}

impl VerifiableDecryption {
    /// Computes a verifiable decryption.
    ///
    /// The arguments are
    /// - `produce_resource` - common resource data provider
    /// - `ciphertext` - the ciphertext
    /// - `m` - combined decryption share
    /// - `proof` - the proof of correctness
    pub async fn new(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        ciphertext: &Ciphertext,
        m: &CombinedDecryptionShare,
        proof: &DecryptionProof,
    ) -> EgResult<Self> {
        let fixed_parameters = produce_resource.fixed_parameters().await?;
        let fixed_parameters = fixed_parameters.as_ref();
        let jvepk_k = produce_resource
            .joint_vote_encryption_public_key_k()
            .await?;
        let jvepk_k = jvepk_k.as_ref();

        let field = fixed_parameters.field();
        let group = fixed_parameters.group();
        let group_msg = match m.0.inv(group) {
            None => Err(DecryptionError::NoInverse)?,
            Some(m_inv) => ciphertext.beta.mul(&m_inv, group),
        };
        let base = &jvepk_k.group_element;
        let dlog = DiscreteLog::from_group(base, group);
        let plaintext = match dlog.ff_find(&group_msg, field) {
            None => Err(DecryptionError::NoDlog)?,
            Some(x) => x,
        };
        Ok(VerifiableDecryption {
            plaintext,
            proof: proof.clone(),
        })
    }

    /// Computes a verifiable decryption together with proofs.
    ///
    /// The arguments are
    /// - `produce_resource` - common resource data provider
    /// - `contest_ix` - context index
    /// - `contest_data_field_ix` - selectable option or additional data field index
    /// - `ciphertext` - the ciphertext
    /// - `m` - combined decryption share
    /// - `proof` - the proof of correctness
    pub async fn compute<'a, Shares, Proofs>(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        contest_ix: ContestIndex,
        contest_data_field_ix: ContestDataFieldIndex,
        ciphertext: &Ciphertext,
        decryptions: Shares,
        response_shares: Proofs,
    ) -> EgResult<Self>
    where
        Shares: IntoIterator<Item = &'a DecryptionShareResult>,
        Shares::IntoIter: ExactSizeIterator + Clone,
        Proofs: IntoIterator<Item = &'a DecryptionProofResponseShare>,
        Proofs::IntoIter: ExactSizeIterator,
    {
        let election_parameters = produce_resource.election_parameters().await?;
        let election_parameters = election_parameters.as_ref();

        let gpks_purpose = KeyPurpose::Ballot_Votes;
        let gpks = produce_resource.guardian_public_keys(gpks_purpose).await?;
        let gpks = gpks.iter_map_into(Arc::as_ref);

        let decryptions = decryptions.into_iter();
        let m = CombinedDecryptionShare::combine(
            election_parameters,
            decryptions.clone().map(|d| &d.share),
        )?;

        let proof = DecryptionProof::combine_proof(
            produce_resource,
            contest_ix,
            contest_data_field_ix,
            ciphertext,
            decryptions.clone().map(|d| &d.share),
            decryptions.map(|d| &d.proof_commit),
            response_shares,
            gpks.as_zero_based_slice(),
        )
        .await?;

        let r = Self::new(produce_resource, ciphertext, &m, &proof).await?;
        Ok(r)
    }

    /// Checks the correctness of the decryption for given
    /// ciphertext and joint public key.
    ///
    /// Arguments are
    /// - `self` - the verifiable decryption
    /// - `fixed_parameters` - the fixed parameters
    /// - `h_e` - the extended bash hash
    /// - `jpk` - joint public key
    /// - `contest_ix` - context index
    /// - `contest_data_field_ix` - selectable option or additional data field index
    /// - `ciphertext` - the ciphertext
    pub fn verify(
        &self,
        fixed_parameters: &FixedParameters,
        h_e: &ExtendedBaseHash_H_E,
        jpk: &JointPublicKey,
        contest_ix: ContestIndex,
        contest_data_field_ix: ContestDataFieldIndex,
        ciphertext: &Ciphertext,
    ) -> bool {
        let group = fixed_parameters.group();
        let t = jpk.group_element.exp(&self.plaintext, group);
        let m = match t.inv(group) {
            None => return false,
            Some(t_inv) => ciphertext.beta.mul(&t_inv, group),
        };
        self.proof.validate(
            fixed_parameters,
            h_e,
            jpk,
            contest_ix,
            contest_data_field_ix,
            ciphertext,
            &CombinedDecryptionShare(m),
        )
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t1 {
    use std::sync::Arc;

    use crate::{algebra::FieldElement, resource::ProduceResourceExt};
    use either::Either;

    use super::{CombinedDecryptionShare, DecryptionShare};
    use crate::{
        eg::Eg,
        election_parameters::{ElectionParameters, ElectionParametersInfo},
        fixed_parameters::{FixedParameters, FixedParametersTrait, FixedParametersTraitExt},
        guardian::GuardianIndex,
        validatable::Validated,
        varying_parameters::{BallotChaining, VaryingParameters, VaryingParametersInfo},
        verifiable_decryption::DecryptionShareCombinationError,
    };

    #[ignore] //? TODO
    #[test_log::test]
    fn test_decryption_share_combination() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::verifiable_decryption::t1::test_decryption_share_combination",
            );
            let eg = eg.as_ref();

            let n = GuardianIndex::try_from_one_based_index_u32(3).unwrap();
            let k = GuardianIndex::try_from_one_based_index_u32(3).unwrap();

            let varying_parameters_info = VaryingParametersInfo {
                n,
                k,
                date: "2023-05-02".to_string(),
                info: "The test election".to_string(),
                ballot_chaining: BallotChaining::Prohibited,
            };

            let election_parameters_info = ElectionParametersInfo {
                fixed_parameters: Either::Right(eg.fixed_parameters().await.unwrap()),
                varying_parameters: Either::Left(Arc::new(varying_parameters_info)),
            };
            let election_parameters =
                ElectionParameters::try_validate_from(election_parameters_info, eg).unwrap();

            let field = election_parameters.fixed_parameters().field();
            let group = election_parameters.fixed_parameters().group();

            // Using x^2-1 as polynomial
            let decryption_shares = [
                DecryptionShare {
                    guardian_ix: GuardianIndex::try_from_one_based_index_u32(1).unwrap(),
                    m_i: group.g_exp(&FieldElement::from(0_u8, field)),
                },
                DecryptionShare {
                    guardian_ix: GuardianIndex::try_from_one_based_index_u32(2).unwrap(),
                    m_i: group.g_exp(&FieldElement::from(3_u8, field)),
                },
                DecryptionShare {
                    guardian_ix: GuardianIndex::try_from_one_based_index_u32(3).unwrap(),
                    m_i: group.g_exp(&FieldElement::from(8_u8, field)),
                },
            ];
            let exp_m = CombinedDecryptionShare(group.g_exp(&FieldElement::from(126_u8, field)));

            assert_eq!(
                CombinedDecryptionShare::combine(&election_parameters, &decryption_shares)
                    .unwrap()
                    .0,
                exp_m.0
            );

            let gi_1: GuardianIndex = 1.try_into().unwrap();
            let gi_2: GuardianIndex = 2.try_into().unwrap();
            let gi_3: GuardianIndex = 3.try_into().unwrap();
            let gi_4: GuardianIndex = 4.try_into().unwrap();

            let combine_result =
                CombinedDecryptionShare::combine(&election_parameters, &decryption_shares[0..2]);
            let combine_err = combine_result.unwrap_err();
            let dec_share_comb_error = DecryptionShareCombinationError::NotEnoughShares { l: 2, k };
            assert_eq!(combine_err, dec_share_comb_error);

            let decryption_shares = [
                DecryptionShare {
                    guardian_ix: gi_1,
                    m_i: group.g_exp(&FieldElement::from(0_u8, field)),
                },
                DecryptionShare {
                    guardian_ix: gi_2,
                    m_i: group.g_exp(&FieldElement::from(3_u8, field)),
                },
                DecryptionShare {
                    guardian_ix: gi_4,
                    m_i: group.g_exp(&FieldElement::from(8_u8, field)),
                },
            ];

            assert!(matches!(
                CombinedDecryptionShare::combine(&election_parameters, &decryption_shares),
                Err(DecryptionShareCombinationError::InvalidGuardianIndex { i, n })
                if i == gi_4 && n == gi_3
            ));

            let decryption_shares = [
                DecryptionShare {
                    guardian_ix: gi_1,
                    m_i: group.g_exp(&FieldElement::from(0_u8, field)),
                },
                DecryptionShare {
                    guardian_ix: gi_2,
                    m_i: group.g_exp(&FieldElement::from(3_u8, field)),
                },
                DecryptionShare {
                    guardian_ix: gi_2,
                    m_i: group.g_exp(&FieldElement::from(8_u8, field)),
                },
            ];

            assert!(matches!(
                CombinedDecryptionShare::combine(&election_parameters, &decryption_shares).unwrap_err(),
                DecryptionShareCombinationError::DuplicateGuardian { i } if i == gi_2
            ));
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t2 {
    use std::{iter::zip, sync::Arc};

    use crate::algebra::FieldElement;

    use super::{CombinedDecryptionShare, DecryptionProof, DecryptionShare, VerifiableDecryption};
    use crate::{
        contest::ContestIndex,
        contest_data_fields::ContestDataFieldIndex,
        eg::Eg,
        errors::EgResult,
        fixed_parameters::{FixedParametersTrait, FixedParametersTraitExt},
        key::KeyPurpose,
        //? interguardian_share::{InterguardianShare, GuardianSecretKeyShare},
        resource::{ProduceResource, ProduceResourceExt},
        verifiable_decryption::DecryptionProofResponseShare,
    };

    #[ignore] //? TODO
    #[test_log::test]
    fn test_decryption_overall() {
        #[allow(unused_variables)] //? TODO: Remove temp development code
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::verifiable_decryption::t2::test_decryption_overall",
            );
            let eg = eg.as_ref();

            let election_parameters = eg.election_parameters().await.unwrap();
            let election_parameters = election_parameters.as_ref();
            let fixed_parameters = election_parameters.fixed_parameters();
            let field = fixed_parameters.field();

            let extended_base_hash = eg.extended_base_hash().await.unwrap();
            let extended_base_hash = extended_base_hash.as_ref();
            let h_e = extended_base_hash.h_e();

            let contest_ix = ContestIndex::one();
            let contest_data_field_ix = ContestDataFieldIndex::one();

            for key_purpose in [KeyPurpose::Ballot_Votes, KeyPurpose::Ballot_OtherData] {
                let jpk = match key_purpose {
                    KeyPurpose::Ballot_Votes => {
                        eg.joint_vote_encryption_public_key_k().await.unwrap()
                    }
                    KeyPurpose::Ballot_OtherData => eg
                        .joint_ballot_data_encryption_public_key_k_hat()
                        .await
                        .unwrap(),
                    _ => unreachable!(),
                };
                let jpk = jpk.as_ref();

                let gpks = eg.guardian_public_keys(key_purpose).await.unwrap();
                let gpks = gpks.iter_map_into(Arc::as_ref);

                let gsks = eg.guardians_secret_keys(key_purpose).await.unwrap();
                let gsks = gsks.iter_map_into(Arc::as_ref);

                assert!(false, "TODO rework for EGDS 2.1.0");
                /*

                let vec_vec_guardian_interguardian_share = eg
                    .guardian_public_keys(key_purpose)
                    .await
                    .unwrap()
                    .iter()
                    .map(|receiver_pk| {
                        gsks.iter()
                            .map(|sender_sk| {
                                InterguardianShare::encrypt(
                                    eg.csrng(),
                                    election_parameters,
                                    sender_sk,
                                    receiver_pk,
                                )
                                .unwrap()
                                .ciphertext
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                let mut secret_key_shares: Vec<GuardianSecretKeyShare> = Vec::with_capacity(gsks.len());
                for (&sk, shares) in zip(gsks.iter(), &vec_vec_guardian_interguardian_share) {
                    let gsk_share = GuardianSecretKeyShare::generate(eg, gpks.as_slice(), shares, sk)
                        .await
                        .unwrap();
                    secret_key_shares.push(gsk_share);
                }

                let message: usize = 42;
                let nonce = field.random_field_elem(eg.csrng());
                let ciphertext = jpk.encrypt_to(fixed_parameters, &nonce, message);

                let dec_shares: Vec<_> = secret_key_shares
                    .iter()
                    .map(|ks| DecryptionShare::from(fixed_parameters, ks, &ciphertext))
                    .collect();
                let combined_dec_share =
                    CombinedDecryptionShare::combine(election_parameters, &dec_shares).unwrap();

                let mut decryption_proof_commit_shares = vec![];
                let mut decryption_proof_state_shares = vec![];
                for key_share in secret_key_shares.iter() {
                    let (decryption_proof_commit_share, decryption_proof_state_share) =
                        DecryptionProof::generate_commit_share(
                            eg.csrng(),
                            fixed_parameters,
                            &ciphertext,
                            key_share.guardian_ix,
                        );
                    decryption_proof_commit_shares.push(decryption_proof_commit_share);
                    decryption_proof_state_shares.push(decryption_proof_state_share);
                }

                let mut decryption_proof_response_shares: Vec<DecryptionProofResponseShare> =
                    Vec::with_capacity(decryption_proof_state_shares.len());
                for (state, key_share) in decryption_proof_state_shares.iter().zip(&secret_key_shares) {
                    let decryption_proof_response_share = DecryptionProof::generate_response_share(
                        eg,
                        contest_ix,
                        contest_data_field_ix,
                        &ciphertext,
                        &combined_dec_share,
                        &decryption_proof_commit_shares,
                        state,
                        key_share,
                    )
                    .await
                    .unwrap();
                    decryption_proof_response_shares.push(decryption_proof_response_share);
                }

                let decryption_proof = DecryptionProof::combine_proof(
                    eg,
                    contest_ix,
                    contest_data_field_ix,
                    &ciphertext,
                    &dec_shares,
                    &decryption_proof_commit_shares,
                    &decryption_proof_response_shares,
                    gpks.as_slice(),
                )
                .await
                .unwrap();

                let decryption =
                    VerifiableDecryption::new(eg, &ciphertext, &combined_dec_share, &decryption_proof)
                        .await
                        .unwrap();

                assert_eq!(
                    decryption.plaintext,
                    FieldElement::from(message, field),
                    "Decryption should match the message."
                );

                assert!(decryption.verify(
                    fixed_parameters,
                    h_e,
                    jpk,
                    contest_ix,
                    contest_data_field_ix,
                    &ciphertext
                ));
                // */
            } // for key_purpose
        });
    }
}
