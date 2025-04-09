// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

//! This module provides the implementation of guardian key shares.
//!
//! For more details see Section `3.2.2` of the Electionguard specification `2.0.0`. [TODO fix ref]

use std::{
    //borrow::Cow,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    iter::zip,
    //path::{Path, PathBuf},
    //sync::Arc,
    //str::FromStr,
    //sync::OnceLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use rand::{distr::Uniform, Rng, RngCore};
use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};
use util::{
    algebra::{FieldElement, Group, GroupElement, ScalarField},
    bitwise::xor,
    csrng::Csrng,
};

use crate::{
    eg::Eg,
    el_gamal::{ElGamalPublicKey, ElGamalSecretKey},
    election_parameters::ElectionParameters,
    errors::{EgError, EgResult, PublicKeyValidationError},
    guardian::GuardianIndex,
    guardian_public_key::GuardianPublicKey,
    guardian_public_key_trait::GuardianKeyInfoTrait,
    guardian_secret_key::GuardianSecretKey,
    hash::{HValue, eg_h, eg_hmac},
    hashes::ParameterBaseHash,
    resource::{ProduceResource, ProduceResourceExt},
    validatable::Validated,
};

//=================================================================================================|

/// The secret input used to generate a [`GuardianEncryptedShare`].
///
/// This object is used in case there is a dispute about the validity of a given [`GuardianEncryptedShare`].
#[derive(Serialize, Deserialize)]
pub struct GuardianEncryptionSecret {
    /// The sender of the share
    pub sender: GuardianIndex,

    /// The recipient of the share
    pub recipient: GuardianIndex,

    /// The share in plain
    pub share: FieldElement,

    /// The used encryption nonce    
    pub nonce: FieldElement,
}

/// A tuple consisting of a [`GuardianEncryptedShare`] and the corresponding [`GuardianEncryptionSecret`].
pub struct ShareEncryptionResult {
    // The encrypted share
    pub ciphertext: GuardianEncryptedShare,

    // The corresponding secrets
    pub secret: GuardianEncryptionSecret,
}

/// Represents errors occurring while decrypting a [`GuardianEncryptedShare`].
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum DecryptionError {
    /// Occurs if the given public key does not match the sender.
    #[error("The sender of the ciphertext is {i}, but the public key has index {j}.")]
    DealerIndicesMismatch { i: GuardianIndex, j: GuardianIndex },

    /// Occurs if the given secret key does not match the recipient.
    #[error("The recipient of the ciphertext is {i}, but the secret key has index {j}.")]
    RecipientIndicesMismatch { i: GuardianIndex, j: GuardianIndex },

    /// Occurs if the mac is invalid.
    #[error("The MAC does not verify.")]
    InvalidMAC,

    /// Occurs if the decrypted share is invalid with respect to the sender's public key.
    #[error("The share does not validate against the sender's public key.")]
    InvalidShare,
}

/// An encrypted share for sending shares to other guardians.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GuardianEncryptedShare {
    /// The sender of the share
    pub sender: GuardianIndex,

    /// The recipient of the share
    pub recipient: GuardianIndex,

    /// First ciphertext part, corresponds to `C_{i,l,0}` in Equation `19`. [TODO fix ref]
    pub c0: GroupElement,

    /// Second ciphertext part, corresponds to `C_{i,l,1}` in Equation `19`. [TODO fix ref]
    pub c1: HValue,

    /// Third ciphertext part, corresponds to `C_{i,l,2}` in Equation `19`. [TODO fix ref]
    pub c2: HValue,
}

impl GuardianEncryptedShare {
    /* Err("TODO rework for EGDS 2.1.0")?
    /// Computes the share encryption secret key as defined in Equation `16`. [TODO fix ref]
    ///
    /// The arguments are
    /// - `election_parameters` - the election parameters
    /// - `i` - the sender index
    /// - `l` - the recipient index
    /// - `capital_k_l` - the recipient public key
    /// - `alpha` - as in Equation `14` [TODO fix ref]
    /// - `beta` - as in Equation `14` [TODO fix ref]
    fn secret_key(
        election_parameters: &ElectionParameters,
        i: u32,
        l: u32,
        capital_k_l: &GroupElement,
        alpha: &GroupElement,
        beta: &GroupElement,
    ) -> HValue {
        let h_p = ParameterBaseHash::compute(election_parameters).h_p;
        let group = election_parameters.fixed_parameters().group();
        // v = 0x11 | b(i, 4) | b(l, 4) | b(capital_k_l, 512) | b(alpha_l, 512) | b(beta_l, 512)
        let mut v = vec![0x11];
        v.extend_from_slice(i.to_be_bytes().as_slice());
        v.extend_from_slice(l.to_be_bytes().as_slice());
        v.extend_from_slice(capital_k_l.to_be_bytes_left_pad(group).as_slice());
        v.extend_from_slice(alpha.to_be_bytes_left_pad(group).as_slice());
        v.extend_from_slice(beta.to_be_bytes_left_pad(group).as_slice());
        eg_h(&h_p, &v)
    }
    // */

    /* Err("TODO rework for EGDS 2.1.0")?

    /// Computes the MAC key (eq `16`) and the encryption keys (eq `17` and `18`). [TODO fix ref]
    ///
    /// The arguments are
    /// - `i` - the sender index
    /// - `l` - the recipient index
    /// - `k_i_l` - the secret key as in Equation `15` [TODO fix ref]
    fn mac_and_encryption_key(i: u32, l: u32, k_i_l: &HValue) -> (HValue, HValue) {
        // label = b("share_enc_keys",14)
        let label = "share_enc_keys".as_bytes();
        // context = b("share_encrypt",13) | b(i, 4) | b(l, 4)
        let mut context = "share_encrypt".as_bytes().to_vec();
        context.extend_from_slice(i.to_be_bytes().as_slice());
        context.extend_from_slice(l.to_be_bytes().as_slice());

        // MAC key, eq. 17
        // v = 0x01 | label | 0x00 | context | 0x0200
        let mut v = vec![0x01];
        v.extend_from_slice(label);
        v.push(0x00);
        v.extend(&context);
        v.extend([0x02, 0x00]);
        let k1 = eg_hmac(k_i_l, &v);

        // Encryption key, eq. 18
        // v = 0x02 | label | 0x00 | context | 0x0200
        let mut v = vec![0x02];
        v.extend_from_slice(label);
        v.push(0x00);
        v.extend(context);
        v.extend(vec![0x02, 0x00]);
        let k2 = eg_hmac(k_i_l, &v);

        (k1, k2)
    }

    /// Computes the MAC as in Equation `19`. [TODO fix ref]
    ///
    /// The arguments are
    ///
    /// - `k0` - the MAC key
    /// - `c0` - ciphertext part 1
    /// - `c1` - ciphertext part 2
    fn share_mac(k0: HValue, c0: &[u8], c1: &HValue) -> HValue {
        let mut v = c0.to_vec();
        v.extend_from_slice(c1.0.as_slice());
        eg_hmac(&k0, &v)
    }
    // */

    /*
    /// Computes a [`GuardianEncryptedShare`] of a share for a given recipient and nonce.
    ///
    /// The arguments are
    ///
    /// - `election_parameters` - the election parameters
    /// - 'sender_ix' - the sender index
    /// - `nonce` - the encryption nonce
    /// - `share` - the secret key share
    /// - `receiver_public_key` - the receiver's [`GuardianPublicKey`]
    ///
    /// This function is deterministic.
    fn new(
        election_parameters: &ElectionParameters,
        sender_ix: GuardianIndex,
        nonce: &FieldElement,
        share: &FieldElement,
        receiver_public_key: &GuardianPublicKey,
    ) -> EgResult<Self> {
        Err("TODO rework for EGDS 2.1.0")?;

        let group = election_parameters.fixed_parameters().group();

        let i = sender_ix.get_one_based_u32();
        let l = receiver_public_key.i().get_one_based_u32();
        let capital_k = receiver_public_key.public_key_k_i_0()?;

        // Generate alpha and beta (Equation 14) [TODO fix ref]
        let alpha = group.g_exp(nonce);
        let beta = capital_k.exp(nonce, group);

        let k_i_l = Self::secret_key(election_parameters, i, l, capital_k, &alpha, &beta);
        let (k0, k1) = Self::mac_and_encryption_key(i, l, &k_i_l);

        // Ciphertext as in Equation (19) [TODO fix ref]
        let c1 = xor(share.to_32_be_bytes().as_slice(), k1.0.as_slice());

        let c1: HValue = (&c1[0..32]).try_into()?;
        let c2: HValue = Self::share_mac(k0, alpha.to_be_bytes_left_pad(group).as_slice(), &c1);

        Ok(GuardianEncryptedShare {
            sender: sender_ix,
            recipient: receiver_public_key.i(),
            c0: alpha,
            c1,
            c2,
        })
    }
    // */

    /// Creates a new [`ShareEncryptionResult`] given the sender's secret key for a given recipient.
    ///
    /// The arguments are
    /// - `csrng` - secure randomness generator
    /// - `election_parameters` - the election parameters
    /// - `sender_secret_key` - the sender's [`GuardianSecretKey`]
    /// - `receiver_public_key` - the receiver's [`GuardianPublicKey`]
    pub fn encrypt(
        csrng: &dyn Csrng,
        election_parameters: &ElectionParameters,
        sender_secret_key: &GuardianSecretKey,
        receiver_public_key: &GuardianPublicKey,
    ) -> EgResult<ShareEncryptionResult> {
        let fixed_parameters = election_parameters.fixed_parameters();
        let field = fixed_parameters.field();

        Err("TODO rework for EGDS 2.1.0")?
        /*

        let l = receiver_public_key.i().get_one_based_u32();

        // Generate key share as P(l) (cf. Equations 9 and 18) using Horner's method [TODO fix ref]
        let x = FieldElement::from(l, field);
        let mut p_l = ScalarField::zero();
        for coeff in sender_secret_key.secret_coefficients().0.iter().rev() {
            p_l = p_l.mul(&x, field).add(&coeff.0, field);
        }

        // Generate a fresh nonce
        let nonce = field.random_field_elem(csrng);

        // Encrypt the share
        let ciphertext: GuardianEncryptedShare = Self::new(
            election_parameters,
            sender_secret_key.i(),
            &nonce,
            &p_l,
            receiver_public_key,
        )?;

        let secret = GuardianEncryptionSecret {
            sender: sender_secret_key.i(),
            recipient: receiver_public_key.i(),
            share: p_l,
            nonce,
        };

        Ok(ShareEncryptionResult { ciphertext, secret })
        // */
    }

    /// EGDS 2.1.0 eq. 23 pg. 26.
    ///
    /// Decrypts and validates a [`GuardianEncryptedShare`].
    ///
    /// The arguments are
    ///
    /// - `self` - the encrypted share
    /// - `election_parameters` - the election parameters
    /// - `sender_public_key` - the sender's [`ElGamalPublicKey`]
    /// - `receiver_secret_key` - the receiver's [`ElGamalSecretKey`]
    pub fn decrypt_and_validate(
        &self,
        election_parameters: &ElectionParameters,
        sender_public_key: &GuardianPublicKey,
        receiver_secret_key: &GuardianSecretKey,
    ) -> EgResult<FieldElement> {
        Err("TODO rework for EGDS 2.1.0")?
        /*
        if self.sender != sender_public_key.i() {
            return Err(DecryptionError::DealerIndicesMismatch {
                i: self.sender,
                j: sender_public_key.i(),
            });
        }
        if self.recipient != receiver_secret_key.i() {
            return Err(DecryptionError::RecipientIndicesMismatch {
                i: self.sender,
                j: sender_public_key.i(),
            });
        }

        let fixed_parameters = election_parameters.fixed_parameters();
        let field = fixed_parameters.field();
        let group = fixed_parameters.group();

        let i = self.sender.get_one_based_u32();
        let l = self.recipient.get_one_based_u32();

        let capital_k = &receiver_secret_key.coefficient_commitments().as_slice()[0].0;
        let alpha = &self.c0;
        let beta = alpha.exp(receiver_secret_key.secret_s(), group);
        let k_i_l = Self::secret_key(election_parameters, i, l, capital_k, alpha, &beta);

        let (k0, k1) = Self::mac_and_encryption_key(i, l, &k_i_l);
        let mac = Self::share_mac(k0, alpha.to_be_bytes_left_pad(group).as_slice(), &self.c1);

        if mac != self.c2 {
            return Err(DecryptionError::InvalidMAC);
        }

        // Decryption as in Equation `20` [TODO fix ref]
        let p_l_bytes = xor(self.c1.0.as_slice(), k1.0.as_slice());
        let p_l = FieldElement::from_bytes_be(p_l_bytes.as_slice(), field);

        // Share validity check
        let g_p_l = group.g_exp(&p_l);

        // RHS of Equation `21` [TODO fix ref]
        let l = FieldElement::from(l, field);
        let vec_k_i_j: &Vec<_> = sender_public_key.coefficient_commitments();
        let rhs = (0u32..)
            .zip(vec_k_i_j)
            .fold(Group::one(), |prod, (j, k_i_j)| {
                let l_pow_j = l.pow(j, field);
                prod.mul(&k_i_j.0.exp(&l_pow_j, group), group)
            });
        if g_p_l != rhs {
            return Err(DecryptionError::InvalidShare);
        }

        Ok(p_l)
        // */
    }
}

/// Errors that may occur with the public validation of a [`GuardianEncryptedShare`].
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum GuardianEncryptedSharePublicValidationError {
    #[error(
        "DealerPublicKeyMismatch: This guardian encrypted share is from sender `{expected_dealer}`, but the public key for guardian `{supplied_dealer}` was supplied."
    )]
    DealerPublicKeyMismatch {
        expected_dealer: GuardianIndex,
        supplied_dealer: GuardianIndex,
    },

    #[error(
        "RecipientPublicKeyMismatch: This guardian encrypted share is for recipient `{expected_recipient}`, but the public key for guardian `{supplied_recipient}` was supplied."
    )]
    RecipientPublicKeyMismatch {
        expected_recipient: GuardianIndex,
        supplied_recipient: GuardianIndex,
    },

    #[error(
        "DealerSecretMismatch: This guardian encrypted share is from sender `{sender}` for recipient `{recipient}`, but the guardian encryption secret is for sender `{guardian_encryption_secret_dealer}` and recipient `{guardian_encryption_secret_recipient}`."
    )]
    DealerSecretMismatch {
        sender: GuardianIndex,
        recipient: GuardianIndex,
        guardian_encryption_secret_dealer: GuardianIndex,
        guardian_encryption_secret_recipient: GuardianIndex,
    },

    #[error(
        "RecipientSecretMismatch: This guardian encrypted share is from sender {sender} for recipient {recipient}, but the guardian encryption secret is for sender `{guardian_encryption_secret_dealer}` and recipient `{guardian_encryption_secret_recipient}`."
    )]
    RecipientSecretMismatch {
        sender: GuardianIndex,
        recipient: GuardianIndex,
        guardian_encryption_secret_dealer: GuardianIndex,
        guardian_encryption_secret_recipient: GuardianIndex,
    },

    #[error(
        "The guardian encrypted share ciphertext does not match the value expected for these values of the sender's public key and the guardian encryption secret and nonce."
    )]
    CiphertextDoesNotMatchExpectedValue,

    #[error("The guardian encrypted share fails the validity check.")]
    ValidityCheckFailed,
}

impl GuardianEncryptedShare {
    /// Validates a [`GuardianEncryptedShare`] with respect to given [`GuardianEncryptionSecret`] and [`GuardianPublicKey`] of sender and recipient in case of a dispute.
    ///
    /// The arguments are
    ///
    /// - `self` - the encrypted share
    /// - `election_parameters` - the election parameters
    /// - `sender_public_key` - the sender's [`GuardianPublicKey`]
    /// - `receiver_public_key` - the receiver's [`GuardianPublicKey`]
    /// - `secret` - the published [`GuardianEncryptionSecret`]
    ///
    /// Returns false if the sender's published secrets do not match the published
    /// ciphertext, or Equation `21`. [TODO fix ref]
    ///
    /// If they match, the function returns `Ok(())`, meaning the receiver's claim about the
    /// wrongdoing by the sender is dismissed.
    pub fn public_validation(
        &self,
        election_parameters: &ElectionParameters,
        sender_public_key: &GuardianPublicKey,
        receiver_public_key: &GuardianPublicKey,
        secret: &GuardianEncryptionSecret,
    ) -> EgResult<()> {
        Err("TODO rework for EGDS 2.1.0")?
        /*

        if self.sender != sender_public_key.i() {
            Err(
                GuardianEncryptedSharePublicValidationError::DealerPublicKeyMismatch {
                    expected_dealer: self.sender,
                    supplied_dealer: sender_public_key.i(),
                },
            )?;
        }

        if self.recipient != receiver_public_key.i() {
            Err(
                GuardianEncryptedSharePublicValidationError::RecipientPublicKeyMismatch {
                    expected_recipient: self.recipient,
                    supplied_recipient: receiver_public_key.i(),
                },
            )?;
        }

        if self.sender != secret.sender {
            Err(
                GuardianEncryptedSharePublicValidationError::DealerSecretMismatch {
                    sender: self.sender,
                    recipient: self.recipient,
                    guardian_encryption_secret_dealer: secret.sender,
                    guardian_encryption_secret_recipient: secret.recipient,
                },
            )?;
        }

        if self.recipient != secret.recipient {
            Err(
                GuardianEncryptedSharePublicValidationError::RecipientSecretMismatch {
                    sender: self.sender,
                    recipient: self.recipient,
                    guardian_encryption_secret_dealer: secret.sender,
                    guardian_encryption_secret_recipient: secret.recipient,
                },
            )?;
        }

        let fixed_parameters = election_parameters.fixed_parameters();
        let field = fixed_parameters.field();
        let group = fixed_parameters.group();

        // Check that the ciphertext was computed correctly
        let expected_ciphertext = Self::new(
            election_parameters,
            self.sender,
            &secret.nonce,
            &secret.share,
            receiver_public_key,
        )?;

        if *self != expected_ciphertext {
            Err(GuardianEncryptedSharePublicValidationError::CiphertextDoesNotMatchExpectedValue)?;
        }

        let l = self.recipient.get_one_based_u32();

        // Share validity check
        let g_p_l = group.g_exp(&secret.share);

        // RHS of Equation `21` [TODO fix ref]
        let l = &FieldElement::from(l, field);
        let vec_k_i_j: &Vec<_> = sender_public_key.coefficient_commitments();
        let rhs = (0u32..)
            .zip(vec_k_i_j)
            .fold(Group::one(), |prod, (j, k_i_j)| {
                let l_pow_j = l.pow(j, field);
                prod.mul(&k_i_j.0.exp(&l_pow_j, group), group)
            });

        if g_p_l != rhs {
            Err(GuardianEncryptedSharePublicValidationError::ValidityCheckFailed)?;
        }

        Ok(())
        // */
    }
}

/// A guardian's share of the joint secret key, it corresponds to `P(i)` in Equation `22`. [TODO fix ref]
///
/// The corresponding public key is never computed explicitly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianSecretKeyShare {
    /// Guardian index, 1 <= i <= [`n`](crate::varying_parameters::VaryingParameters::n).
    pub guardian_ix: GuardianIndex,

    /// Secret key share
    pub z_i: FieldElement,
}

/// Errors that may occur when combining shares to generate a [`GuardianSecretKeyShare`].
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum GuardianSecretKeyShareGenerationError {
    /// One or more guardian public keys are missing.
    #[error("Public keys are missing for guardian(s): {0}")]
    MissingGuardians(String),

    /// A guardian public key is invalid.
    #[error("Public key of guardian `{guardian}` is invalid: {error}")]
    GuardianPublicKeyInvalid {
        guardian: GuardianIndex,
        error: PublicKeyValidationError,
    },

    /// Multiple public keys of the same guardian were given.
    #[error("Guardian `{0}` is represented more than once in the guardian public keys.")]
    DuplicateGuardian(GuardianIndex),

    /// A [`GuardianEncryptedShare`] was missing.
    #[error("The encrypted share corresponding to guardian `{0}` is missing.")]
    EncryptedShareMissing(GuardianIndex),

    /// A [`GuardianEncryptedShare`] was missing.
    #[error(
        "The guardian listed in the encrypted share `{guardian_listed_in_encrypted_share}` corresponds to the public key from guardian `{guardian_listed_in_public_key}`."
    )]
    EncryptedShareCorrespondsToWrongPublicKey {
        guardian_listed_in_encrypted_share: GuardianIndex,
        guardian_listed_in_public_key: GuardianIndex,
    },

    /// Different numbers of [`GuardianPublicKey`]s and [`GuardianEncryptedShare`]s were supplied.
    #[error(
        "Different numbers of guardian public keys (`{cnt_guardian_public_keys}`) and encrypted shares (`{cnt_encrypted_shares}`) were supplied."
    )]
    GuardianPublicKeyAndEncryptedShareQuantityMismatch {
        cnt_guardian_public_keys: usize,
        cnt_encrypted_shares: usize,
    },

    /// A [`GuardianEncryptedShare`] could not be decrypted.
    #[error(
        "Could not decrypt and validate all shares. There are issues with shares from the following guardians: {0}"
    )]
    DecryptionError(String),

    #[error("Guardian secret key generation error: {0}")]
    EgError(#[from] Box<EgError>),
}

impl From<EgError> for GuardianSecretKeyShareGenerationError {
    fn from(e: EgError) -> Self {
        GuardianSecretKeyShareGenerationError::EgError(Box::new(e))
    }
}

impl GuardianSecretKeyShare {
    /// Computes the [`GuardianSecretKeyShare`] from the [`GuardianEncryptedShare`]s.
    ///
    /// The arguments are
    ///
    /// - `produce_resource` - common resource data provider
    /// - `guardian_public_keys` - a sequence of [`GuardianPublicKey`]s
    /// - `encrypted_shares` - a sequence of [`GuardianEncryptedShare`]
    /// - `receiver_secret_key` - the receiver's [`GuardianSecretKey`]
    ///
    /// Verifies that the i-th `GuardianPublicKey` and the i-th `GuardianEncryptedShare` correspond to the same Guardian.
    pub async fn generate(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        guardian_public_keys: &[&GuardianPublicKey],
        encrypted_shares: &[GuardianEncryptedShare],
        receiver_secret_key: &GuardianSecretKey,
    ) -> Result<Self, GuardianSecretKeyShareGenerationError> {
        let pre_voting_data = produce_resource.pre_voting_data().await?;
        let pre_voting_data = pre_voting_data.as_ref();
        let election_parameters = pre_voting_data.election_parameters();
        let fixed_parameters = election_parameters.fixed_parameters();
        let field = fixed_parameters.field();
        let varying_parameters = election_parameters.varying_parameters();

        let n = varying_parameters.n().get_one_based_usize();

        // Verify that every guardian is represented exactly once.
        let mut seen = vec![false; n];
        for &guardian_public_key in guardian_public_keys {
            let seen_ix = guardian_public_key.i().get_zero_based_usize();
            if seen[seen_ix] {
                Err(GuardianSecretKeyShareGenerationError::DuplicateGuardian(
                    guardian_public_key.i(),
                ))?;
            }
            seen[seen_ix] = true;
        }

        // Verify that the encrypted shares are from every guardian.
        for (guardian_ix0, &guardian_public_key) in guardian_public_keys.iter().enumerate() {
            let guardian_listed_in_public_key = guardian_public_key.i();
            let encrypted_share: &GuardianEncryptedShare =
                encrypted_shares.get(guardian_ix0).ok_or(
                    GuardianSecretKeyShareGenerationError::EncryptedShareMissing(
                        guardian_listed_in_public_key,
                    ),
                )?;
            let guardian_listed_in_encrypted_share = encrypted_share.sender;
            if guardian_listed_in_encrypted_share != guardian_listed_in_public_key {
                return Err(
                    GuardianSecretKeyShareGenerationError::EncryptedShareCorrespondsToWrongPublicKey {
                        guardian_listed_in_encrypted_share,
                        guardian_listed_in_public_key,
                    },
                );
            }
        }

        // Verify that there are no additional encrypted shares.
        if encrypted_shares.len() != guardian_public_keys.len() {
            return Err(GuardianSecretKeyShareGenerationError::GuardianPublicKeyAndEncryptedShareQuantityMismatch {
                cnt_guardian_public_keys: guardian_public_keys.len(),
                cnt_encrypted_shares: encrypted_shares.len(),
            });
        }

        let missing_guardian_ixs: Vec<usize> = seen
            .iter()
            .enumerate()
            .filter(|&(_ix, &seen)| !seen)
            .map(|(ix, _)| ix)
            .collect();

        if !missing_guardian_ixs.is_empty() {
            let s = missing_guardian_ixs.iter().fold(String::new(), |acc, ix| {
                if acc.is_empty() {
                    (ix + 1).to_string()
                } else {
                    acc + "," + &(ix + 1).to_string()
                }
            });

            return Err(GuardianSecretKeyShareGenerationError::MissingGuardians(s));
        }

        // Validate every supplied guardian public key.
        for &guardian_public_key in guardian_public_keys {
            guardian_public_key
                .clone()
                .re_validate(produce_resource)
                .map_err(|error| {
                    GuardianSecretKeyShareGenerationError::GuardianPublicKeyInvalid {
                        guardian: guardian_public_key.i(),
                        error: error.into(),
                    }
                })?;
        }

        // Decrypt and validate shares
        let mut shares = vec![];
        let mut issues = vec![];
        for (&sender_public_key, share) in zip(guardian_public_keys, encrypted_shares) {
            let res = share.decrypt_and_validate(
                election_parameters,
                sender_public_key,
                receiver_secret_key,
            );
            match res {
                Err(e) => issues.push((sender_public_key.i(), e)),
                Ok(share) => shares.push(share),
            }
        }

        if !issues.is_empty() {
            let info = issues.iter().fold(String::new(), |acc, (i, _)| {
                if acc.is_empty() {
                    i.get_one_based_usize().to_string()
                } else {
                    acc + "," + &i.get_one_based_usize().to_string()
                }
            });

            return Err(GuardianSecretKeyShareGenerationError::DecryptionError(info));
        }

        let key = shares
            .iter()
            .fold(FieldElement::from(0_u8, field), |acc, share| {
                acc.add(share, field)
            });

        Ok(Self {
            guardian_ix: receiver_secret_key.i(),
            z_i: key,
        })
    }
}

//-------------------------------------------------------------------------------------------------|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::{iter::zip, sync::Arc};

    use util::{
        algebra::{FieldElement, ScalarField},
        algebra_utils::field_lagrange_at_zero,
    };

    use super::{GuardianEncryptedShare, GuardianSecretKeyShare};
    use crate::{
        eg::{Eg, EgConfig},
        errors::EgResult,
        guardian::GuardianKeyPurpose,
        guardian_public_key_trait::GuardianKeyInfoTrait,
        resource::{ProduceResource, ProduceResourceExt},
    };

    #[test_log::test]
    #[allow(clippy::needless_as_bytes)]
    fn test_text_encoding() {
        assert_eq!("share_enc_keys".as_bytes().len(), 14);
        assert_eq!("share_encrypt".as_bytes().len(), 13);
    }

    const N: u32 = 2;
    const K: u32 = N;

    #[test_log::test]
    fn test_encryption_decryption() {
        async_global_executor::block_on(test_encryption_decryption_async());
    }

    async fn test_encryption_decryption_async() {
        let eg = {
            let mut config = EgConfig::new();
            config.use_insecure_deterministic_csprng_seed_str(
                "eg::guardian_share::test::test_encryption_decryption",
            );
            config.enable_test_data_generation_n_k(N, K).unwrap();
            Eg::from_config(config)
        };
        let eg = eg.as_ref();

        let election_parameters = eg.election_parameters().await.unwrap();
        let election_parameters = election_parameters.as_ref();

        let key_purpose = GuardianKeyPurpose::Encrypt_InterGuardianCommunication;

        let gpks = eg.guardian_public_keys(key_purpose).await.unwrap();
        let gpks = gpks.map_into(Arc::as_ref);

        let gsks = eg.guardians_secret_keys(key_purpose).await.unwrap();
        let gsks = gsks.map_into(Arc::as_ref);

        let [&pk_sender, &pk_recipient] = gpks.arr_refs::<{ N as usize }>().unwrap();
        let [&sk_sender, &sk_recipient] = gsks.arr_refs::<{ N as usize }>().unwrap();

        let encrypted_result = GuardianEncryptedShare::encrypt(
            eg.csrng(),
            election_parameters,
            sk_sender,
            pk_recipient,
        )
        .unwrap();

        let result = encrypted_result.ciphertext.decrypt_and_validate(
            election_parameters,
            pk_sender,
            sk_recipient,
        );

        assert!(result.is_ok(), "The decrypted share should be valid");
    }

    #[test_log::test]
    fn test_key_sharing() {
        async_global_executor::block_on(test_key_sharing_async());
    }

    async fn test_key_sharing_async() {
        let eg = {
            let mut config = EgConfig::new();
            config.use_insecure_deterministic_csprng_seed_str(
                "eg::guardian_share::test::test_key_sharing",
            );
            config.enable_test_data_generation_n_k(N, K).unwrap();
            Eg::from_config(config)
        };
        let eg = eg.as_ref();

        let election_parameters = eg.election_parameters().await.unwrap();
        let election_parameters = election_parameters.as_ref();
        let fixed_parameters = election_parameters.fixed_parameters();
        let field = fixed_parameters.field();
        let csrng = eg.csrng();

        let key_purpose = GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields;

        let gpks_rc = eg.guardian_public_keys(key_purpose).await.unwrap();

        let gsks = eg.guardians_secret_keys(key_purpose).await.unwrap();

        // Compute secret key shares
        let share_vecs = gpks_rc
            .iter()
            .map(|receiver_public_key| {
                gsks.iter()
                    .map(|sender_sk| {
                        GuardianEncryptedShare::encrypt(
                            csrng,
                            election_parameters,
                            sender_sk,
                            receiver_public_key,
                        )
                        .unwrap()
                        .ciphertext
                    })
                    .collect::<Vec<GuardianEncryptedShare>>()
            })
            .collect::<Vec<Vec<GuardianEncryptedShare>>>();

        let secret_key_shares: Vec<GuardianSecretKeyShare> = {
            let gpks = gpks_rc.map_into(Arc::as_ref);
            let mut secret_key_shares: Vec<GuardianSecretKeyShare> = Vec::with_capacity(gsks.len());
            for (sender_sk, shares) in zip(gsks.iter(), share_vecs.iter()) {
                let gsk_share = GuardianSecretKeyShare::generate(
                    eg,
                    gpks.as_slice(),
                    shares.as_slice(),
                    sender_sk.as_ref(),
                )
                .await
                .unwrap();
                secret_key_shares.push(gsk_share);
            }
            secret_key_shares
        };
        let eg = eg.as_ref();

        // Compute joint secret key from secret keys
        let joint_secret_key_from_secret_keys =
            gsks.iter().fold(ScalarField::zero(), |acc, share| {
                acc.add(share.secret_s(), field)
            });

        // Compute joint secret key from shares
        let joint_secret_key_from_secret_key_shares = {
            let xs = gpks_rc
                .iter()
                .map(|guardian_public_key| {
                    FieldElement::from(guardian_public_key.i().get_one_based_u32(), field)
                })
                .collect::<Vec<FieldElement>>();
            let ys = secret_key_shares
                .iter()
                .map(|s| s.z_i.clone())
                .collect::<Vec<FieldElement>>();
            field_lagrange_at_zero(&xs, &ys, field).unwrap()
        };

        assert_eq!(
            joint_secret_key_from_secret_keys,
            joint_secret_key_from_secret_key_shares
        );
    }

    #[test_log::test]
    fn test_public_validation() {
        async_global_executor::block_on(async {
            let eg = {
                let mut config = EgConfig::new();
                config.use_insecure_deterministic_csprng_seed_str(
                    "eg::guardian_share::test::test_public_validation",
                );
                config.enable_test_data_generation_n_k(N, K).unwrap();
                Eg::from_config(config)
            };
            let eg = eg.as_ref();

            let election_parameters = eg.election_parameters().await.unwrap();
            let election_parameters = election_parameters.as_ref();

            let key_purpose = GuardianKeyPurpose::Encrypt_InterGuardianCommunication;

            let gpks = eg.guardian_public_keys(key_purpose).await.unwrap();
            let gpks = gpks.map_into(Arc::as_ref);

            let gsks = eg.guardians_secret_keys(key_purpose).await.unwrap();
            let gsks = gsks.map_into(Arc::as_ref);

            let [&pk_one, &pk_two] = gpks.arr_refs::<{ N as usize }>().unwrap();
            let [&sk_one, &sk_two] = gsks.arr_refs::<{ N as usize }>().unwrap();

            let csrng = eg.csrng();

            let enc_res_1 =
                GuardianEncryptedShare::encrypt(csrng, election_parameters, sk_one, pk_two)
                    .unwrap();

            let enc_res_2 =
                GuardianEncryptedShare::encrypt(csrng, election_parameters, sk_one, pk_one)
                    .unwrap();

            let enc_res_3 =
                GuardianEncryptedShare::encrypt(csrng, election_parameters, sk_two, pk_one)
                    .unwrap();

            assert!(
                enc_res_1
                    .ciphertext
                    .public_validation(election_parameters, pk_one, pk_two, &enc_res_1.secret)
                    .is_ok(),
                "The ciphertext should be valid"
            );
            assert!(
                enc_res_2
                    .ciphertext
                    .public_validation(election_parameters, pk_one, pk_two, &enc_res_1.secret)
                    .is_err(),
                "The ciphertext should not be valid"
            );
            assert!(
                enc_res_3
                    .ciphertext
                    .public_validation(election_parameters, pk_one, pk_two, &enc_res_1.secret)
                    .is_err(),
                "The ciphertext should not be valid"
            );
        });
    }
}
