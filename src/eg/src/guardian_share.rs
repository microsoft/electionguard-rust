#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

//! This module provides the implementation of guardian key shares.
//!
//! For more details see Section `3.2.2` of the Electionguard specification `2.0.0`.

use std::iter::zip;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use util::{
    algebra::{FieldElement, Group, GroupElement, ScalarField},
    bitwise::xor,
    csprng::Csprng,
};

use crate::{
    election_parameters::ElectionParameters,
    fixed_parameters::FixedParameters,
    guardian::GuardianIndex,
    guardian_public_key::GuardianPublicKey,
    guardian_secret_key::GuardianSecretKey,
    hash::{eg_h, eg_hmac, HValue},
    hashes::ParameterBaseHash,
    pre_voting_data::PreVotingData,
};

/// The secret input used to generate a [`GuardianEncryptedShare`].
///
/// This object is used in case there is a dispute about the validity of a given [`GuardianEncryptedShare`].
#[derive(Serialize, Deserialize)]
pub struct GuardianEncryptionSecret {
    /// The sender of the share
    pub dealer: GuardianIndex,
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
#[derive(Error, Debug)]
pub enum DecryptionError {
    /// Occurs if the given public key does not match the dealer.
    #[error("The dealer of the ciphertext is {i}, but the public key has index {j}.")]
    DealerIndicesMismatch { i: GuardianIndex, j: GuardianIndex },
    /// Occurs if the given secret key does not match the recipient.
    #[error("The recipient of the ciphertext is {i}, but the secret key has index {j}.")]
    RecipientIndicesMismatch { i: GuardianIndex, j: GuardianIndex },
    /// Occurs if the mac is invalid.
    #[error("The MAC does not verify.")]
    InvalidMAC,
    /// Occurs if the decrypted share is invalid with respect to the dealer's public key.
    #[error("The share does not validate against the dealer's public key.")]
    InvalidShare,
}

/// An encrypted share for sending shares to other guardians.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GuardianEncryptedShare {
    /// The sender of the share
    pub dealer: GuardianIndex,
    /// The recipient of the share
    pub recipient: GuardianIndex,
    /// First ciphertext part, corresponds to `C_{i,l,0}` in Equation `19`.
    pub c0: GroupElement,
    /// Second ciphertext part, corresponds to `C_{i,l,1}` in Equation `19`.
    pub c1: HValue,
    /// Third ciphertext part, corresponds to `C_{i,l,2}` in Equation `19`.
    pub c2: HValue,
}

impl GuardianEncryptedShare {
    /// This function computes the share encryption secret key as defined in Equation `15`.
    ///
    /// The arguments are
    /// - `fixed_parameters` - the fixed parameters
    /// - `i` - the dealer index
    /// - `l` - the recipient index
    /// - `capital_k_l` - the recipient public key
    /// - `alpha` - as in Equation `14`
    /// - `beta` - as in Equation `14`
    fn secret_key(
        fixed_parameters: &FixedParameters,
        i: u32,
        l: u32,
        capital_k_l: &GroupElement,
        alpha: &GroupElement,
        beta: &GroupElement,
    ) -> HValue {
        let h_p = ParameterBaseHash::compute(fixed_parameters).h_p;
        let group = &fixed_parameters.group;
        // v = 0x11 | b(i, 4) | b(l, 4) | b(capital_k, 512) | b(alpha,l, 512) | b(beta,l, 512)
        let mut v = vec![0x11];
        v.extend_from_slice(i.to_be_bytes().as_slice());
        v.extend_from_slice(l.to_be_bytes().as_slice());
        v.extend_from_slice(capital_k_l.to_be_bytes_left_pad(group).as_slice());
        v.extend_from_slice(alpha.to_be_bytes_left_pad(group).as_slice());
        v.extend_from_slice(beta.to_be_bytes_left_pad(group).as_slice());
        eg_h(&h_p, &v)
    }

    /// This function computes the MAC key (Equation `16`) and the encryption key (Equation `17`).
    ///
    /// The arguments are
    /// - `i` - the dealer index
    /// - `l` - the recipient index
    /// - `k_i_l` - the secret key as in Equation `15`
    fn mac_and_encryption_key(i: u32, l: u32, k_i_l: &HValue) -> (HValue, HValue) {
        // label = b("share_enc_keys",14)
        let label = "share_enc_keys".as_bytes();
        // context = b("share_encrypt",13) | b(i, 4) | b(l, 4)
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

    /// This function computes the MAC as in Equation `19`.
    ///
    /// The arguments are
    /// - `k0` - the MAC key
    /// - `c0` - ciphertext part 1
    /// - `c1` - ciphertext part 2
    fn share_mac(k0: HValue, c0: &[u8], c1: &HValue) -> HValue {
        let mut v = c0.to_vec();
        v.extend_from_slice(c1.0.as_slice());
        eg_hmac(&k0, &v)
    }

    /// This function computes a [`GuardianEncryptedShare`] of a share for a given recipient and nonce.
    ///
    /// The arguments are
    /// - `fixed_parameters` - the fixed parameters
    /// - 'dealer' - the dealer index
    /// - `nonce` - the encryption nonce
    /// - `share` - the secret key share
    /// - `recipient_public_key` - the recipient's [`GuardianPublicKey`]    
    ///
    /// This function is deterministic.
    fn new(
        fixed_parameters: &FixedParameters,
        dealer: &GuardianIndex,
        nonce: &FieldElement,
        share: &FieldElement,
        recipient_public_key: &GuardianPublicKey,
    ) -> Self {
        let group = &fixed_parameters.group;

        let i = dealer.get_one_based_u32();
        let l = recipient_public_key.i.get_one_based_u32();
        let capital_k = recipient_public_key.public_key_k_i_0();

        //Generate alpha and beta (Equation 14)
        let alpha = group.g_exp(nonce);
        let beta = capital_k.exp(nonce, group);

        let k_i_l = Self::secret_key(fixed_parameters, i, l, capital_k, &alpha, &beta);
        let (k0, k1) = Self::mac_and_encryption_key(i, l, &k_i_l);

        //Ciphertext as in Equation (19)
        let c1 = xor(share.to_32_be_bytes().as_slice(), k1.0.as_slice());
        //The unwrap is justified as the output of the XOR will always be 32 bytes.
        #[allow(clippy::unwrap_used)]
        let c1 = HValue(c1[0..32].try_into().unwrap());
        let c2 = Self::share_mac(k0, alpha.to_be_bytes_left_pad(group).as_slice(), &c1);

        GuardianEncryptedShare {
            dealer: *dealer,
            recipient: recipient_public_key.i,
            c0: alpha,
            c1,
            c2,
        }
    }

    /// This function creates a new [`ShareEncryptionResult`] given the dealer's secret key for a given recipient.
    ///
    /// The arguments are
    /// - `csprng` - secure randomness generator
    /// - `election_parameters` - the election parameters
    /// - `dealer_private_key` - the dealer's [`GuardianSecretKey`]
    /// - `recipient_public_key` - the recipient's [`GuardianPublicKey`]
    pub fn encrypt(
        csprng: &mut Csprng,
        election_parameters: &ElectionParameters,
        dealer_private_key: &GuardianSecretKey,
        recipient_public_key: &GuardianPublicKey,
    ) -> ShareEncryptionResult {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let field = &fixed_parameters.field;

        let l = recipient_public_key.i.get_one_based_u32();

        //Generate key share as P(l) (cf. Equations 9 and 18) using Horner's method
        let x = FieldElement::from(l, field);
        let mut p_l = ScalarField::zero();
        for coeff in dealer_private_key.secret_coefficients.0.iter().rev() {
            p_l = p_l.mul(&x, field).add(&coeff.0, field);
        }

        //Generate a fresh nonce
        let nonce = field.random_field_elem(csprng);
        // Encrypt the share
        let ciphertext = Self::new(
            fixed_parameters,
            &dealer_private_key.i,
            &nonce,
            &p_l,
            recipient_public_key,
        );
        let secret = GuardianEncryptionSecret {
            dealer: dealer_private_key.i,
            recipient: recipient_public_key.i,
            share: p_l,
            nonce,
        };

        ShareEncryptionResult { ciphertext, secret }
    }

    /// This function decrypts and validates a [`GuardianEncryptedShare`].
    ///
    /// The arguments are
    /// - `self` - the encrypted share
    /// - `election_parameters` - the election parameters
    /// - `dealer_public_key` - the dealer's [`GuardianPublicKey`]
    /// - `recipient_secret_key` - the recipient's [`GuardianSecretKey`]
    pub fn decrypt_and_validate(
        &self,
        election_parameters: &ElectionParameters,
        dealer_public_key: &GuardianPublicKey,
        recipient_secret_key: &GuardianSecretKey,
    ) -> Result<FieldElement, DecryptionError> {
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

        let fixed_parameters = &election_parameters.fixed_parameters;
        let field = &fixed_parameters.field;
        let group = &fixed_parameters.group;

        let i = self.dealer.get_one_based_u32();
        let l = self.recipient.get_one_based_u32();

        let capital_k = &recipient_secret_key.coefficient_commitments.0[0].0;
        let alpha = &self.c0;
        let beta = alpha.exp(recipient_secret_key.secret_s(), group);
        let k_i_l = Self::secret_key(fixed_parameters, i, l, capital_k, alpha, &beta);

        let (k0, k1) = Self::mac_and_encryption_key(i, l, &k_i_l);
        let mac = Self::share_mac(k0, alpha.to_be_bytes_left_pad(group).as_slice(), &self.c1);

        if mac != self.c2 {
            return Err(DecryptionError::InvalidMAC);
        }

        // Decryption as in Equation `20`
        let p_l_bytes = xor(self.c1.0.as_slice(), k1.0.as_slice());
        let p_l = FieldElement::from_bytes_be(p_l_bytes.as_slice(), field);

        // Share validity check
        let g_p_l = group.g_exp(&p_l);
        // RHS of Equation `21`
        let l = FieldElement::from(l, field);
        let vec_k_i_j = &dealer_public_key.coefficient_commitments.0;
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
    }

    /// This function validates a [`GuardianEncryptedShare`] with respect to given [`GuardianEncryptionSecret`] and [`GuardianPublicKey`] of dealer and recipient in case of a dispute.
    ///
    /// The arguments are
    /// - `self` - the encrypted share
    /// - `election_parameters` - the election parameters
    /// - `dealer_public_key` - the dealer's [`GuardianPublicKey`]
    /// - `recipient_public_key` - the recipient's [`GuardianPublicKey`]
    /// - `secret` - the published [`GuardianEncryptionSecret`]
    ///
    /// This function returns false if the dealer's published secrets do not match the published ciphertext, or Equation `21`.
    /// If they match, the function returns true, meaning the recipient's claim about the wrongdoing by the dealer is dismissed.
    pub fn public_validation(
        &self,
        election_parameters: &ElectionParameters,
        dealer_public_key: &GuardianPublicKey,
        recipient_public_key: &GuardianPublicKey,
        secret: &GuardianEncryptionSecret,
    ) -> bool {
        if self.recipient != secret.recipient || self.dealer != secret.dealer {
            return false;
        }

        let fixed_parameters = &election_parameters.fixed_parameters;
        let field = &fixed_parameters.field;
        let group = &fixed_parameters.group;

        // Check that the ciphertext was computed correctly
        let expected_ciphertext = Self::new(
            fixed_parameters,
            &dealer_public_key.i,
            &secret.nonce,
            &secret.share,
            recipient_public_key,
        );
        if *self != expected_ciphertext {
            return false;
        }

        let l = self.recipient.get_one_based_u32();

        // Share validity check
        let g_p_l = group.g_exp(&secret.share);
        // RHS of Equation `21`
        let l = &FieldElement::from(l, field);
        let vec_k_i_j = &dealer_public_key.coefficient_commitments.0;
        let rhs = (0u32..)
            .zip(vec_k_i_j)
            .fold(Group::one(), |prod, (j, k_i_j)| {
                let l_pow_j = l.pow(j, field);
                prod.mul(&k_i_j.0.exp(&l_pow_j, group), group)
            });
        if g_p_l != rhs {
            return false;
        }

        true
    }
}

/// Represents errors occurring while combining shares to compute a [`GuardianSecretKeyShare`].
#[derive(Error, Debug)]
pub enum ShareCombinationError {
    /// Occurs if a given public key is invalid.
    #[error("Public key of guardian {0} is invalid.")]
    InvalidPublicKey(GuardianIndex),
    /// Occurs if multiple public keys of the same guardian are given.
    #[error("Guardian {0} is represented more than once in the guardian public keys.")]
    DuplicateGuardian(GuardianIndex),
    /// Occurs if the public key of a guardian is missing.
    #[error("The public key of guardian {0} is missing.")]
    MissingGuardian(String),
    /// Occurs if any share could not be decrypted.
    #[error("Could not decrypt and validate all shares. There are issues with shares from the following guardians: {0}")]
    DecryptionError(String),
}

/// A guardian's share of the joint secret key, it corresponds to `P(i)` in Equation `22`.
///
/// The corresponding public key is never computed explicitly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianSecretKeyShare {
    /// Guardian index, 1 <= i <= [`n`](crate::varying_parameters::VaryingParameters::n).
    pub i: GuardianIndex,
    /// Secret key share
    pub p_i: FieldElement,
}

impl GuardianSecretKeyShare {
    /// This function computes a new [`GuardianSecretKeyShare`] from a list of [`GuardianEncryptedShare`].
    ///
    /// The arguments are
    /// - `pre_voting_data` - the [`PreVotingData`]
    /// - `guardian_public_keys` - a list of [`GuardianPublicKey`]
    /// - `encrypted_shares` - a list of [`GuardianEncryptedShare`]
    /// - `recipient_secret_key` - the recipient's [`GuardianSecretKey`]
    ///
    /// This function assumes that i-th encrypted_share and the i-th guardian_public_key are from the same guardian.
    pub fn compute(
        pre_voting_data: &PreVotingData,
        guardian_public_keys: &[GuardianPublicKey],
        encrypted_shares: &[GuardianEncryptedShare],
        recipient_secret_key: &GuardianSecretKey,
    ) -> Result<Self, ShareCombinationError> {
        let fixed_parameters = &pre_voting_data.parameters.fixed_parameters;
        let varying_parameters = &pre_voting_data.parameters.varying_parameters;

        let n = varying_parameters.n.get_one_based_usize();

        // Validate every supplied guardian public key.
        for guardian_public_key in guardian_public_keys {
            if guardian_public_key
                .validate(&pre_voting_data.parameters)
                .is_err()
            {
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
        let mut issues = vec![];
        for (pk, share) in zip(guardian_public_keys, encrypted_shares) {
            let res =
                share.decrypt_and_validate(&pre_voting_data.parameters, pk, recipient_secret_key);
            match res {
                Err(e) => issues.push((pk.i, e)),
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
            return Err(ShareCombinationError::DecryptionError(info));
        }

        let key = shares.iter().fold(
            FieldElement::from(0_u8, &fixed_parameters.field),
            |acc, share| acc.add(share, &fixed_parameters.field),
        );

        Ok(Self {
            i: recipient_secret_key.i,
            p_i: key,
        })
    }
}

//-------------------------------------------------------------------------------------------------|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::iter::zip;

    use util::{
        algebra::{FieldElement, ScalarField},
        algebra_utils::field_lagrange_at_zero,
        csprng::Csprng,
    };

    use crate::{
        errors::EgResult, example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters, guardian::GuardianIndex,
        guardian_secret_key::GuardianSecretKey, pre_voting_data::PreVotingData,
    };

    use super::{GuardianEncryptedShare, GuardianSecretKeyShare};

    #[test]
    fn test_text_encoding() {
        assert_eq!("share_enc_keys".as_bytes().len(), 14);
        assert_eq!("share_encrypt".as_bytes().len(), 13);
    }

    #[test]
    fn test_encryption_decryption() {
        let mut csprng = Csprng::new(b"test_encryption_decryption");

        let election_parameters = example_election_parameters();
        let index_one = GuardianIndex::from_one_based_index(1).unwrap();
        let index_two = GuardianIndex::from_one_based_index(2).unwrap();
        let sk_one =
            GuardianSecretKey::generate(&mut csprng, &election_parameters, index_one, None);
        let sk_two =
            GuardianSecretKey::generate(&mut csprng, &election_parameters, index_two, None);
        let pk_one = sk_one.make_public_key();
        let pk_two = sk_two.make_public_key();

        let encrypted_result =
            GuardianEncryptedShare::encrypt(&mut csprng, &election_parameters, &sk_one, &pk_two);

        let result = encrypted_result.ciphertext.decrypt_and_validate(
            &election_parameters,
            &pk_one,
            &sk_two,
        );

        assert!(result.is_ok(), "The decrypted share should be valid");
    }

    #[test]
    fn test_key_sharing() -> EgResult<()> {
        let mut csprng = Csprng::new(b"test_key_sharing");

        let election_parameters = example_election_parameters();

        let guardian_secret_keys = election_parameters
            .varying_parameters
            .each_guardian_i()
            .map(|i| GuardianSecretKey::generate(&mut csprng, &election_parameters, i, None))
            .collect::<Vec<_>>();

        let guardian_public_keys = guardian_secret_keys
            .iter()
            .map(|secret_key| secret_key.make_public_key())
            .collect::<Vec<_>>();

        let pre_voting_data = PreVotingData::try_from_parameters_manifest_gpks(
            election_parameters,
            example_election_manifest(),
            &guardian_public_keys,
        )?;
        let election_parameters = &pre_voting_data.parameters;
        let fixed_parameters = &election_parameters.fixed_parameters;

        // Compute secret key shares
        let share_vecs = guardian_public_keys
            .iter()
            .map(|pk| {
                guardian_secret_keys
                    .iter()
                    .map(|dealer_sk| {
                        GuardianEncryptedShare::encrypt(
                            &mut csprng,
                            election_parameters,
                            dealer_sk,
                            pk,
                        )
                        .ciphertext
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let key_shares = zip(&guardian_secret_keys, share_vecs)
            .map(|(sk, shares)| {
                GuardianSecretKeyShare::compute(
                    &pre_voting_data,
                    &guardian_public_keys,
                    &shares,
                    sk,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        // Compute joint secret key from secret keys
        let joint_key_1 = guardian_secret_keys
            .iter()
            .fold(ScalarField::zero(), |acc, share| {
                acc.add(share.secret_s(), &fixed_parameters.field)
            });

        // Compute joint secret key from shares
        let xs = guardian_public_keys
            .iter()
            .map(|pk| FieldElement::from(pk.i.get_one_based_u32(), &fixed_parameters.field))
            .collect::<Vec<_>>();
        let ys = key_shares.iter().map(|s| s.p_i.clone()).collect::<Vec<_>>();
        let joint_key_2 = field_lagrange_at_zero(&xs, &ys, &fixed_parameters.field);

        assert_eq!(Some(joint_key_1), joint_key_2, "Joint keys should match.");
        Ok(())
    }

    #[test]
    fn test_public_validation() {
        let mut csprng = Csprng::new(b"test_public_validation");

        let election_parameters = example_election_parameters();

        let index_one = GuardianIndex::from_one_based_index(1).unwrap();
        let index_two = GuardianIndex::from_one_based_index(2).unwrap();
        let sk_one =
            GuardianSecretKey::generate(&mut csprng, &election_parameters, index_one, None);
        let sk_two =
            GuardianSecretKey::generate(&mut csprng, &election_parameters, index_two, None);
        let pk_one = sk_one.make_public_key();
        let pk_two = sk_two.make_public_key();

        let enc_res_1 =
            GuardianEncryptedShare::encrypt(&mut csprng, &election_parameters, &sk_one, &pk_two);

        let enc_res_2 =
            GuardianEncryptedShare::encrypt(&mut csprng, &election_parameters, &sk_one, &pk_one);
        let enc_res_3 =
            GuardianEncryptedShare::encrypt(&mut csprng, &election_parameters, &sk_two, &pk_one);

        assert!(
            enc_res_1.ciphertext.public_validation(
                &election_parameters,
                &pk_one,
                &pk_two,
                &enc_res_1.secret
            ),
            "The ciphertext should be valid"
        );
        assert!(
            !enc_res_2.ciphertext.public_validation(
                &election_parameters,
                &pk_one,
                &pk_two,
                &enc_res_1.secret
            ),
            "The ciphertext should not be valid"
        );
        assert!(
            !enc_res_3.ciphertext.public_validation(
                &election_parameters,
                &pk_one,
                &pk_two,
                &enc_res_1.secret
            ),
            "The ciphertext should not be valid"
        );
    }
}
