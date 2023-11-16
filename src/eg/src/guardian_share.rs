use std::borrow::Borrow;

use anyhow::{ensure, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use util::{bitwise::xor, csprng::Csprng, integer_util::to_be_bytes_left_pad};

use crate::{
    election_parameters::ElectionParameters,
    guardian::GuardianIndex,
    guardian_public_key::GuardianPublicKey,
    guardian_secret_key::GuardianSecretKey,
    hash::{eg_h, HValue},
};

/// Encrypted guardian share
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianEncryptedShare {
    pub dealer: GuardianIndex,
    pub recipient: GuardianIndex,
    pub c0: BigUint,
    pub c1: BigUint,
    pub c2: HValue,
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

    /// SHA-256 HMAC this is (currently) the same as eg_h
    fn hmac(key: &HValue, data: &dyn AsRef<[u8]>) -> HValue {
        eg_h(key, data)
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
        v.extend(vec![0x00]);
        v.extend(context.clone());
        v.extend(vec![0x02, 0x00]);
        //SHA-256 HMAC which is equivalent to H(key,value)
        let k1 = Self::hmac(k_i_l, &v);

        // encryption key
        // v = 0x02 | label | 0x00 | context | 0x0200
        let mut v = vec![0x02];
        v.extend_from_slice(label);
        v.extend(vec![0x00]);
        v.extend(context.clone());
        v.extend(vec![0x02, 0x00]);
        //SHA-256 HMAC which is equivalent to H(key,value)
        let k2 = Self::hmac(k_i_l, &v);

        (k1, k2)
    }

    fn share_mac(k0: HValue, c0: &[u8], c1: &[u8]) -> HValue {
        let mut v = c0.to_vec();
        v.extend_from_slice(c1);
        Self::hmac(&k0, &v)
    }

    pub fn new(
        csprng: &mut Csprng,
        election_parameters: &ElectionParameters,
        h_p: HValue,
        dealer_private_key: &GuardianSecretKey,
        recipient_public_key: &GuardianPublicKey,
    ) -> Self {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let i = dealer_private_key.i.get_one_based_u32();
        let l = recipient_public_key.i.get_one_based_u32();
        let q: &BigUint = fixed_parameters.q.borrow();
        let p: &BigUint = fixed_parameters.p.borrow();
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
        let c2 = Self::share_mac(k0, to_be_bytes_left_pad(&alpha, 512).as_slice(), &c1);

        GuardianEncryptedShare {
            dealer: dealer_private_key.i,
            recipient: recipient_public_key.i,
            c0: alpha,
            c1: BigUint::from_bytes_be(c1.as_slice()),
            c2,
        }
    }

    pub fn decrypt_and_validate(
        &self,
        election_parameters: &ElectionParameters,
        h_p: HValue,
        recipient_secret_key: &GuardianSecretKey,
        dealer_public_key: &GuardianPublicKey,
    ) -> Result<BigUint> {
        ensure!(
            self.dealer == dealer_public_key.i,
            "The indices for the dealer must match."
        );
        ensure!(
            self.recipient == recipient_secret_key.i,
            "The indices for the dealer must match."
        );

        let i = self.dealer.get_one_based_u32();
        let l = self.recipient.get_one_based_u32();
        let fixed_parameters = &election_parameters.fixed_parameters;
        let p: &BigUint = fixed_parameters.p.borrow();
        let capital_k = &recipient_secret_key.coefficient_commitments.0[0].0;

        let alpha = &self.c0;
        let beta = alpha.modpow(recipient_secret_key.secret_s(), p);
        let k_i_l = Self::secret_key(h_p, i, l, capital_k, alpha, &beta);

        let (k0, k1) = Self::mac_and_encryption_key(i, l, &k_i_l);
        let mac = Self::share_mac(
            k0,
            to_be_bytes_left_pad(alpha, 512).as_slice(),
            to_be_bytes_left_pad(&self.c1, 32).as_slice(),
        );

        ensure!(mac == self.c2, "The MAC does not verify.");

        let p_l_bytes = xor(
            to_be_bytes_left_pad(&self.c1, 32).as_slice(),
            k1.0.as_slice(),
        );

        Ok(BigUint::from_bytes_be(p_l_bytes.as_slice()))
    }
}

/// A guardian's share of the master secret key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianSecretKeyShare {
    i: GuardianIndex,
    p_i: BigUint,
}

#[cfg(test)]
mod test {
    use util::csprng::Csprng;

    use crate::{
        example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters, guardian::GuardianIndex,
        guardian_secret_key::GuardianSecretKey, hashes::Hashes,
    };

    use super::GuardianEncryptedShare;

    #[test]
    fn test_text_encoding() {
        assert_eq!("share_enc_keys".as_bytes().len(), 14);
        assert_eq!("share_encrypt".as_bytes().len(), 13);
    }

    #[test]
    fn test_encryption_decryption() {
        let mut csprng = Csprng::new(b"test_proof_generation");

        let election_parameters = example_election_parameters();
        let election_manifest = example_election_manifest();

        let hashes = Hashes::compute(&election_parameters, &election_manifest).unwrap();

        let index_one = GuardianIndex::from_one_based_index(1).unwrap();
        let index_two = GuardianIndex::from_one_based_index(2).unwrap();
        let sk_one =
            GuardianSecretKey::generate(&mut csprng, &election_parameters, index_one, None);
        let sk_two =
            GuardianSecretKey::generate(&mut csprng, &election_parameters, index_two, None);
        let pk_one = sk_one.make_public_key();
        let pk_two = sk_two.make_public_key();

        let encrypted_share = GuardianEncryptedShare::new(
            &mut csprng,
            &election_parameters,
            hashes.h_p,
            &sk_one,
            &pk_two,
        );

        let result = encrypted_share.decrypt_and_validate(
            &election_parameters,
            hashes.h_p,
            &sk_two,
            &pk_one,
        );

        assert!(result.is_ok(), "The decrypted share should be valid");
    }
}
