use num_bigint::BigUint;

use crate::{election_parameters::ElectionParameters, hashes::Hashes, nizk::ProofGuardian};

struct Verifier {
    election_parameters: ElectionParameters,
    hashes: Hashes,
}

impl Verifier {
    pub fn new(election_parameters: ElectionParameters, hashes: Hashes) -> Self {
        Verifier {
            election_parameters,
            hashes,
        }
    }

    /// Verification 1: Parameter Validation
    pub fn verification_one(&self) -> bool {
        todo!()
    }

    /// Verification 2: Guardian Public Key Validation
    pub fn verification_two(&self, proofs: &Vec<ProofGuardian>) -> bool {
        for (i, proof) in proofs.iter().enumerate() {
            if !proof.verify(
                &self.election_parameters.fixed_parameters,
                self.hashes.h_p,
                i as u16,
                self.election_parameters.varying_parameters.k,
            ) {
                return false;
            }
        }
        false
    }
}
