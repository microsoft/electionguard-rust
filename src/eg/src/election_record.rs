use crate::{
    ballot::BallotEncrypted, election_manifest::ElectionManifest,
    election_parameters::ElectionParameters, hashes::Hashes, key::PublicKey, nizk::ProofGuardian,
};

struct ElectionRecord {
    /// The election manifest
    manifest: ElectionManifest,

    /// Baseline election and cryptographic parameters
    parameters: ElectionParameters,

    /// Hashes H_B, H_P, and H_E
    hashes: Hashes,

    /// Commitments from each election guardian to each of their polynomial coefficients and
    /// proofs from each guardian of possession of each of the associated coefficients
    guardian_proofs: Vec<ProofGuardian>,

    /// The election public key
    election_public_key: PublicKey,

    /// Every encrypted ballot prepared in the election (whether cast or challenged)
    all_ballots: Vec<BallotEncrypted>,

    challenged_ballots: Vec<BallotEncrypted>,
}
