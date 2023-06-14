use crate::{
    ballot::BallotEncrypted, election_manifest::ElectionManifest,
    election_parameters::ElectionParameters, hashes::Hashes, key::PublicKey, nizk::ProofGuardian,
};

struct ElectionRecord {
    manifest: ElectionManifest,
    parameters: ElectionParameters,
    hashes: Hashes,
    guardian_proofs: Vec<ProofGuardian>,
    election_public_key: PublicKey,
    all_ballots: Vec<BallotEncrypted>,
    challenged_ballots: Vec<BallotEncrypted>,
}
