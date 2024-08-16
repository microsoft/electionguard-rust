// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    ballot::BallotEncrypted,
    ciphertext::Ciphertext,
    election_manifest::ContestIndex,
    guardian_public_key::GuardianPublicKey,
    pre_voting_data::PreVotingData,
    serializable::{SerializableCanonical, SerializablePretty},
    verifiable_decryption::VerifiableDecryption,
};

/// The election record, generated after the tally.
#[derive(Debug, Serialize, Deserialize)]
pub struct ElectionRecord {
    /// Pre-voting data including election parameters, manifest, hashes, etc.
    pub pre_voting_data: PreVotingData,

    /// Guardian public keys including commitments and proofs of knowledge.
    pub guardian_public_keys: Vec<GuardianPublicKey>,

    /// Every ballot in the election (whether cast, spoiled, or challenged).
    pub ballots: Vec<BallotEncrypted>,

    /// Every weighted ballot in the election (whether cast, spoiled, or challenged)
    /// and its weight used in the tally.
    //pub weighted_ballots: Vec<(BallotEncrypted, FieldElement)>,

    /// Encrypted tallies of each contest option.
    pub encrypted_tallies: BTreeMap<ContestIndex, Vec<Ciphertext>>,

    /// Decrypted tallies of each contest option with proofs of correct decryption.
    pub decrypted_tallies: BTreeMap<ContestIndex, Vec<VerifiableDecryption>>,
}

impl SerializableCanonical for ElectionRecord {}

impl SerializablePretty for ElectionRecord {}
