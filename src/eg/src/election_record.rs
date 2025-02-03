// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::collections::BTreeMap;

use serde::Serialize;
use util::vec1::Vec1;

use crate::{
    ballot::Ballot, ciphertext::Ciphertext, eg::Eg, election_manifest::ContestIndex,
    guardian_public_key::GuardianPublicKey, pre_voting_data::PreVotingData,
    serializable::SerializableCanonical, verifiable_decryption::VerifiableDecryption,
};

/// The election record, generated after the tally.
#[derive(Debug, Serialize)] // Deserialize
pub struct ElectionRecord {
    /// Pre-voting data including election parameters, election_manifest, hashes, etc.
    pub pre_voting_data: PreVotingData,

    // TODO "Information sufficient to uniquely identify and describe the election,
    // such as date, location, election type, etc (not otherwise included in the election manifest)."
    /// Guardian public keys including commitments and proofs of knowledge.
    pub guardian_public_keys: Vec1<GuardianPublicKey>,

    /// Every ballot in the election (whether cast, spoiled, or challenged).
    pub ballots: Vec<Ballot>,

    // TODO Every weighted ballot in the election (whether cast, spoiled, or challenged)
    // and its weight used in the tally.
    //pub weighted_ballots: Vec<(Ballot, FieldElement)>,

    // TODO The commitments from each election guardian to each of their polynomial coefficients.
    // TODO The proofs from each guardian of possession of each of the associated coefficients.

    // TODO The public key κi from each election guardian together with
    // the proof of knowledge of the corresponding secret key

    // TODO Every encrypted ballot prepared in the election (whether cast or challenged):
    // – The selection encryption identifier `id_B`
    // – the selection encryption identifier hash `H_I`
    // – all of the encrypted selections
    // – the proofs that each such value is an encryption of either zero or one (or more generally, the proofs that these values satisfy the respective option selection limits)
    // – the selection limit for each contest
    // – the proof that the number of selections made does not exceed the selection limit
    // – the ballot weight if given—if no weight is given, the weight is assumed to be 1
    // – the ballot style
    // – the device information for the device that encrypted the ballot
    // – the date and time of the ballot encryption
    // – the confirmation code produced for the ballot
    // – the status of the ballot (cast or challenged)

    // The decryption of each challenged ballot:
    // – The selections made on the ballot,
    // – the plaintext representation of the selections,
    // – proofs of each decryption or decryption nonces.

    // Tallies of each option in an election:
    // – The encrypted tally of each option,
    /// Encrypted tallies of each contest option.
    pub encrypted_tallies: BTreeMap<ContestIndex, Vec<Ciphertext>>,

    /// Decrypted tallies of each contest option with proofs of correct decryption.
    // TODO full decryptions of each encrypted tally,
    // TODO plaintext representations of each tally,
    // TODO proofs of correct decryption of each tally.
    pub decrypted_tallies: BTreeMap<ContestIndex, Vec<VerifiableDecryption>>,
    // TODO Ordered lists of the ballots encrypted by each device.

    // TODO "encrypted contest data when such data is available"

    // TODO digital signature by election administrators with the date of the signature

    // TODO tools for easy look up of confirmation codes by voters
}

impl SerializableCanonical for ElectionRecord {}
