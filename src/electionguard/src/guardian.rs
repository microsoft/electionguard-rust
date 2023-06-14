use std::{collections::HashMap, path::PathBuf};

use crate::{Clargs, Subcommand};
use anyhow::{bail, Result};
use clap::Args;
use eg::{
    example_election_manifest::example_election_manifest_small,
    example_election_parameters::example_election_parameters,
    guardian::{export, import, verify_share_from, GuardianShare},
    hash,
    hashes::Hashes,
    key::PublicKey,
    nizk::ProofGuardian,
};
use util::{
    csprng::Csprng,
    file::{create_path, read_path, write_path},
    logging::Logging,
};

#[derive(Args, Debug)]
pub(crate) struct Guardian {
    /// Sequence order
    #[arg(long)]
    i: i32,

    /// File from which to read the election manifest.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Use the example election manifest.
    #[arg(long)]
    example_manifest: bool,

    /// Path to election data store
    #[arg(long)]
    data: Option<PathBuf>,

    /// Whether to verify shares
    #[arg(long)]
    share_verify: bool,

    /// Whether to generate shares
    #[arg(long)]
    share_generate: bool,

    /// Sequence order (for guardian verification)
    #[arg(long, default_value_t = 0)]
    l: i32,
}

impl Subcommand for Guardian {
    fn need_csprng(&self) -> bool {
        true
    }

    fn do_it(&self, _clargs: &Clargs) -> Result<()> {
        bail!("need csprng version instead");
    }

    fn do_it_with_csprng(&self, _clargs: &Clargs, mut csprng: Csprng) -> Result<()> {
        use eg::guardian::Guardian;

        if self.example_manifest && self.manifest.is_some() {
            bail!("Specify either --example-manifest or --manifest, but not both.");
        }

        if self.share_verify && self.share_generate {
            bail!("Specify either --share-verify or --share-generate, but not both.");
        }

        if self.example_manifest {
            let election_parameters = example_election_parameters();
            let election_manifest = example_election_manifest_small();
            let hashes = Hashes::new(&election_parameters, &election_manifest);

            assert!(self.i != 0 && self.i as u16 <= election_parameters.varying_parameters.n);

            match &self.data {
                Some(path) => {
                    if self.share_generate {
                        // Read guardian private data
                        let guardian = Guardian::from_json(
                            &String::from_utf8(read_path(
                                &path.join(format!("{}/private.json", self.i)),
                            ))
                            .unwrap(),
                        );
                        assert!(guardian.i == self.i as usize);

                        let mut public_keys = <HashMap<u16, PublicKey>>::new();
                        let mut proofs = <HashMap<u16, ProofGuardian>>::new();

                        // Read public keys associated with other guardians
                        for l in 1..election_parameters.varying_parameters.n + 1 {
                            if guardian.i != l as usize {
                                public_keys.insert(
                                    l,
                                    PublicKey::from_json(
                                        &String::from_utf8(read_path(
                                            &path.join(format!("{}/public/key.json", l)),
                                        ))
                                        .unwrap(),
                                    ),
                                );
                                proofs.insert(
                                    l,
                                    ProofGuardian::from_json(
                                        &String::from_utf8(read_path(
                                            &path.join(format!("{}/public/proof.json", l)),
                                        ))
                                        .unwrap(),
                                    ),
                                );
                            }
                        }

                        // Generate encrypted share for each other guardian
                        for l in 1..election_parameters.varying_parameters.n + 1 {
                            if guardian.i != l as usize {
                                let share = guardian.share_for(
                                    &mut csprng,
                                    &election_parameters,
                                    &hashes.h_p,
                                    l as usize,
                                    &public_keys[&l],
                                );
                                write_path(
                                    &path.join(format!("{}/public/share-{}.json", self.i, l)),
                                    share.to_json().as_bytes(),
                                );
                            }
                        }
                        Logging::log(
                            "Guardian",
                            &format!(
                                "Wrote encrypted shares to {:?}",
                                path.join(format!("{}/public", self.i))
                            ),
                            line!(),
                            file!(),
                        );
                    } else if self.share_verify {
                        assert!(
                            self.l != self.i
                                && self.l != 0
                                && self.l as u16 <= election_parameters.varying_parameters.n
                        );

                        // Read guardian private data
                        let guardian = Guardian::from_json(
                            &String::from_utf8(read_path(
                                &path.join(format!("{}/private.json", self.i)),
                            ))
                            .unwrap(),
                        );
                        assert!(guardian.i == self.i as usize);

                        // Read encrypted share and proof
                        let encrypted_share = GuardianShare::from_json(
                            &String::from_utf8(read_path(
                                &path.join(format!("{}/public/share-{}.json", self.l, guardian.i)),
                            ))
                            .unwrap(),
                        );
                        let proof = ProofGuardian::from_json(
                            &String::from_utf8(read_path(
                                &path.join(format!("{}/public/proof.json", self.l)),
                            ))
                            .unwrap(),
                        );

                        // Decrypt share
                        let p_i_l = guardian.decrypt_share(
                            &election_parameters,
                            &hashes.h_p,
                            self.l as usize,
                            &encrypted_share,
                        );

                        let mut success = true;

                        // Verify proof of knowledge
                        match proof.verify(
                            &election_parameters.fixed_parameters,
                            hashes.h_p,
                            self.l as u16,
                            election_parameters.varying_parameters.k,
                        ) {
                            true => {}
                            false => {
                                Logging::log("Guardian", "Proof not verified.", line!(), file!());
                                success = false;
                            }
                        };

                        if success {
                            Logging::log(
                                "Guardian",
                                &format!("Verified proof of knowledge by {} as {}", self.l, self.i),
                                line!(),
                                file!(),
                            );
                        }

                        success = true;

                        // Verify secret key share
                        match verify_share_from(
                            &election_parameters.fixed_parameters,
                            self.i as usize,
                            &p_i_l,
                            &proof.capital_k,
                        ) {
                            true => {}
                            false => {
                                Logging::log("Guardian", "Share not verified.", line!(), file!());
                                success = false;
                            }
                        };

                        if success {
                            Logging::log(
                                "Guardian",
                                &format!("Verified secret share by {} as {}", self.l, self.i),
                                line!(),
                                file!(),
                            );
                        }
                    } else {
                        // Generate new keys and proof
                        let guardian =
                            Guardian::new(&mut csprng, &election_parameters, self.i as usize);
                        let public_key = guardian.public_key();
                        let proof = guardian.proof_of_knowledge(
                            &mut csprng,
                            &election_parameters,
                            hashes.h_p,
                            self.i as u16,
                        );

                        create_path(&path.join(format!("{}", self.i)));
                        write_path(
                            &path.join(format!("{}/private.json", self.i)),
                            guardian.to_json().as_bytes(),
                        );
                        create_path(&path.join(format!("{}/public", self.i)));
                        write_path(
                            &path.join(format!("{}/public/key.json", self.i)),
                            public_key.to_json().as_bytes(),
                        );
                        write_path(
                            &path.join(format!("{}/public/proof.json", self.i)),
                            proof.to_json().as_bytes(),
                        );

                        Logging::log(
                            "Guardian",
                            &format!("Wrote to {:?}", path.join(format!("{}", self.i))),
                            line!(),
                            file!(),
                        );
                    }
                }
                None => Logging::log(
                    "Guardian",
                    "Could not find data directory.",
                    line!(),
                    file!(),
                ),
            }
        }

        Ok(())
    }
}
