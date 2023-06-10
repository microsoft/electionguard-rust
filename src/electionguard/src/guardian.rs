use std::path::PathBuf;

use crate::{Clargs, Subcommand};
use anyhow::{bail, Result};
use clap::Args;
use eg::{
    example_election_manifest::example_election_manifest_small,
    example_election_parameters::example_election_parameters,
    guardian::{export, import, verify_share_from},
    hashes::Hashes,
};
use util::{csprng::Csprng, prime::BigUintPrime};

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
        use eg::standard_parameters::STANDARD_PARAMETERS;
        let fixed_parameters = &*STANDARD_PARAMETERS;

        if self.example_manifest && self.manifest.is_some() {
            bail!("Specify either --example-manifest or --manifest, but not both.");
        }

        if self.example_manifest {
            println!("Using sample manifest.");
            let election_parameters = example_election_parameters();
            let election_manifest = example_election_manifest_small();
            let hashes = Hashes::new(&election_parameters, &election_manifest);

            assert!(self.i != 0 && self.i as u16 <= election_parameters.varying_parameters.n);

            if self.share_verify {
                assert!(
                    self.l != self.i
                        && self.l != 0
                        && self.l as u16 <= election_parameters.varying_parameters.n
                );
                match self.data {
                    Some(ref path) => {
                        let path = path.join(format!("{}", self.i));
                        // Verify generated shares
                        let (_, proof, share) = import(&path, self.l as usize);

                        // Verify secret key share
                        match verify_share_from(
                            &election_parameters.fixed_parameters,
                            self.l as usize,
                            &share,
                            &proof.capital_k,
                        ) {
                            true => println!("Share verified."),
                            false => println!("Share not verified."),
                        };

                        // Verify proof of knowledge
                        match proof.verify(
                            &election_parameters.fixed_parameters,
                            hashes.h_p,
                            self.i as u16,
                            election_parameters.varying_parameters.k,
                        ) {
                            true => println!("Proof verified."),
                            false => println!("Proof not verified."),
                        }
                    }
                    None => println!("Could not find data directory."),
                };
            } else {
                // Generate new keys
                let guardian = Guardian::new(&mut csprng, &election_parameters);
                let public_key = guardian.public_key();
                let proof = guardian.proof_of_knowledge(
                    &mut csprng,
                    &election_parameters,
                    hashes.h_p,
                    self.i as u16,
                );
                let shares = (1..election_parameters.varying_parameters.n + 1)
                    .map(|l| {
                        if l != self.i as u16 {
                            guardian.share_for(l as usize)
                        } else {
                            String::from("0")
                        }
                    })
                    .collect::<Vec<String>>();

                match self.data {
                    Some(ref path) => {
                        let path = path.join(format!("{}", self.i));
                        export(&path, &public_key, &proof, &shares);
                    }
                    None => {
                        println!("Public key: {:?}", public_key);
                        println!("Proof: {:?}", proof);
                        println!("Shares: {:?}", shares);
                    }
                }
            }
        }

        Ok(())
    }
}
