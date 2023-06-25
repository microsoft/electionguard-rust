use std::path::PathBuf;

use crate::{
    artifacts_dir::{ArtifactFile, ArtifactsDir},
    subcommand_helper::SubcommandHelper,
    Subcommand,
};
use anyhow::{bail, Result};
use clap::Args;
use eg::{
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    example_election_manifest::example_election_manifest_small,
    example_election_parameters::example_election_parameters,
    // guardian::{shares_from_json, verify_share_from},
    hashes::Hashes,
    nizk::ProofGuardian,
};
use util::{file::read_path, logging::Logging};

#[derive(Args, Debug)]
pub(crate) struct VerifyGuardianShares {
    /// Sequence order
    #[arg(long)]
    i: i32,

    /// File from which to read the election manifest.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Use the example election manifest.
    #[arg(long)]
    example_manifest: bool,
}

impl Subcommand for VerifyGuardianShares {
    fn uses_csprng(&self) -> bool {
        false
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        // // use eg::guardian::Guardian;

        // if self.example_manifest && self.manifest.is_some() {
        //     bail!("Specify either --example-manifest or --manifest, but not both.");
        // }

        // let election_parameters: ElectionParameters;
        // let election_manifest: ElectionManifest;

        // if self.example_manifest {
        //     election_parameters = example_election_parameters();
        //     election_manifest = example_election_manifest_small();
        // } else {
        //     return Err(anyhow::anyhow!("Not implemented yet"));
        // }

        // let hashes = Hashes::new(&election_parameters, &election_manifest);

        // assert!(self.i != 0 && self.i as u16 <= election_parameters.varying_parameters.n);

        // // Read guardian private data
        // // let our_artifacts = ArtifactsDir::new(
        // //     subcommand_helper
        // //         .artifacts_dir
        // //         .dir_path
        // //         .join(format!("{}", self.i)),
        // // )
        // // .unwrap();
        // let guardian = Guardian::from_json(
        //     &String::from_utf8(read_path(
        //         &subcommand_helper
        //             .artifacts_dir
        //             .path(ArtifactFile::GuardianPrivateData(self.i as u16)),
        //     ))
        //     .unwrap(),
        // );
        // assert!(guardian.i == self.i as usize);

        // for l in 1..election_parameters.varying_parameters.n + 1 {
        //     if guardian.i != l as usize {
        //         let their_artifacts = ArtifactsDir::new(
        //             subcommand_helper
        //                 .artifacts_dir
        //                 .dir_path
        //                 .join(format!("{}", l)),
        //         )
        //         .unwrap();
        //         // Read encrypted share and proof
        //         let encrypted_shares = shares_from_json(
        //             &String::from_utf8(read_path(&their_artifacts.path(
        //                 ArtifactFile::GuardianEncryptedShares(l as u16, guardian.i as u16),
        //             )))
        //             .unwrap(),
        //         );
        //         let proof = ProofGuardian::from_json(
        //             &String::from_utf8(read_path(
        //                 &their_artifacts.path(ArtifactFile::GuardianProof(l as u16)),
        //             ))
        //             .unwrap(),
        //         );

        //         // let mut idx = self.i - 1;
        //         let mut idx = encrypted_shares.len();
        //         for (i, s) in encrypted_shares.iter().enumerate() {
        //             assert!(s.i != l);
        //             if s.i == guardian.i as u16 {
        //                 idx = i as usize;
        //                 break;
        //             }
        //         }

        //         // Decrypt share
        //         let p_i_l = guardian.decrypt_share(
        //             &election_parameters,
        //             &hashes.h_p,
        //             l as usize,
        //             &encrypted_shares[idx as usize],
        //         );

        //         // Verify secret key share
        //         Logging::log(
        //             &format!("Guardian {}", guardian.i),
        //             &format!(
        //                 "  Share from {} (verified): {:?}",
        //                 l,
        //                 verify_share_from(
        //                     &election_parameters.fixed_parameters,
        //                     guardian.i as usize,
        //                     &p_i_l,
        //                     &proof.capital_k,
        //                 )
        //             ),
        //             line!(),
        //             file!(),
        //         );
        //     }
        // }

        Ok(())
    }
}
