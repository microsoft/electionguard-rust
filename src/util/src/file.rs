use std::{fs, path::PathBuf};

use crate::logging::Logging;

/// Write bytes to path and handle associated errors
///
pub fn write_path(path: &PathBuf, s: &[u8]) {
    match fs::write(path, s) {
        Ok(_) => {}
        Err(e) => {
            Logging::log(
                "utils::file",
                &format!("Error writing to path: {}", e),
                line!(),
                file!(),
            );
        }
    }
}

/// Read bytes from path and handle associated errors
pub fn read_path(path: &PathBuf) -> Vec<u8> {
    match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            Logging::log(
                "utils::file",
                &format!("Error reading from path: {}", e),
                line!(),
                file!(),
            );
            vec![]
        }
    }
}

/// Create path and handle associated errors
pub fn create_path(path: &PathBuf) {
    match fs::create_dir_all(path) {
        Ok(_) => {}
        Err(e) => {
            Logging::log(
                "utils::file",
                &format!("Error creating path: {}", e),
                line!(),
                file!(),
            );
        }
    }
}

// pub fn export(dir: &PathBuf, public_key: &PublicKey, proof: &ProofGuardian) {
//     let private_dir = dir.join("private");
//     let public_dir = dir.join("public");
//     fs::create_dir_all(private_dir.clone()).unwrap();
//     fs::create_dir_all(public_dir.clone()).unwrap();

//     fs::write(
//         public_dir.join("public_key.json"),
//         serde_json::to_string(public_key).unwrap(),
//     )
//     .unwrap();
//     fs::write(
//         public_dir.join("proof.json"),
//         serde_json::to_string(proof).unwrap(),
//     )
//     .unwrap();
//     // fs::write(
//     //     private_dir.join("shares.json"),
//     //     serde_json::to_string(shares).unwrap(),
//     // )
//     // .unwrap();
// }
