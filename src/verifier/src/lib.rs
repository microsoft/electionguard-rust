use eg::{
    hash::{eg_h, eg_h_js, HValue},
    nonce::encrypted,
    voter::VoterChallengeCode,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::console_log;

pub mod verifier;

///
/// Roadmap
/// --------
/// [ ] Export the following functionality to JavaScript:
///     [*] Computation of Hashes (H_P, H_M, H_B, H_E)
///             Requires guardian commitments
///             Requires preliminary election record
///     [*] Computation of Selection Nonce  
///
///
///  

/* Types */

#[derive(Serialize)]
pub struct Hashes {
    pub h_p: String,
    pub h_m: String,
    pub h_b: String,
    pub h_e: String,
}

/* Hashes */

#[wasm_bindgen]
pub fn eg_hash_compute(
    p: &[u8],
    q: &[u8],
    g: &[u8],
    manifest: &[u8],
    date: &[u8],
    info: &[u8],
    capital_k_i: &[u8],
) -> String {
    let h_p = {
        let mut v_pqg = vec![0x00];

        v_pqg.extend_from_slice(p);
        v_pqg.extend_from_slice(q);
        v_pqg.extend_from_slice(g);

        eg_h(&HValue::default(), &v_pqg)
    };

    let h_m = {
        let mut v = vec![0x01];

        v.extend_from_slice(manifest);

        eg_h(&h_p, &v)
    };

    let h_b = {
        let mut v = vec![0x02];

        v.extend_from_slice(date);
        v.extend_from_slice(info);

        v.extend(h_m.as_ref().iter());

        eg_h(&h_p, &v)
    };

    let h_e = {
        let mut v = vec![0x12];

        v.extend_from_slice(capital_k_i);

        console_log!("v: {:?}", v.len());

        eg_h(&h_b, &v)
    };

    serde_json::to_string(&Hashes {
        h_p: h_p.to_string(),
        h_m: h_m.to_string(),
        h_b: h_b.to_string(),
        h_e: h_e.to_string(),
    })
    .unwrap()
}

/* Voter Selection */

/// vs_str should be a base64 encoded string
#[wasm_bindgen]
pub fn eg_voter_selection_decode(num_options: &[usize], vs_str: &str) -> String {
    let vs = VoterChallengeCode::decode_selections(num_options, vs_str);
    serde_json::to_string(&vs).unwrap()
}

/* Nonce */

#[wasm_bindgen]
pub fn eg_nonce_selection(h_e: &[u8], pn: &[u8], label_i: &[u8], label_j: &[u8]) -> String {
    let mut v = vec![0x20];

    v.extend_from_slice(pn);
    v.extend_from_slice(label_i);
    v.extend_from_slice(label_j);

    eg_h_js(&h_e, &v)
}
