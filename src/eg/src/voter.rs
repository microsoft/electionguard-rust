use std::{fs, path::Path};

use base64::{engine::general_purpose, Engine as _};
use num_bigint::BigUint;
use qrcode::{render::svg, QrCode};
use serde::Serialize;
use util::integer_util::round_to_next_multiple;

use crate::{ballot::BallotConfig, contest_selection::ContestSelection};

#[derive(Debug, Serialize)]
pub struct VoterVerificationCode {
    /// Base 64 encoded ballot nonce
    pub pn: String,

    // Base 64 encoded ballot confirmation code
    pub cc: String,

    // Base 64 encoded voter selection vector (bitwise, 1 = selected, 0 = not selected)
    pub vs: String,
}

impl VoterVerificationCode {
    fn encode_selections(config: &BallotConfig, vs: &Vec<ContestSelection>) -> String {
        let mut ballot_vote = Vec::new();
        for (i, contest_vote) in vs.iter().enumerate() {
            let mut encoded_contest_vote =
                vec![0u8; round_to_next_multiple(config.manifest.contests[i].options.len(), 8)];
            for &v in contest_vote.vote.iter() {
                encoded_contest_vote[v as usize / 8] |= 1 << (v % 8);
            }
            ballot_vote.extend(encoded_contest_vote);
        }
        general_purpose::URL_SAFE_NO_PAD.encode(&ballot_vote.as_slice())
    }

    pub fn new_as_file(
        config: &BallotConfig,
        dir_path: &Path,
        pn: &[u8],
        cc: &[u8],
        vs: &Vec<ContestSelection>,
    ) {
        let code_data = Self {
            pn: general_purpose::URL_SAFE_NO_PAD.encode(pn),
            cc: general_purpose::URL_SAFE_NO_PAD.encode(cc),
            vs: Self::encode_selections(config, vs),
        };
        let code = QrCode::new(serde_json::to_string(&code_data).unwrap().as_bytes()).unwrap();
        let image = code
            .render()
            .min_dimensions(300, 300)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();
        fs::write(dir_path.join(format!("{}.svg", code_data.pn)), image).unwrap();
    }
}
