use std::{fs, path::Path};

use base64::{engine::general_purpose, Engine as _};
use qrcode::{render::svg, QrCode};
use serde::Serialize;
use util::integer_util::round_to_next_multiple;

use crate::contest_selection::ContestSelection;

#[derive(Debug, Serialize)]
pub struct VoterChallengeCode {
    /// Base 64 encoded ballot nonce
    pub pn: String,

    // Base 64 encoded voter selection vector (bitwise, 1 = selected, 0 = not selected)
    pub vs: String,
}

#[derive(Debug, Serialize)]
pub struct VoterConfirmationCode {
    // Base 64 encoded ballot confirmation code
    pub cc: String,
}

pub fn generate_qr(data: &[u8]) -> QrCode {
    match QrCode::new(data) {
        Ok(qr) => qr,
        Err(e) => panic!("Error generating QR code: {}", e),
    }
}

impl VoterChallengeCode {
    fn encode_selections(vs: &Vec<ContestSelection>) -> String {
        let mut ballot_vote = Vec::new();
        for (i, contest_selection) in vs.iter().enumerate() {
            let mut contest_vote =
                vec![0u8; round_to_next_multiple(contest_selection.vote.len(), 8) / 8];
            for (j, v) in contest_selection.vote.iter().enumerate() {
                if *v != 0u8 {
                    contest_vote[j / 8] |= 1 << (j % 8);
                }
            }
            ballot_vote.extend(contest_vote);
        }
        general_purpose::URL_SAFE_NO_PAD.encode(&ballot_vote.as_slice())
    }

    pub fn decode_selections(num_options: &[usize], vs: &str) -> Vec<ContestSelection> {
        let vs_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(vs.as_bytes())
            .unwrap();
        let mut ret = Vec::new();
        let mut start = 0;
        for (i, num_opt) in num_options.iter().enumerate() {
            ret.push(ContestSelection {
                vote: vec![0u8; *num_opt],
            });
            for j in 0..ret[i].vote.len() {
                ret[i].vote[j] = (vs_bytes[start + j / 8] >> (j % 8)) & 1;
            }
            start += round_to_next_multiple(*num_opt, 8) / 8;
        }
        ret
    }

    pub fn new_as_file(dir_path: &Path, pn: &[u8], cc: &[u8], vs: &Vec<ContestSelection>) {
        let code_data = Self {
            pn: general_purpose::URL_SAFE_NO_PAD.encode(pn),
            vs: Self::encode_selections(vs),
        };
        let code = QrCode::new(serde_json::to_string(&code_data).unwrap().as_bytes()).unwrap();
        let image = code
            .render()
            .min_dimensions(300, 300)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();
        fs::write(
            dir_path.join(format!(
                "CC-{}-verification.svg",
                general_purpose::URL_SAFE_NO_PAD.encode(cc)
            )),
            image,
        )
        .unwrap();
    }
}

impl VoterConfirmationCode {
    pub fn to_string(&self) -> Option<String> {
        match serde_json::to_string(self) {
            Ok(s) => Some(s),
            Err(_) => None,
        }
    }

    pub fn new_as_file(dir_path: &Path, cc: &[u8]) -> bool {
        let code_data = Self {
            cc: general_purpose::URL_SAFE_NO_PAD.encode(cc),
        };
        let code: QrCode;
        match code_data.to_string() {
            Some(c) => code = generate_qr(c.as_bytes()),
            None => return false,
        }
        let image = code
            .render()
            .min_dimensions(300, 300)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();
        match fs::write(dir_path.join(format!("CC-{}.svg", code_data.cc)), image) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encoding_decoding() {
        let vs = vec![
            ContestSelection {
                vote: vec![0, 0, 1, 0, 0, 0, 0, 0, 0],
            },
            ContestSelection {
                vote: vec![0, 0, 0, 0, 0, 1, 0],
            },
            ContestSelection {
                vote: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            },
        ];

        let encoded = VoterChallengeCode::encode_selections(&vs);
        let decoded = VoterChallengeCode::decode_selections(&[9, 7, 12], &encoded);

        assert!(vs.len() == decoded.len());

        for i in 0..vs.len() {
            assert!(vs[i].vote == decoded[i].vote);
        }
    }
}
