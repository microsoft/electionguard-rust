use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct VoterVerificationCode {
    pub pn: String,
    pub cc: String,
}
