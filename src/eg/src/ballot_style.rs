use serde::{Deserialize, Serialize};

/// A ballot style.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BallotStyle {
    /// The label.
    pub label: String,

    /// The contests in this ballot style.
    pub contests: Vec<u16>,
}

impl BallotStyle {
    pub fn empty() -> Self {
        Self {
            label: "".to_string(),
            contests: Vec::new(),
        }
    }
}
