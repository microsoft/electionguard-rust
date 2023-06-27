use eg::{
    election_record::ElectionRecordHeader,
    hash::{eg_h, HValue},
};

use crate::contest_selection::ContestSelectionPreEncrypted;

/// Contest hash for pre-encrypted ballots (Equation 95)
///
/// ψ_i = H(H_E;40,λ_i,K,α_1,β_1,α_2,β_2 ...,α_m,β_m),
///
pub fn contest_hash(
    header: &ElectionRecordHeader,
    contest_label: &String,
    selections: &Vec<ContestSelectionPreEncrypted>,
) -> HValue {
    let mut v = vec![0x41];

    v.extend_from_slice(contest_label.as_bytes());
    v.extend_from_slice(header.public_key.0.to_bytes_be().as_slice());

    // TODO: Check if this sorting works
    let mut sorted_selection_hashes = selections
        .iter()
        .map(|s| s.selection_hash)
        .collect::<Vec<HValue>>();
    sorted_selection_hashes.sort();

    sorted_selection_hashes.iter().for_each(|s| {
        v.extend(s.as_ref());
    });

    eg_h(&header.hashes_ext.h_e, &v)
}
