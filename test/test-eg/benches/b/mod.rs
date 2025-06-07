// Copyright (C) Microsoft Corporation. All rights reserved.
//     MIT License
//
//    Copyright (c) Microsoft Corporation.
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE


pub mod b1_ballotnonce_generate;
pub mod b2_ballotnonce_derive_ballotcontestoptionfieldnonce;
pub mod b3_encrypt_contestoptionselectionvalue;
pub mod b4_encrypt_ballot;
pub mod b5_make_exptable;
pub mod b6_use_exptable;

#[derive(Debug, Default)]
pub(crate) struct GroupPassInfo {
    opt_warm_up_time_s: Option<u64>,
    opt_target_measurement_time_s: Option<u64>,
    sample_size: usize,
    cnt_passes: usize,
}

#[rustfmt::skip]
pub(crate) fn group_pass_infos() -> Vec<GroupPassInfo> {
    [ //   warmup_s,    meas_s,    samp_sz,     passes   
    //(          None,      None,         20,         16    ),
    //(          Some(1),      Some(1),         10,         1    ),
    //(          Some(2),      Some(5),         20,         1    ),
    (          None,      None,        100,          1    ),
    //(       Some(2),    Some(5),       100,          1    ),
    //(       Some(3),   Some(10),       100,          1    ),
    ].iter()
    .map(|&(opt_warm_up_time_s, opt_target_measurement_time_s, sample_size, cnt_passes)| {
        if sample_size < 10 {
            eprintln!("\nWARN: Sample size of {sample_size} is less than the minimum recommended value of 10");
        }
        GroupPassInfo { opt_warm_up_time_s, opt_target_measurement_time_s, sample_size, cnt_passes }
    }).collect()
}

#[rustfmt::skip]
pub(crate) fn groups_passes() -> impl Iterator<Item = (u64, u64, usize)> {
    vec![
        (3_u64, 10_u64, 1),
    ].into_iter()
}
