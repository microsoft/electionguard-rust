// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

pub struct Logging {}

impl Logging {
    pub fn log(tag: &str, msg: &str, line: u32, file: &str) {
        println!("{}:{} [{}] {}", file, line, tag, msg);
    }
}
