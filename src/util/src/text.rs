// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]

use std::borrow::Cow;

//=================================================================================================|

/// Truncates text to the specified length, as necessary.
///
/// Any truncated text is replaced by `"[...]"`.
///
/// - `s` - The text to be truncated.
/// - `max_chars` - The maximum length of the resulting text.
pub fn truncate_text(s: Cow<'_, str>, max_chars: usize) -> Cow<'_, str> {
    static CHARS: &str = "[...]";
    static CHARS_QTY: usize = 5;

    let max_chars = max_chars.max(CHARS_QTY);

    let s_len = s.chars().take(max_chars.saturating_add(1)).count();

    if s_len <= max_chars {
        s
    } else {
        let mut s: String = s.chars().take(max_chars - CHARS_QTY).collect();
        s.push_str(CHARS);
        s.into()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use insta::assert_snapshot;

    #[test]
    fn text() {
        fn t<'a, S: Into<Cow<'a, str>>>(s: S, max_chars: usize) -> Cow<'a, str> {
            //let s: &str = s.as_ref();
            let s: Cow<'a, str> = s.into();
            truncate_text(s, max_chars)
        }

        let s = "";
        assert_snapshot!(t(s, 0), @"");
        assert_snapshot!(t(s, 1), @"");

        let s = "1";
        assert_snapshot!(t(s, 0), @"1");

        let s = "1234";
        assert_snapshot!(t(s, 0), @"1234");
        assert_snapshot!(t(s, 1), @"1234");
        assert_snapshot!(t(s, 4), @"1234");
        assert_snapshot!(t(s, 5), @"1234");
        assert_snapshot!(t(s, 6), @"1234");

        let s = "12345";
        assert_snapshot!(t(s, 4), @"12345");
        assert_snapshot!(t(s, 5), @"12345");
        assert_snapshot!(t(s, 6), @"12345");

        let s = "123456";
        assert_snapshot!(t(s, 4), @"[...]");
        assert_snapshot!(t(s, 5), @"[...]");
        assert_snapshot!(t(s, 6), @"123456");

        let s = "1234567";
        assert_snapshot!(t(s, 4), @"[...]");
        assert_snapshot!(t(s, 5), @"[...]");
        assert_snapshot!(t(s, 6), @"1[...]");
        assert_snapshot!(t(s, 7), @"1234567");
    }
}
