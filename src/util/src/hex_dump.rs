// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{
    fmt::{Debug, Display, Error, Formatter, Write},
    iter::Iterator,
};

#[derive(Clone, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct HexDump {
    show_addr: bool,
    show_hex: bool,
    show_ascii: bool,
    show_truncation_indicator: bool,
    skip_allzeroes_lines: bool,
    bytes_per_line: usize,
    line_prefix: String,
    addr_start: usize,
    addr_min_width: usize,
    cnt_bytes_max: usize,
    group: usize,
}

impl HexDump {
    #[must_use]
    pub fn new() -> Self {
        Self {
            show_addr: true,
            show_hex: true,
            show_ascii: true,
            show_truncation_indicator: true,
            skip_allzeroes_lines: false,
            bytes_per_line: 16,
            line_prefix: String::new(),
            addr_start: 0,
            addr_min_width: 4,
            cnt_bytes_max: usize::MAX,
            group: 1,
        }
    }

    #[must_use]
    pub fn show_addr(mut self, b: bool) -> Self {
        self.show_addr = b;
        self
    }

    #[must_use]
    pub fn show_hex(mut self, b: bool) -> Self {
        self.show_hex = b;
        self
    }

    #[must_use]
    pub fn show_ascii(mut self, b: bool) -> Self {
        self.show_ascii = b;
        self
    }

    #[must_use]
    pub fn skip_allzeroes_lines(mut self, b: bool) -> Self {
        self.skip_allzeroes_lines = b;
        self
    }

    /// The number of bytes in each line of the hex dump.
    /// Minimum value is 1.
    #[must_use]
    pub fn bytes_per_line(mut self, n: usize) -> Self {
        self.bytes_per_line = n.max(1);
        self
    }

    #[must_use]
    pub fn line_prefix(mut self, line_prefix: &str) -> Self {
        self.line_prefix = line_prefix.to_owned();
        self
    }

    #[must_use]
    pub fn addr_start(mut self, n: usize) -> Self {
        self.addr_start = n;
        self
    }

    /// The minimum width of the address field in hex digits.
    #[must_use]
    pub fn addr_min_width(mut self, n: usize) -> Self {
        self.addr_min_width = n;
        self
    }

    /// The maximum number of bytes to dump. The default is `usize::MAX`.
    /// A truncation indicator (`...`) may be shown if the number of bytes supplied exceeds this value.
    #[must_use]
    pub fn cnt_bytes_max(mut self, n: usize) -> Self {
        self.cnt_bytes_max = n;
        self
    }

    /// Specifies whether the truncation indicator (`...`) is shown if the number of bytes supplied
    /// exceeds the `cnt_bytes_max` value.
    #[must_use]
    pub fn show_truncation_indicator(mut self, b: bool) -> Self {
        self.show_truncation_indicator = b;
        self
    }

    /// The number of bytes in each group in the hex dump.
    /// A value of `0` groups all bytes together.
    /// The default is `1`, indicating no grouping.
    #[must_use]
    pub fn group(mut self, n: usize) -> Self {
        self.group = n;
        self
    }

    /// Produces a `std::fmt::Display` object that formats the supplied bytes.
    /// The `.to_string()` method can also be used on the resulting object.
    #[must_use]
    pub fn dump<'a>(&self, bytes: &'a [u8]) -> HexDumpDisplay<'a> {
        HexDumpDisplay {
            hd: self.clone(),
            bytes,
        }
    }
}

pub struct HexDumpDisplay<'a> {
    hd: HexDump,
    bytes: &'a [u8],
}

impl<'a> Display for HexDumpDisplay<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        HexDumpOperation::dump_to_formatter(self, f)
    }
}

impl<'a> Debug for HexDumpDisplay<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        HexDumpOperation::dump_to_formatter(self, f)
    }
}

const SPACE_BEFORE_HEX: &str = "  ";
const TRUNCATION_INDICATOR: &str = "...";
const INTERGROUP_SPACE: char = ' ';
const TWO_HEXDIGIT_SPACE: &str = "  ";
const SPACE_BEFORE_ASCII: &str = "  ";

struct HexDumpOperation<'b, 'f, 'g: 'f> {
    hd: HexDump,
    bytes: &'b [u8],
    f: &'f mut Formatter<'g>,
    addr_width: usize,
    line_buf: Vec<u8>,
    is_subsequent_line: bool,
}

impl<'b, 'f, 'g> HexDumpOperation<'b, 'f, 'g> {
    fn dump_to_formatter(hdd: &'b HexDumpDisplay, f: &'f mut Formatter<'g>) -> Result<(), Error> {
        HexDumpOperation {
            hd: hdd.hd.clone(),
            bytes: hdd.bytes,
            f,
            addr_width: 0,
            line_buf: Vec::with_capacity(hdd.hd.bytes_per_line),
            is_subsequent_line: false,
        }
        .dump_to_formatter_method()
    }

    fn dump_to_formatter_method(&mut self) -> Result<(), Error> {
        let (cnt_bytes_total, truncated_result) = if self.bytes.len() <= self.hd.cnt_bytes_max {
            (self.bytes.len(), false)
        } else {
            (self.hd.cnt_bytes_max, true)
        };

        let bytes_iter = self.bytes.iter().clone().cloned();

        let cnt_lines = (cnt_bytes_total + self.hd.bytes_per_line - 1) / self.hd.bytes_per_line;

        let addr_last_line = self.hd.addr_start + cnt_lines * self.hd.bytes_per_line;

        self.addr_width = if addr_last_line == 0 {
            self.hd.addr_min_width
        } else {
            let bits = addr_last_line.ilog2() as usize + 1;
            let hex_digits = (bits + 3) / 4;
            self.hd.addr_min_width.max(hex_digits)
        };

        let mut addr = self.hd.addr_start;
        let mut addr_line = addr;
        for by in bytes_iter.take(cnt_bytes_total) {
            if self.hd.bytes_per_line <= self.line_buf.len() {
                self.flush_line_buf(addr_line)?;
                addr_line = addr;
            }

            self.line_buf.push(by);
            addr += 1;
        }

        if !self.line_buf.is_empty() {
            self.flush_line_buf(addr_line)?;
            addr_line = addr;
        }

        if truncated_result && self.hd.show_truncation_indicator {
            if self.is_subsequent_line {
                writeln!(self.f)?;
            }

            let mut some_char_written = false;
            self.write_prefix_and_addr(&mut some_char_written, addr_line)?;

            if some_char_written {
                self.f.write_str(SPACE_BEFORE_HEX)?;
            }

            self.f.write_str(TRUNCATION_INDICATOR)?;
            //some_char_written = true;
        }

        Ok(())
    }

    fn flush_line_buf(&mut self, addr: usize) -> Result<(), Error> {
        let skip_this_line =
            self.hd.skip_allzeroes_lines && self.line_buf.iter().copied().all(|x| x == 0);

        if !skip_this_line {
            if self.is_subsequent_line {
                writeln!(self.f)?;
            }

            let mut some_char_written = false;
            self.write_prefix_and_addr(&mut some_char_written, addr)?;

            if self.hd.show_hex {
                // Figure whether a space should be inserted before this byte's hex digits.
                let need_intergroup_space = |hex_bytes_written_this_line: usize| {
                    hex_bytes_written_this_line != 0
                        && match self.hd.group {
                            0 => false, // all one big group
                            1 => true,  // usual single-byte group
                            _ => hex_bytes_written_this_line % self.hd.group == 0,
                        }
                };

                if some_char_written {
                    self.f.write_str(SPACE_BEFORE_HEX)?;
                }

                let mut hex_bytes_written_this_line = 0;
                for by in self.line_buf.iter() {
                    if need_intergroup_space(hex_bytes_written_this_line) {
                        self.f.write_char(INTERGROUP_SPACE)?;
                    }
                    write!(self.f, "{by:02x}")?;

                    hex_bytes_written_this_line += 1;
                }

                some_char_written = some_char_written || (hex_bytes_written_this_line != 0);

                // Pad out the rest of the hex digits if necessary.
                if self.hd.show_ascii {
                    while hex_bytes_written_this_line < self.hd.bytes_per_line {
                        if need_intergroup_space(hex_bytes_written_this_line) {
                            self.f.write_char(INTERGROUP_SPACE)?;
                        }
                        self.f.write_str(TWO_HEXDIGIT_SPACE)?;
                        hex_bytes_written_this_line += 1;
                    }
                }
            }

            if self.hd.show_ascii {
                if some_char_written {
                    self.f.write_str(SPACE_BEFORE_ASCII)?;
                }

                for by in self.line_buf.iter().copied() {
                    let ch: char = if 0x20 < by && by <= 0x7e {
                        by as char
                    } else {
                        '.'
                    };
                    self.f.write_char(ch)?;
                }
            }
        }

        self.line_buf.clear();
        self.is_subsequent_line = true;

        Ok(())
    }

    fn write_prefix_and_addr(
        &mut self,
        some_char_written: &mut bool,
        addr: usize,
    ) -> Result<(), Error> {
        if !self.hd.line_prefix.is_empty() {
            self.f.write_str(self.hd.line_prefix.as_str())?;
            // We don't set some_char_written to true here, because the line prefix is not counted.
        }

        if self.hd.show_addr {
            write!(self.f, "{addr:0width$x}", width = self.addr_width)?;
            *some_char_written = true;
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        // Show that we can re-use a HexDump configuration object.
        let hd = HexDump::new().show_addr(false).show_ascii(false);

        // Show that .dump() takes various types
        assert_eq!(hd.dump(&[0u8, 1, 2]).to_string(), "00 01 02");
        let v = vec![0u8, 1, 2];
        assert_eq!(hd.dump(&v).to_string(), "00 01 02");
    }

    #[test]
    fn test_defaults() {
        assert_eq!(
            HexDump::new().dump(&[0u8; 16]).to_string(),
            "0000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................"
        );
    }

    #[test]
    fn test_empty() {
        assert_eq!(HexDump::new().dump(&[0u8; 0]).to_string(), "");
    }

    #[test]
    fn test_line_prefix() {
        // Show that we can re-use a HexDump configuration object.
        let hd = HexDump::new()
            .show_addr(false)
            .show_hex(true)
            .show_ascii(false)
            .cnt_bytes_max(2);

        let hd = hd.line_prefix("[line prefix]");
        let bytes = [0x00u8, 0x11, 0x22];

        assert_eq!(
            hd.dump(&bytes).to_string(),
            "[line prefix]00 11\n[line prefix]..."
        );
    }

    #[test]
    fn test_addr_start() {
        assert_eq!(
            HexDump::new()
                .addr_start(0x1000)
                .bytes_per_line(4)
                .dump(&[0u8; 4])
                .to_string(),
            "1000  00 00 00 00  ...."
        );
    }

    #[test]
    fn test_addr_min_width() {
        assert_eq!(
            HexDump::new()
                .addr_min_width(5)
                .bytes_per_line(4)
                .dump(&[0u8; 4])
                .to_string(),
            "00000  00 00 00 00  ...."
        );
    }

    #[test]
    fn test_grouping() {
        // Verifies cnt_bytes_max = true
        let hd = HexDump::new().show_ascii(false);

        #[rustfmt::skip]
        let test_cases: Vec<
            // cb_line cb_group  cb_src   expected
            (   usize,   usize,  usize,   &str            )> = vec![
            (       0,       0,      0,   ""                         ),
            (       0,       0,      1,   "0000  00"                 ),
            (       0,       0,      2,   "0000  00\n0001  01"       ),
            (       0,       1,      0,   ""                         ),
            (       0,       1,      1,   "0000  00"                 ),
            (       0,       1,      2,   "0000  00\n0001  01"       ),
            (       1,       0,      0,   ""                         ),
            (       1,       0,      1,   "0000  00"                 ),
            (       1,       0,      2,   "0000  00\n0001  01"       ),
            (       1,       1,      0,   ""                         ),
            (       1,       1,      1,   "0000  00"                 ),
            (       1,       1,      2,   "0000  00\n0001  01"       ),
            (       2,       0,      2,   "0000  0001"               ),
            (       2,       0,      3,   "0000  0001\n0002  02"     ),
            (       2,       1,      1,   "0000  00"                 ),
            (       2,       1,      2,   "0000  00 01"              ),
            (       2,       1,      3,   "0000  00 01\n0002  02"    ),
            (       2,       2,      2,   "0000  0001"               ),
            (       2,       2,      3,   "0000  0001\n0002  02"     ),
            (       3,       2,      5,   "0000  0001 02\n0003  0304"              ),
            (       3,       2,      6,   "0000  0001 02\n0003  0304 05"           ),
            (       3,       2,      7,   "0000  0001 02\n0003  0304 05\n0006  06" ),
            (       4,       2,      5,   "0000  0001 0203\n0004  04"              ),
            (       4,       2,      6,   "0000  0001 0203\n0004  0405"            ),
            (       4,       2,      7,   "0000  0001 0203\n0004  0405 06"         ),
            (       4,       3,      7,   "0000  000102 03\n0004  040506"          ),
            (       4,       3,      8,   "0000  000102 03\n0004  040506 07"       ),
            (       4,       3,     12,   "0000  000102 03\n0004  040506 07\n0008  08090a 0b" ),
        ];

        for (cb_line, cb_group, cb_src, expected) in test_cases {
            let hd = hd.clone().bytes_per_line(cb_line).group(cb_group);
            let data: Vec<u8> = (0..cb_src).map(|n| n as u8).collect();
            assert_eq!(hd.dump(&data).to_string(), expected);
        }
    }

    #[test]
    fn test_truncation() {
        // Verifies cnt_bytes_max = true
        let hd = HexDump::new().show_addr(false).show_ascii(false);

        #[rustfmt::skip]
        let test_cases: Vec<
            //  cb_src  cb_max   show_ti    expected
            (   usize,  usize,    bool,     &str            )> = vec![
            (       0,      0,    false,    ""              ),
            (       0,      0,    true,     ""              ),
            (       0,      1,    false,    ""              ),
            (       0,      1,    true,     ""              ),

            (       1,      0,    false,    ""              ),
            (       1,      0,    true,     "..."           ),
            (       1,      1,    false,    "00"            ),
            (       1,      1,    true,     "00"            ),
            (       1,      2,    false,    "00"            ),
            (       1,      2,    true,     "00"            ),

            (       2,      0,    false,    ""              ),
            (       2,      0,    true,     "..."           ),
            (       2,      1,    false,    "00"            ),
            (       2,      1,    true,     "00\n..."       ),
            (       2,      2,    false,    "00 00"         ),
            (       2,      2,    true,     "00 00"         ),
            (       2,      3,    false,    "00 00"         ),
            (       2,      3,    true,     "00 00"         ),
        ];

        for (cb_src, cb_max, show_truncation_indicator, expected) in test_cases {
            let hd = hd
                .clone()
                .cnt_bytes_max(cb_max)
                .show_truncation_indicator(show_truncation_indicator);
            let v = vec![0u8; cb_src];
            assert_eq!(hd.dump(&v).to_string(), expected);
        }
    }

    #[test]
    fn test_skip_allzeroes_lines() {
        let mut v = vec![0u8; 12];
        v[3] = 0x01;
        v[11] = 0x03;

        assert_eq!(
            HexDump::new()
                .skip_allzeroes_lines(false)
                .bytes_per_line(4)
                .dump(&v)
                .to_string(),
            "0000  00 00 00 01  ....\n0004  00 00 00 00  ....\n0008  00 00 00 03  ...."
        );

        assert_eq!(
            HexDump::new()
                .skip_allzeroes_lines(true)
                .bytes_per_line(4)
                .dump(&v)
                .to_string(),
            "0000  00 00 00 01  ....\n0008  00 00 00 03  ...."
        );
    }
}
