//! `escapeElevationDisplayText` from the contract, used for the helper's own
//! terminal output (install/enroll confirmation).

use std::fmt::Write as _;

/// General categories Cf, Zs (except U+0020), Zl and Zp, every
/// Default_Ignorable_Code_Point, and U+2800 (braille blank), outside the ASCII
/// and C1 control ranges, which are handled separately.
const FORMAT_AND_SPACE: &[(u32, u32)] = &[
    (0x00A0, 0x00A0),
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x115F, 0x1160),
    (0x1680, 0x1680),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x2000, 0x200F),
    (0x2028, 0x202F),
    (0x205F, 0x206F),
    (0x2800, 0x2800),
    (0x3000, 0x3000),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

fn needs_escape(ch: char) -> bool {
    let code = ch as u32;
    code < 0x20
        || (0x7F..=0x9F).contains(&code)
        || FORMAT_AND_SPACE
            .iter()
            .any(|(low, high)| (*low..=*high).contains(&code))
}

pub fn display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if needs_escape(c) => {
                let _ = write!(out, "\\u{{{:X}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
