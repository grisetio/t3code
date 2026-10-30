//! Compact JSON writing with a fixed key order. The payload bytes are signed as
//! produced, so the writer is deliberately small and deterministic.

use std::fmt::Write as _;

pub fn push_str(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn push_str_array<S: AsRef<str>>(out: &mut String, values: &[S]) {
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_str(out, value.as_ref());
    }
    out.push(']');
}

pub fn push_opt_str(out: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_str(out, value),
        None => out.push_str("null"),
    }
}

pub fn string(value: &str) -> String {
    let mut out = String::new();
    push_str(&mut out, value);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn escapes_like_the_vector_generator() {
        assert_eq!(super::string("a\"b\\c\n\u{1b}\u{7f}é"), "\"a\\\"b\\\\c\\n\\u001b\u{7f}é\"");
    }
}
