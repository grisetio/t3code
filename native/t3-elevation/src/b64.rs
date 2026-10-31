//! Base64url without padding (RFC 4648 §5), strict: padding, other alphabets and
//! non-zero trailing bits are rejected.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(text: &str) -> Option<Vec<u8>> {
    if !text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    URL_SAFE_NO_PAD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_padding_and_standard_alphabet() {
        assert_eq!(decode("AQ"), Some(vec![1]));
        assert_eq!(decode("AQ=="), None);
        assert_eq!(decode("+/8"), None);
        assert_eq!(decode("_-8"), Some(vec![0xff, 0xef]));
        // Non-canonical trailing bits.
        assert_eq!(decode("AR"), None);
        assert_eq!(decode("A"), None);
        assert_eq!(decode(""), Some(vec![]));
    }
}
