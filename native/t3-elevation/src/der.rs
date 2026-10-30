//! Minimal DER reader for X.509 and the Android key description. Android's
//! AuthorizationList uses context tags above 30, which general DER crates of
//! this generation don't parse.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Universal,
    Application,
    Context,
    Private,
}

#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub class: Class,
    pub constructed: bool,
    pub number: u32,
    pub value: &'a [u8],
    /// The whole element, header included.
    pub raw: &'a [u8],
}

pub const SEQUENCE: u32 = 16;
pub const SET: u32 = 17;
pub const INTEGER: u32 = 2;
pub const BIT_STRING: u32 = 3;
pub const OCTET_STRING: u32 = 4;
pub const NULL: u32 = 5;
pub const OID: u32 = 6;
pub const ENUMERATED: u32 = 10;
pub const BOOLEAN: u32 = 1;

pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn next(&mut self) -> Option<Tlv<'a>> {
        let data = self.data;
        let first = *data.first()?;
        let class = match first >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::Context,
            _ => Class::Private,
        };
        let constructed = first & 0x20 != 0;
        let mut position = 1;
        let mut number = u32::from(first & 0x1f);
        if number == 0x1f {
            number = 0;
            loop {
                let byte = *data.get(position)?;
                position += 1;
                number = number.checked_mul(128)?.checked_add(u32::from(byte & 0x7f))?;
                if byte & 0x80 == 0 {
                    break;
                }
                if position > 5 {
                    return None;
                }
            }
        }
        let length_byte = *data.get(position)?;
        position += 1;
        let length = if length_byte < 0x80 {
            usize::from(length_byte)
        } else {
            let count = usize::from(length_byte & 0x7f);
            if count == 0 || count > 4 {
                return None;
            }
            let mut length = 0usize;
            for _ in 0..count {
                length = (length << 8) | usize::from(*data.get(position)?);
                position += 1;
            }
            length
        };
        let end = position.checked_add(length)?;
        let value = data.get(position..end)?;
        self.data = &data[end..];
        Some(Tlv { class, constructed, number, value, raw: &data[..end] })
    }

    pub fn expect(&mut self, class: Class, number: u32) -> Option<Tlv<'a>> {
        let tlv = self.next()?;
        (tlv.class == class && tlv.number == number).then_some(tlv)
    }

    pub fn universal(&mut self, number: u32) -> Option<Tlv<'a>> {
        self.expect(Class::Universal, number)
    }
}

impl<'a> Tlv<'a> {
    pub fn reader(&self) -> Reader<'a> {
        Reader::new(self.value)
    }

    /// A non-negative INTEGER or ENUMERATED that fits in u64.
    pub fn as_u64(&self) -> Option<u64> {
        let bytes = self.value;
        if bytes.is_empty() || bytes[0] & 0x80 != 0 {
            return None;
        }
        let bytes = if bytes.len() > 1 && bytes[0] == 0 { &bytes[1..] } else { bytes };
        if bytes.len() > 8 {
            return None;
        }
        Some(bytes.iter().fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)))
    }
}

/// Builds DER for test fixtures.
#[cfg(any(test, feature = "fixtures"))]
pub mod write {
    pub fn tlv(class_bits: u8, constructed: bool, number: u32, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let first = class_bits | if constructed { 0x20 } else { 0 };
        if number < 31 {
            out.push(first | number as u8);
        } else {
            out.push(first | 0x1f);
            let mut groups = Vec::new();
            let mut rest = number;
            loop {
                groups.push((rest & 0x7f) as u8);
                rest >>= 7;
                if rest == 0 {
                    break;
                }
            }
            for (index, group) in groups.iter().rev().enumerate() {
                out.push(if index + 1 < groups.len() { group | 0x80 } else { *group });
            }
        }
        let length = value.len();
        if length < 0x80 {
            out.push(length as u8);
        } else {
            let bytes: Vec<u8> = length.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
            out.push(0x80 | bytes.len() as u8);
            out.extend(bytes);
        }
        out.extend_from_slice(value);
        out
    }
    pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0, true, 16, &parts.concat())
    }
    pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0, true, 17, &parts.concat())
    }
    pub fn int(value: u64) -> Vec<u8> {
        let mut bytes: Vec<u8> = value.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        if bytes.is_empty() || bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        tlv(0, false, 2, &bytes)
    }
    pub fn enumerated(value: u64) -> Vec<u8> {
        let mut out = int(value);
        out[0] = 10;
        out
    }
    pub fn octets(value: &[u8]) -> Vec<u8> {
        tlv(0, false, 4, value)
    }
    pub fn null() -> Vec<u8> {
        vec![5, 0]
    }
    pub fn boolean(value: bool) -> Vec<u8> {
        vec![1, 1, if value { 0xff } else { 0 }]
    }
    pub fn bits(value: &[u8]) -> Vec<u8> {
        let mut body = vec![0];
        body.extend_from_slice(value);
        tlv(0, false, 3, &body)
    }
    pub fn oid(encoded: &[u8]) -> Vec<u8> {
        tlv(0, false, 6, encoded)
    }
    /// `[number] EXPLICIT`.
    pub fn explicit(number: u32, inner: &[u8]) -> Vec<u8> {
        tlv(0x80, true, number, inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_high_tag_numbers_and_long_lengths() {
        let inner = write::int(300);
        let tagged = write::explicit(709, &write::octets(&vec![7u8; 200]));
        let data = write::seq(&[inner, tagged]);
        let mut outer = Reader::new(&data);
        let sequence = outer.universal(SEQUENCE).unwrap();
        assert!(outer.is_empty());
        let mut reader = sequence.reader();
        assert_eq!(reader.universal(INTEGER).unwrap().as_u64(), Some(300));
        let tagged = reader.next().unwrap();
        assert_eq!((tagged.class, tagged.number, tagged.constructed), (Class::Context, 709, true));
        assert_eq!(tagged.reader().universal(OCTET_STRING).unwrap().value.len(), 200);
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(Reader::new(&[0x30, 0x05, 0x02]).next().is_none());
        assert!(Reader::new(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).next().is_none());
    }
}
