//! Unsigned LEB128 varints, the length encoding of the protocol.
//!
//! Seven bits of payload per byte, little-endian groups, the most
//! significant bit marking continuation. Encoding is canonical by
//! construction; decoding rejects every non-canonical form:
//! superfluous trailing zero groups, encodings longer than the
//! minimum, and values that do not fit in a `u64`.

use crate::DecodeError;

/// Writes `value` as a canonical varint into `out`.
pub fn write_varint(value: u64, out: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// Reads a varint from the front of `bytes`.
///
/// Returns the value and the number of bytes consumed. The rules
/// are strict: `[0x80, 0x00]` is not a valid encoding of zero, and
/// no value ever needs more than ten bytes.
///
/// # Errors
///
/// Returns [`DecodeError::InvalidVarint`] for a truncated stream,
/// a non-canonical encoding, or an encoding wider than ten bytes.
pub fn read_varint(bytes: &[u8]) -> Result<(u64, usize), DecodeError> {
    let mut value: u64 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        let payload = u64::from(byte & 0x7f);
        let terminates = byte & 0x80 == 0;
        if i == 9 {
            // The tenth byte exists only to carry the final bit.
            if payload != 1 || !terminates {
                return Err(DecodeError::InvalidVarint);
            }
            return Ok((value | (1 << 63), 10));
        }
        value |= payload << (7 * i);
        if terminates {
            // A zero-payload terminating group beyond the first byte
            // encodes a superfluous leading zero: non-canonical.
            if payload == 0 && i > 0 {
                return Err(DecodeError::InvalidVarint);
            }
            return Ok((value, i + 1));
        }
    }
    // The stream ended inside a continuation.
    Err(DecodeError::InvalidVarint)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: u64) {
        let mut buf = Vec::new();
        write_varint(value, &mut buf);
        let (decoded, used) = read_varint(&buf).expect("valid varint");
        assert_eq!(decoded, value);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn known_encodings() {
        let mut buf = Vec::new();
        write_varint(0, &mut buf);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        write_varint(1, &mut buf);
        assert_eq!(buf, vec![0x01]);

        buf.clear();
        write_varint(127, &mut buf);
        assert_eq!(buf, vec![0x7f]);

        buf.clear();
        write_varint(128, &mut buf);
        assert_eq!(buf, vec![0x80, 0x01]);

        buf.clear();
        write_varint(300, &mut buf);
        assert_eq!(buf, vec![0xac, 0x02]);

        buf.clear();
        write_varint(u64::MAX, &mut buf);
        // 64 bits = nine full groups of seven plus one final bit.
        assert_eq!(
            buf,
            [0xff; 9].iter().copied().chain([0x01]).collect::<Vec<u8>>()
        );
    }

    #[test]
    fn boundaries() {
        roundtrip(0);
        roundtrip(1);
        roundtrip(127);
        roundtrip(128);
        roundtrip(16_383);
        roundtrip(16_384);
        roundtrip(u32::MAX as u64);
        roundtrip(1 << 55);
        roundtrip((1 << 63) - 1);
        roundtrip(1 << 63);
        roundtrip(u64::MAX - 1);
        roundtrip(u64::MAX);
    }

    #[test]
    fn deterministic_lcg_roundtrip() {
        // Fixed-seed linear congruential generator: no external RNG,
        // the sequence is identical on every machine, forever.
        let mut state = 0x1618_0339_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        };
        for _ in 0..512 {
            roundtrip(next());
        }
    }

    #[test]
    fn rejects_superfluous_zero_tail() {
        assert!(read_varint(&[0x80, 0x00]).is_err());
        assert!(read_varint(&[0xff, 0x00]).is_err());
        assert!(read_varint(&[0x80, 0x80, 0x00]).is_err());
    }

    #[test]
    fn rejects_truncated() {
        assert!(read_varint(&[0x80]).is_err());
        assert!(read_varint(&[0xff, 0xff]).is_err());
        assert!(read_varint(&[]).is_err());
    }

    #[test]
    fn rejects_overflow() {
        // More than ten bytes: wider than any u64 encoding.
        assert!(read_varint(&[0xff; 10]).is_err());
        // Tenth byte carrying more than the single final bit.
        assert!(
            read_varint(&[0xff; 9].iter().copied().chain([0x02]).collect::<Vec<u8>>()).is_err()
        );
        // Tenth byte with its continuation bit still set.
        assert!(
            read_varint(&[0xff; 9].iter().copied().chain([0x81]).collect::<Vec<u8>>()).is_err()
        );
    }
}
