//! Block base58, the string encoding of addresses.
//!
//! The CryptoNote lineage scheme: the byte string is cut into full
//! blocks of eight bytes and one final short block; a full block
//! encodes to exactly eleven characters, a short block of `n` bytes
//! to a fixed size from the table below. Alphabet characters are
//! chosen so that no digit is confused with another in print or
//! handwriting.
//!
//! Decoding is strict: unknown characters, structurally impossible
//! lengths, values that overflow their block, and any form that
//! does not re-encode identically are all errors.

use crate::DecodeError;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encoded sizes of blocks, indexed by the byte count (0 to 8);
/// a full eight-byte block encodes to eleven characters.
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

const FULL_BLOCK_BYTES: usize = 8;
const FULL_BLOCK_CHARS: usize = 11;

const fn build_decode_table() -> [i8; 256] {
    let mut table = [-1i8; 256];
    let mut i = 0;
    while i < 58 {
        table[ALPHABET[i] as usize] = i as i8;
        i += 1;
    }
    table
}

const DECODE_TABLE: [i8; 256] = build_decode_table();

fn decode_digit(c: u8) -> Result<u64, DecodeError> {
    match DECODE_TABLE[c as usize] {
        d if d >= 0 => Ok(d as u64),
        _ => Err(DecodeError::InvalidBase58),
    }
}

/// Encodes one block of at most eight bytes to its fixed-size form.
fn encode_block(data: &[u8]) -> String {
    let size = ENCODED_BLOCK_SIZES[data.len()];
    let mut value: u64 = 0;
    for &byte in data {
        value = (value << 8) | u64::from(byte);
    }
    let mut out = vec![b'1'; size];
    let mut i = size;
    while i > 0 && value > 0 {
        i -= 1;
        out[i] = ALPHABET[(value % 58) as usize];
        value /= 58;
    }
    String::from_utf8(out).expect("alphabet is ASCII")
}

/// Decodes one encoded block back to its (at most eight) bytes,
/// returned big-endian in a fixed array.
fn decode_block(chunk: &[u8], byte_count: usize) -> Result<[u8; 8], DecodeError> {
    if byte_count > FULL_BLOCK_BYTES || chunk.len() != ENCODED_BLOCK_SIZES[byte_count] {
        return Err(DecodeError::InvalidBase58);
    }
    let mut value: u64 = 0;
    for &c in chunk {
        let digit = decode_digit(c)?;
        value = value
            .checked_mul(58)
            .and_then(|v| v.checked_add(digit))
            .ok_or(DecodeError::InvalidBase58)?;
    }
    if byte_count < FULL_BLOCK_BYTES && value >= 1u64 << (8 * byte_count) {
        return Err(DecodeError::InvalidBase58);
    }
    Ok(value.to_be_bytes())
}

/// Block base58 encoding of a byte string.
#[must_use]
pub fn base58_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() / FULL_BLOCK_BYTES + 1) * FULL_BLOCK_CHARS);
    let mut chunks = data.chunks_exact(FULL_BLOCK_BYTES);
    for chunk in &mut chunks {
        out.push_str(&encode_block(chunk));
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        out.push_str(&encode_block(remainder));
    }
    out
}

/// Strict block base58 decoding.
///
/// # Errors
///
/// Returns [`DecodeError::InvalidBase58`] for any invalid or
/// non-canonical form, including inputs that decode but do not
/// re-encode to exactly the same string.
pub fn base58_decode(s: &str) -> Result<Vec<u8>, DecodeError> {
    let chars = s.as_bytes();
    if chars.is_empty() {
        return Ok(Vec::new());
    }
    let full_blocks = chars.len() / FULL_BLOCK_CHARS;
    let short_len = chars.len() % FULL_BLOCK_CHARS;
    // A short block exists only in the sizes of the table; lengths
    // 1, 4 and 8 are structurally impossible.
    let short_bytes = match short_len {
        0 => 0,
        2 => 1,
        3 => 2,
        5 => 3,
        6 => 4,
        7 => 5,
        9 => 6,
        10 => 7,
        _ => return Err(DecodeError::InvalidBase58),
    };

    let mut out = Vec::with_capacity(full_blocks * FULL_BLOCK_BYTES + short_bytes);
    for i in 0..full_blocks {
        let block = decode_block(
            &chars[i * FULL_BLOCK_CHARS..(i + 1) * FULL_BLOCK_CHARS],
            FULL_BLOCK_BYTES,
        )?;
        out.extend_from_slice(&block);
    }
    if short_bytes > 0 {
        let block = decode_block(&chars[full_blocks * FULL_BLOCK_CHARS..], short_bytes)?;
        out.extend_from_slice(&block[8 - short_bytes..]);
    }

    // Canonicality: whatever decodes must re-encode identically.
    if base58_encode(&out) != s {
        return Err(DecodeError::InvalidBase58);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn roundtrip(data: &[u8]) {
        let encoded = base58_encode(data);
        let decoded = base58_decode(&encoded).expect("roundtrip decode");
        assert_eq!(hex(&decoded), hex(data), "roundtrip failed for {encoded}");
    }

    #[test]
    fn full_block_boundaries() {
        // One full block: eight bytes become eleven characters.
        assert_eq!(base58_encode(&[0u8; 8]).len(), 11);
        // 8 bytes + 1 byte: 11 + 2 characters.
        assert_eq!(base58_encode(&[0u8; 9]).len(), 13);
    }

    #[test]
    fn zeros() {
        // A zero full block is eleven '1' characters.
        assert_eq!(base58_encode(&[0u8; 8]), "11111111111");
        roundtrip(&[0u8; 8]);
        roundtrip(&[0u8; 3]);
        roundtrip(&[0u8; 9]);
    }

    #[test]
    fn known_values() {
        // A single 0x01 byte is a one-byte short block: two
        // characters, the leading '1' padding a zero digit.
        assert_eq!(base58_encode(&[0x01]), "12");
        assert_eq!(base58_decode("12"), Ok(vec![0x01]));
        // 0x00 encodes as two '1' characters.
        assert_eq!(base58_encode(&[0x00]), "11");
    }

    #[test]
    fn deterministic_lcg_roundtrip() {
        let mut state = 0x6180_3398u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        };
        for len in 1..=80 {
            let mut data = vec![0u8; len];
            for byte in &mut data {
                *byte = (next() >> 32) as u8;
            }
            roundtrip(&data);
        }
    }

    #[test]
    fn empty_string() {
        assert_eq!(base58_encode(&[]), "");
        assert_eq!(base58_decode(""), Ok(vec![]));
    }

    #[test]
    fn rejects_unknown_characters() {
        assert!(base58_decode("0").is_err()); // not in alphabet
        assert!(base58_decode("IOl").is_err()); // excluded look-alikes
        assert!(base58_decode("2 +2").is_err()); // whitespace
    }

    #[test]
    fn rejects_impossible_lengths() {
        // Lengths 1, 4 and 8 cannot be produced by any encoding.
        assert!(base58_decode("2").is_err());
        assert!(base58_decode("2222").is_err());
        assert!(base58_decode("22222222").is_err());
    }

    #[test]
    fn rejects_overflowing_short_block() {
        // Two characters encode one byte: "zz" is 3363, above 255.
        assert!(base58_decode("zz").is_err());
    }

    #[test]
    fn rejects_overflowing_full_block() {
        // Eleven 'z' characters exceed the 64-bit block range.
        assert!(base58_decode(&"z".repeat(11)).is_err());
    }
}
