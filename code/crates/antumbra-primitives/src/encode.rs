//! Canonical binary encoding: the reader and the writer.
//!
//! Every consensus structure is a flat sequence of little-endian
//! fixed-width integers, booleans as a single byte, and length
//! prefixed byte strings (varint length). Decoding is total: a
//! reader never guesses, a trailing byte is an error, a boolean
//! is strictly 0 or 1, and a length must fit the remaining input.

use crate::varint::{read_varint, write_varint};

/// A canonical decoding failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// The input ended before the structure was complete.
    Eof,
    /// A varint was truncated, non-canonical or too wide.
    InvalidVarint,
    /// A boolean byte was neither 0 nor 1.
    InvalidBool(u8),
    /// A length prefix exceeded the remaining input.
    LengthTooBig {
        /// The length that was announced.
        announced: u64,
        /// The number of bytes actually remaining.
        remaining: u64,
    },
    /// A base58 string was invalid or non-canonical.
    InvalidBase58,
    /// An address was invalid (length, prefix or checksum).
    InvalidAddress,
    /// Extra bytes remained after a complete decode.
    Trailing(usize),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Eof => write!(f, "unexpected end of input"),
            Self::InvalidVarint => write!(f, "invalid varint"),
            Self::InvalidBool(b) => write!(f, "invalid boolean byte {b}"),
            Self::LengthTooBig {
                announced,
                remaining,
            } => write!(f, "announced {announced} bytes but only {remaining} remain"),
            Self::InvalidBase58 => write!(f, "invalid base58"),
            Self::InvalidAddress => write!(f, "invalid address"),
            Self::Trailing(n) => write!(f, "{n} trailing bytes after decode"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A canonical binary writer.
#[derive(Debug, Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// A fresh empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Writes one byte.
    pub fn write_u8(&mut self, v: u8) {
        self.out.push(v);
    }

    /// Writes a little-endian `u16`.
    pub fn write_u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    /// Writes a little-endian `u32`.
    pub fn write_u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    /// Writes a little-endian `u64`.
    pub fn write_u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    /// Writes a boolean as 0x00 or 0x01.
    pub fn write_bool(&mut self, v: bool) {
        self.out.push(u8::from(v));
    }

    /// Writes a length-prefixed byte string.
    pub fn write_bytes(&mut self, v: &[u8]) {
        write_varint(v.len() as u64, &mut self.out);
        self.out.extend_from_slice(v);
    }

    /// Writes a fixed-width byte array with no length prefix.
    pub fn write_array<const N: usize>(&mut self, v: &[u8; N]) {
        self.out.extend_from_slice(v);
    }

    /// Consumes the writer and returns the encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.out
    }

    /// The number of bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether nothing has been written yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }
}

/// A canonical binary reader over a byte slice.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over the whole of `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(DecodeError::Eof);
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Eof`] past the end of the input.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// Reads a little-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Reads a little-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a boolean: strictly 0x00 or 0x01.
    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(DecodeError::InvalidBool(b)),
        }
    }

    /// Reads a canonical varint.
    pub fn read_varint(&mut self) -> Result<u64, DecodeError> {
        let (value, used) = read_varint(&self.buf[self.pos..])?;
        self.pos += used;
        Ok(value)
    }

    /// Reads a length-prefixed byte string.
    ///
    /// The announced length must fit the remaining input exactly:
    /// no over-announced allocations, ever.
    pub fn read_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.read_varint()?;
        let remaining = (self.buf.len() - self.pos) as u64;
        if len > remaining {
            return Err(DecodeError::LengthTooBig {
                announced: len,
                remaining,
            });
        }
        self.take(len as usize)
    }

    /// Reads a fixed-width byte array.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let b = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }

    /// Succeeds only when every input byte has been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Trailing`] with the leftover count.
    pub fn finish(&self) -> Result<(), DecodeError> {
        if self.pos < self.buf.len() {
            return Err(DecodeError::Trailing(self.buf.len() - self.pos));
        }
        Ok(())
    }

    /// The number of bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_reader_roundtrip() {
        let mut w = Writer::new();
        w.write_u8(0xab);
        w.write_u16(0x1234);
        w.write_u32(0xdead_beef);
        w.write_u64(0x0123_4567_89ab_cdef);
        w.write_bool(true);
        w.write_bool(false);
        w.write_bytes(b"antumbra");
        w.write_array(&[1u8, 2, 3, 4]);

        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8(), Ok(0xab));
        assert_eq!(r.read_u16(), Ok(0x1234));
        assert_eq!(r.read_u32(), Ok(0xdead_beef));
        assert_eq!(r.read_u64(), Ok(0x0123_4567_89ab_cdef));
        assert_eq!(r.read_bool(), Ok(true));
        assert_eq!(r.read_bool(), Ok(false));
        assert_eq!(r.read_bytes(), Ok(&b"antumbra"[..]));
        assert_eq!(r.read_array::<4>(), Ok([1u8, 2, 3, 4]));
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn little_endian_layout() {
        let mut w = Writer::new();
        w.write_u32(1);
        assert_eq!(w.finish(), vec![1, 0, 0, 0]);
    }

    #[test]
    fn bool_is_strict() {
        let bad = [0x02u8];
        assert_eq!(
            Reader::new(&bad).read_bool(),
            Err(DecodeError::InvalidBool(2))
        );
    }

    #[test]
    fn length_prefix_must_fit() {
        // Announces 5 bytes, provides only 2.
        let bytes = [0x05u8, 0xaa, 0xbb];
        assert_eq!(
            Reader::new(&bytes).read_bytes(),
            Err(DecodeError::LengthTooBig {
                announced: 5,
                remaining: 2
            })
        );
    }

    #[test]
    fn trailing_bytes_rejected() {
        let bytes = [0x01u8, 0xff];
        let mut r = Reader::new(&bytes);
        r.read_u8().unwrap();
        assert_eq!(r.finish(), Err(DecodeError::Trailing(1)));
    }

    #[test]
    fn eof_on_overread() {
        let bytes = [0x01u8];
        let mut r = Reader::new(&bytes);
        r.read_u8().unwrap();
        assert_eq!(r.read_u8(), Err(DecodeError::Eof));
    }
}
