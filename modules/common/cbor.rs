//! A reader for the CBOR subset `WebAuthn` uses (RFC 8949).
//!
//! Pure `no_std` fragment, zero allocation: every accessor returns a slice
//! borrowed from the input. Only what `CTAP2` canonical CBOR can contain is
//! implemented — definite-length byte strings, text strings, arrays and maps,
//! plus unsigned and negative integers. Indefinite-length items, tags, floats
//! and simple values are rejected rather than skipped, because an attestation
//! object that contains them is not canonical `CTAP2` and should not be parsed
//! as though it were.
//!
//! The reader never trusts a length header: every advance is bounds-checked
//! against the remaining input, so a truncated or hostile object yields
//! [`CborError::Truncated`] rather than reading out of bounds.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// How deeply `skip_value` will descend before giving up. An attestation
/// object is two or three levels deep; the bound stops a crafted object from
/// driving unbounded recursion.
pub const MAX_DEPTH: u32 = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CborError {
    /// Input ended inside an item.
    Truncated,
    /// A major type or additional-information value outside the `CTAP2` subset
    /// (indefinite lengths, tags, floats, simple values).
    Unsupported,
    /// The item found was not the type the caller asked for.
    TypeMismatch,
    /// A length or integer that does not fit this platform's `usize`.
    Overflow,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
}

/// CBOR major types (RFC 8949 §3.1).
pub const MAJOR_UNSIGNED: u8 = 0;
pub const MAJOR_NEGATIVE: u8 = 1;
pub const MAJOR_BYTES: u8 = 2;
pub const MAJOR_TEXT: u8 = 3;
pub const MAJOR_ARRAY: u8 = 4;
pub const MAJOR_MAP: u8 = 5;

/// A cursor over a CBOR byte string.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes consumed so far.
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Whether the whole input has been consumed.
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Overflow)?;
        if end > self.data.len() {
            return Err(CborError::Truncated);
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Read one item header: its major type and its argument.
    fn header(&mut self) -> Result<(u8, u64), CborError> {
        let first = *self.take(1)?.first().ok_or(CborError::Truncated)?;
        let major = first >> 5;
        if major > MAJOR_MAP {
            // Major types 6 (tag) and 7 (float / simple) are outside the
            // subset WebAuthn structures are built from. Rejected before the
            // argument is read, so an unsupported item is reported as such
            // rather than as whatever truncation its argument would cause.
            return Err(CborError::Unsupported);
        }
        let info = first & 0x1f;
        let argument = match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => {
                let b = self.take(2)?;
                u64::from(u16::from_be_bytes([b[0], b[1]]))
            }
            26 => {
                let b = self.take(4)?;
                u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            }
            27 => {
                let b = self.take(8)?;
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }
            // 28..=30 are reserved; 31 is an indefinite length, which
            // canonical CTAP2 CBOR never uses.
            _ => return Err(CborError::Unsupported),
        };
        Ok((major, argument))
    }

    /// Peek at the next item's major type without consuming it.
    pub fn peek_major(&self) -> Result<u8, CborError> {
        let mut probe = *self;
        probe.header().map(|(major, _)| major)
    }

    /// Read an unsigned integer.
    pub fn unsigned(&mut self) -> Result<u64, CborError> {
        match self.header()? {
            (MAJOR_UNSIGNED, value) => Ok(value),
            _ => Err(CborError::TypeMismatch),
        }
    }

    /// Read an integer, unsigned or negative. CBOR encodes `-1 - n`, so a
    /// negative argument of 0 is the integer -1 — the encoding COSE key
    /// labels use for their negative parameters.
    pub fn integer(&mut self) -> Result<i64, CborError> {
        match self.header()? {
            (MAJOR_UNSIGNED, value) => i64::try_from(value).map_err(|_| CborError::Overflow),
            (MAJOR_NEGATIVE, value) => {
                let magnitude = i64::try_from(value).map_err(|_| CborError::Overflow)?;
                Ok(-1 - magnitude)
            }
            _ => Err(CborError::TypeMismatch),
        }
    }

    /// Read a byte string, returning a slice of the input.
    pub fn bytes(&mut self) -> Result<&'a [u8], CborError> {
        match self.header()? {
            (MAJOR_BYTES, len) => {
                let len = usize::try_from(len).map_err(|_| CborError::Overflow)?;
                self.take(len)
            }
            _ => Err(CborError::TypeMismatch),
        }
    }

    /// Read a text string, returning its raw (unvalidated) UTF-8 bytes. The
    /// consumer compares against ASCII literals, so no UTF-8 decoding is
    /// needed or done.
    pub fn text(&mut self) -> Result<&'a [u8], CborError> {
        match self.header()? {
            (MAJOR_TEXT, len) => {
                let len = usize::try_from(len).map_err(|_| CborError::Overflow)?;
                self.take(len)
            }
            _ => Err(CborError::TypeMismatch),
        }
    }

    /// Read an array header, returning its element count.
    pub fn array_len(&mut self) -> Result<usize, CborError> {
        match self.header()? {
            (MAJOR_ARRAY, len) => usize::try_from(len).map_err(|_| CborError::Overflow),
            _ => Err(CborError::TypeMismatch),
        }
    }

    /// Read a map header, returning its entry count (pairs, not items).
    pub fn map_len(&mut self) -> Result<usize, CborError> {
        match self.header()? {
            (MAJOR_MAP, len) => usize::try_from(len).map_err(|_| CborError::Overflow),
            _ => Err(CborError::TypeMismatch),
        }
    }

    /// Skip one complete item, whatever it is.
    pub fn skip_value(&mut self) -> Result<(), CborError> {
        self.skip_at_depth(0)
    }

    fn skip_at_depth(&mut self, depth: u32) -> Result<(), CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let (major, argument) = self.header()?;
        match major {
            MAJOR_UNSIGNED | MAJOR_NEGATIVE => Ok(()),
            MAJOR_BYTES | MAJOR_TEXT => {
                let len = usize::try_from(argument).map_err(|_| CborError::Overflow)?;
                self.take(len).map(|_| ())
            }
            MAJOR_ARRAY => {
                for _ in 0..argument {
                    self.skip_at_depth(depth + 1)?;
                }
                Ok(())
            }
            // A map's argument counts pairs, so each entry is two items.
            _ => {
                for _ in 0..argument {
                    self.skip_at_depth(depth + 1)?;
                    self.skip_at_depth(depth + 1)?;
                }
                Ok(())
            }
        }
    }

    /// Find the value for a text key in the map that starts here, leaving the
    /// reader positioned at that value. Returns `false` (with the reader
    /// restored) when the key is absent.
    pub fn seek_text_key(&mut self, key: &[u8]) -> Result<bool, CborError> {
        let start = self.pos;
        let entries = self.map_len()?;
        for _ in 0..entries {
            let found = self.text()?;
            if found == key {
                return Ok(true);
            }
            self.skip_value()?;
        }
        self.pos = start;
        Ok(false)
    }

    /// The same, for the integer-labelled maps COSE keys use.
    pub fn seek_int_key(&mut self, key: i64) -> Result<bool, CborError> {
        let start = self.pos;
        let entries = self.map_len()?;
        for _ in 0..entries {
            let found = self.integer()?;
            if found == key {
                return Ok(true);
            }
            self.skip_value()?;
        }
        self.pos = start;
        Ok(false)
    }
}
