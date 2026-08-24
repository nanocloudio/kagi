//! A DER writer, and the X.509 shape kagi issues with it.
//!
//! Enough ASN.1 to build one end-entity certificate and no more. A general
//! encoder would be a great deal of surface for a module that emits exactly
//! one structure, and every field this does not write is a field that cannot
//! be written wrongly.
//!
//! **Lengths are written after their contents.** DER prefixes every value
//! with its length, and a length is only known once the value is built — so
//! each constructed element reserves room, writes its children, and goes back
//! to fill the header in. Reserving a fixed three bytes and shifting is what
//! keeps that a single pass over a caller's buffer with no allocator.
//!
//! Both the issuing key and the subject key may be Ed25519 or P-256, because
//! the carriers need different ones. A device bootstrapping mTLS presents
//! whichever key it holds; a JWT-SVID is ES256-signed by a P-256 leaf key and
//! its relying party requires a P-256 trust root, so an Ed25519-only
//! authority could not serve that carrier at all.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// ASN.1 tags this writer emits.
const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;

/// `[0]` explicit, for the certificate's version field.
const TAG_CONTEXT_0: u8 = 0xA0;
/// `[3]` explicit, for the extensions.
const TAG_CONTEXT_3: u8 = 0xA3;
/// `[6]` primitive — `uniformResourceIdentifier` in a `GeneralName`.
const TAG_URI: u8 = 0x86;

/// `id-Ed25519` (1.3.101.112), used as both the signature and the key
/// algorithm. RFC 8410 says an Ed25519 `AlgorithmIdentifier` carries no
/// parameters at all — not NULL — and a parameters field written where none
/// belongs makes a certificate some verifiers reject and others accept.
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
/// `id-ecPublicKey` (1.2.840.10045.2.1).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// `prime256v1` / `secp256r1` (1.2.840.10045.3.1.7).
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// `id-at-commonName` (2.5.4.3).
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// `id-ce-subjectAltName` (2.5.29.17).
const OID_SAN: &[u8] = &[0x55, 0x1D, 0x11];
/// `id-ce-basicConstraints` (2.5.29.19).
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
/// `id-ce-keyUsage` (2.5.29.15).
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
/// `id-ce-extKeyUsage` (2.5.29.37).
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
/// `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2).
const OID_CLIENT_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

/// The algorithm an authority signs with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SigningAlgorithm {
    Ed25519,
    P256,
}

/// The key a certificate binds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SubjectKey<'a> {
    /// A raw 32-byte Ed25519 public key.
    Ed25519(&'a [u8; 32]),
    /// An uncompressed SEC1 P-256 point (`0x04 ‖ X ‖ Y`).
    P256(&'a [u8; 65]),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DerError {
    /// The buffer could not hold what was being written.
    BufferTooSmall,
    /// A field was longer than this writer emits.
    TooLong,
    /// A timestamp outside the range the encoding covers.
    BadTime,
}

/// A cursor over a caller's buffer.
pub struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, at: 0 }
    }

    pub const fn len(&self) -> usize {
        self.at
    }

    pub const fn is_empty(&self) -> bool {
        self.at == 0
    }

    pub fn bytes(&self) -> &[u8] {
        self.out.get(..self.at).unwrap_or(&[])
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), DerError> {
        let end = self
            .at
            .checked_add(bytes.len())
            .ok_or(DerError::BufferTooSmall)?;
        self.out
            .get_mut(self.at..end)
            .ok_or(DerError::BufferTooSmall)?
            .copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    /// A primitive element: tag, length, contents.
    pub fn primitive(&mut self, tag: u8, contents: &[u8]) -> Result<(), DerError> {
        self.put(&[tag])?;
        self.length(contents.len())?;
        self.put(contents)
    }

    /// A constructed element, whose children `build` writes.
    ///
    /// The length header is three bytes wide while the children are written
    /// and then narrowed to what DER requires, shifting the contents down.
    /// One pass, no second buffer — and a definite length, because BER's
    /// indefinite form is not DER.
    pub fn constructed(
        &mut self,
        tag: u8,
        build: impl FnOnce(&mut Self) -> Result<(), DerError>,
    ) -> Result<(), DerError> {
        self.put(&[tag])?;
        let header_at = self.at;
        // Room for the widest header this writer emits: 0x82 and two bytes.
        self.put(&[0, 0, 0])?;
        let contents_at = self.at;
        build(self)?;
        let contents_len = self.at - contents_at;

        let mut header = [0u8; 3];
        let header_len = {
            let mut w = Writer::new(&mut header);
            w.length(contents_len)?;
            w.at
        };
        // Shift the contents back over the unused header bytes. Every index
        // is checked: a PIC module links no panic handler, so a slice that
        // could panic is a slice that fails to link at all.
        let shift = 3usize
            .checked_sub(header_len)
            .ok_or(DerError::BufferTooSmall)?;
        if shift > 0 {
            let from_end = contents_at
                .checked_add(contents_len)
                .ok_or(DerError::BufferTooSmall)?;
            let to = header_at
                .checked_add(header_len)
                .ok_or(DerError::BufferTooSmall)?;
            if from_end > self.out.len()
                || to
                    .checked_add(contents_len)
                    .ok_or(DerError::BufferTooSmall)?
                    > self.out.len()
            {
                return Err(DerError::BufferTooSmall);
            }
            // Copied by hand rather than with `copy_within`, which carries
            // its own panic on a bad range and so cannot link into a module.
            // The move is always downward — the header only ever shrinks —
            // so a forward walk never reads a byte it has already written.
            for offset in 0..contents_len {
                let byte = *self
                    .out
                    .get(contents_at + offset)
                    .ok_or(DerError::BufferTooSmall)?;
                *self
                    .out
                    .get_mut(to + offset)
                    .ok_or(DerError::BufferTooSmall)? = byte;
            }
            self.at = self.at.checked_sub(shift).ok_or(DerError::BufferTooSmall)?;
        }
        let header_end = header_at
            .checked_add(header_len)
            .ok_or(DerError::BufferTooSmall)?;
        self.out
            .get_mut(header_at..header_end)
            .ok_or(DerError::BufferTooSmall)?
            .copy_from_slice(header.get(..header_len).ok_or(DerError::BufferTooSmall)?);
        Ok(())
    }

    /// A DER length: short form below 128, else the minimal long form.
    fn length(&mut self, len: usize) -> Result<(), DerError> {
        if len < 0x80 {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "guarded by the bound above"
            )]
            return self.put(&[len as u8]);
        }
        if len <= 0xFF {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "guarded by the bound above"
            )]
            return self.put(&[0x81, len as u8]);
        }
        if len <= 0xFFFF {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "guarded by the bound above"
            )]
            return self.put(&[0x82, (len >> 8) as u8, len as u8]);
        }
        Err(DerError::TooLong)
    }

    /// Bytes already encoded elsewhere, spliced in as they are.
    ///
    /// For the `TBSCertificate`, which is signed over its own encoding and so
    /// must appear in the certificate byte for byte as it was signed. Writing
    /// it a second time from its fields would risk a different — still valid
    /// — encoding, and a signature over the first would not verify over the
    /// second.
    pub fn raw(&mut self, bytes: &[u8]) -> Result<(), DerError> {
        self.put(bytes)
    }

    pub fn oid(&mut self, oid: &[u8]) -> Result<(), DerError> {
        self.primitive(TAG_OID, oid)
    }

    pub fn boolean(&mut self, value: bool) -> Result<(), DerError> {
        self.primitive(TAG_BOOLEAN, &[if value { 0xFF } else { 0x00 }])
    }

    /// A non-negative INTEGER, minimally encoded.
    ///
    /// A leading zero byte goes in when the top bit is set, because DER
    /// INTEGERs are signed and a serial number that read as negative would be
    /// a different serial number.
    pub fn integer(&mut self, value: &[u8]) -> Result<(), DerError> {
        let trimmed = {
            let mut bytes = value;
            while bytes.len() > 1 && bytes.first() == Some(&0) {
                bytes = bytes.get(1..).unwrap_or(&[]);
            }
            bytes
        };
        let first = *trimmed.first().ok_or(DerError::TooLong)?;
        self.put(&[TAG_INTEGER])?;
        if first & 0x80 != 0 {
            self.length(trimmed.len() + 1)?;
            self.put(&[0x00])?;
        } else {
            self.length(trimmed.len())?;
        }
        self.put(trimmed)
    }

    /// A BIT STRING with no unused bits.
    pub fn bit_string(&mut self, contents: &[u8]) -> Result<(), DerError> {
        self.put(&[TAG_BIT_STRING])?;
        self.length(contents.len() + 1)?;
        self.put(&[0x00])?;
        self.put(contents)
    }

    /// `AlgorithmIdentifier` for Ed25519: the OID and nothing else.
    pub fn ed25519_algorithm(&mut self) -> Result<(), DerError> {
        self.constructed(TAG_SEQUENCE, |w| w.oid(OID_ED25519))
    }

    /// `Name` holding a single `CN`.
    pub fn common_name(&mut self, cn: &[u8]) -> Result<(), DerError> {
        self.constructed(TAG_SEQUENCE, |rdn_sequence| {
            rdn_sequence.constructed(TAG_SET, |rdn| {
                rdn.constructed(TAG_SEQUENCE, |attribute| {
                    attribute.oid(OID_COMMON_NAME)?;
                    attribute.primitive(TAG_UTF8_STRING, cn)
                })
            })
        })
    }

    /// `Time`, as `UTCTime` before 2050 and `GeneralizedTime` from 2050.
    ///
    /// RFC 5280 requires exactly that split, and a certificate that used the
    /// wrong one would be rejected by a verifier that reads the spec.
    pub fn time(&mut self, unix_seconds: u64) -> Result<(), DerError> {
        let (year, month, day, hour, minute, second) = civil_from_unix(unix_seconds)?;
        let mut buf = [0u8; 15];
        if year < 2050 {
            let mut at = 0usize;
            two(&mut buf, &mut at, year % 100);
            two(&mut buf, &mut at, month);
            two(&mut buf, &mut at, day);
            two(&mut buf, &mut at, hour);
            two(&mut buf, &mut at, minute);
            two(&mut buf, &mut at, second);
            if let Some(slot) = buf.get_mut(at) {
                *slot = b'Z';
            }
            at += 1;
            self.primitive(TAG_UTC_TIME, buf.get(..at).ok_or(DerError::BadTime)?)
        } else {
            let mut at = 0usize;
            two(&mut buf, &mut at, year / 100);
            two(&mut buf, &mut at, year % 100);
            two(&mut buf, &mut at, month);
            two(&mut buf, &mut at, day);
            two(&mut buf, &mut at, hour);
            two(&mut buf, &mut at, minute);
            two(&mut buf, &mut at, second);
            if let Some(slot) = buf.get_mut(at) {
                *slot = b'Z';
            }
            at += 1;
            self.primitive(
                TAG_GENERALIZED_TIME,
                buf.get(..at).ok_or(DerError::BadTime)?,
            )
        }
    }

    /// `SubjectPublicKeyInfo` for a raw Ed25519 public key.
    pub fn ed25519_spki(&mut self, public_key: &[u8; 32]) -> Result<(), DerError> {
        self.constructed(TAG_SEQUENCE, |spki| {
            spki.ed25519_algorithm()?;
            spki.bit_string(public_key)
        })
    }

    /// An ECDSA signature the SDK has already DER-encoded, in a BIT STRING.
    ///
    /// The encoding is `p256::encode_der_signature`'s, not this fragment's:
    /// the SDK already turns a fixed-width `r ‖ s` into the
    /// `SEQUENCE { r INTEGER, s INTEGER }` X.509 carries, and a second
    /// encoder for one structure is a second place for the leading-zero rule
    /// on a negative-looking component to be got wrong.
    pub fn ecdsa_signature(&mut self, der_signature: &[u8]) -> Result<(), DerError> {
        self.bit_string(der_signature)
    }

    /// The `AlgorithmIdentifier` for a signature by `algorithm`.
    ///
    /// Ed25519 carries no parameters at all (RFC 8410) and ECDSA-with-SHA256
    /// carries none either (RFC 5758) — but for different reasons, and a NULL
    /// written into either makes a certificate some verifiers reject.
    pub fn signature_algorithm(&mut self, algorithm: SigningAlgorithm) -> Result<(), DerError> {
        self.constructed(TAG_SEQUENCE, |w| match algorithm {
            SigningAlgorithm::Ed25519 => w.oid(OID_ED25519),
            SigningAlgorithm::P256 => w.oid(OID_ECDSA_SHA256),
        })
    }

    /// `SubjectPublicKeyInfo` for an uncompressed SEC1 P-256 point.
    ///
    /// Unlike Ed25519, an EC `AlgorithmIdentifier` DOES carry a parameter —
    /// the named curve — and one omitted makes a key nothing can interpret.
    pub fn p256_spki(&mut self, point: &[u8; 65]) -> Result<(), DerError> {
        self.constructed(TAG_SEQUENCE, |spki| {
            spki.constructed(TAG_SEQUENCE, |algorithm| {
                algorithm.oid(OID_EC_PUBLIC_KEY)?;
                algorithm.oid(OID_P256)
            })?;
            spki.bit_string(point)
        })
    }

    /// The extensions an end-entity client certificate carries.
    ///
    /// `subjectAltName` is where the SPIFFE id belongs — relying parties
    /// authorize on the SAN URI, not on the subject `CN`, and putting the
    /// identity only in the `CN` is how a certificate ends up authorizing
    /// nothing.
    pub fn leaf_extensions(&mut self, san_uri: &[u8]) -> Result<(), DerError> {
        self.constructed(TAG_CONTEXT_3, |explicit| {
            explicit.constructed(TAG_SEQUENCE, |extensions| {
                // basicConstraints: cA FALSE, critical. A leaf that did not
                // say so could sign for anyone.
                extensions.constructed(TAG_SEQUENCE, |ext| {
                    ext.oid(OID_BASIC_CONSTRAINTS)?;
                    ext.boolean(true)?;
                    let mut value = [0u8; 8];
                    let len = {
                        let mut w = Writer::new(&mut value);
                        w.constructed(TAG_SEQUENCE, |_| Ok(()))?;
                        w.at
                    };
                    ext.primitive(TAG_OCTET_STRING, &value[..len])
                })?;

                // keyUsage: digitalSignature, critical.
                extensions.constructed(TAG_SEQUENCE, |ext| {
                    ext.oid(OID_KEY_USAGE)?;
                    ext.boolean(true)?;
                    let mut value = [0u8; 8];
                    let len = {
                        let mut w = Writer::new(&mut value);
                        // One bit set, seven unused: digitalSignature.
                        w.put(&[TAG_BIT_STRING, 0x02, 0x07, 0x80])?;
                        w.at
                    };
                    ext.primitive(TAG_OCTET_STRING, &value[..len])
                })?;

                // extKeyUsage: clientAuth.
                extensions.constructed(TAG_SEQUENCE, |ext| {
                    ext.oid(OID_EXT_KEY_USAGE)?;
                    let mut value = [0u8; 32];
                    let len = {
                        let mut w = Writer::new(&mut value);
                        w.constructed(TAG_SEQUENCE, |eku| eku.oid(OID_CLIENT_AUTH))?;
                        w.at
                    };
                    ext.primitive(TAG_OCTET_STRING, &value[..len])
                })?;

                if san_uri.is_empty() {
                    return Ok(());
                }
                // subjectAltName: one URI. Critical, because the subject is
                // empty — RFC 5280 requires it then, and a verifier that
                // enforces that would otherwise refuse the certificate.
                extensions.constructed(TAG_SEQUENCE, |ext| {
                    ext.oid(OID_SAN)?;
                    ext.boolean(true)?;
                    let mut value = [0u8; 512];
                    let len = {
                        let mut w = Writer::new(&mut value);
                        w.constructed(TAG_SEQUENCE, |names| names.primitive(TAG_URI, san_uri))?;
                        w.at
                    };
                    ext.primitive(TAG_OCTET_STRING, &value[..len])
                })
            })
        })
    }

    /// The extensions an authority's own certificate carries.
    ///
    /// `cA TRUE` with `pathLenConstraint` absent, and `keyCertSign`. A root
    /// that did not assert `cA` is a root nothing will chain to.
    pub fn ca_extensions(&mut self) -> Result<(), DerError> {
        self.constructed(TAG_CONTEXT_3, |explicit| {
            explicit.constructed(TAG_SEQUENCE, |extensions| {
                extensions.constructed(TAG_SEQUENCE, |ext| {
                    ext.oid(OID_BASIC_CONSTRAINTS)?;
                    ext.boolean(true)?;
                    let mut value = [0u8; 16];
                    let len = {
                        let mut w = Writer::new(&mut value);
                        w.constructed(TAG_SEQUENCE, |constraints| constraints.boolean(true))?;
                        w.len()
                    };
                    ext.primitive(TAG_OCTET_STRING, value.get(..len).ok_or(DerError::TooLong)?)
                })?;
                extensions.constructed(TAG_SEQUENCE, |ext| {
                    ext.oid(OID_KEY_USAGE)?;
                    ext.boolean(true)?;
                    // keyCertSign is bit 5; six unused bits after it.
                    ext.primitive(TAG_OCTET_STRING, &[TAG_BIT_STRING, 0x02, 0x01, 0x04])
                })
            })
        })
    }

    /// The `TBSCertificate` an authority's own certificate is signed over.
    ///
    /// Issuer and subject are the same name — that is what self-signed means,
    /// and a verifier reads the pair to decide it is looking at a root.
    pub fn ca_certificate(
        &mut self,
        serial: &[u8],
        name: &[u8],
        key: SubjectKey<'_>,
        algorithm: SigningAlgorithm,
        not_before: u64,
        not_after: u64,
    ) -> Result<(), DerError> {
        self.constructed(TAG_SEQUENCE, |tbs| {
            tbs.constructed(TAG_CONTEXT_0, |version| version.integer(&[0x02]))?;
            tbs.integer(serial)?;
            tbs.signature_algorithm(algorithm)?;
            tbs.common_name(name)?;
            tbs.constructed(TAG_SEQUENCE, |validity| {
                validity.time(not_before)?;
                validity.time(not_after)
            })?;
            tbs.common_name(name)?;
            match key {
                SubjectKey::Ed25519(k) => tbs.ed25519_spki(k)?,
                SubjectKey::P256(point) => tbs.p256_spki(point)?,
            }
            tbs.ca_extensions()
        })
    }

    /// The `TBSCertificate` a leaf is signed over.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fields are X.509's, not ours; a struct would carry the \
                  same eight and cost a copy on a no-allocator target"
    )]
    pub fn tbs_certificate(
        &mut self,
        serial: &[u8],
        issuer_cn: &[u8],
        subject_cn: &[u8],
        subject_key: SubjectKey<'_>,
        algorithm: SigningAlgorithm,
        not_before: u64,
        not_after: u64,
        san_uri: &[u8],
    ) -> Result<(), DerError> {
        self.constructed(TAG_SEQUENCE, |tbs| {
            // version: v3, explicit [0].
            tbs.constructed(TAG_CONTEXT_0, |version| version.integer(&[0x02]))?;
            tbs.integer(serial)?;
            // The TBS names the signature algorithm too, and a verifier that
            // found it disagreeing with the outer one would be looking at a
            // certificate somebody had edited.
            tbs.signature_algorithm(algorithm)?;
            tbs.common_name(issuer_cn)?;
            tbs.constructed(TAG_SEQUENCE, |validity| {
                validity.time(not_before)?;
                validity.time(not_after)
            })?;
            tbs.common_name(subject_cn)?;
            match subject_key {
                SubjectKey::Ed25519(key) => tbs.ed25519_spki(key)?,
                SubjectKey::P256(point) => tbs.p256_spki(point)?,
            }
            tbs.leaf_extensions(san_uri)
        })
    }
}

fn two(out: &mut [u8], at: &mut usize, value: u64) {
    let tens = b'0' + u8::try_from(value / 10 % 10).unwrap_or(0);
    let units = b'0' + u8::try_from(value % 10).unwrap_or(0);
    if let Some(slot) = out.get_mut(*at) {
        *slot = tens;
    }
    if let Some(slot) = out.get_mut(*at + 1) {
        *slot = units;
    }
    *at += 2;
}

/// Civil date-time from a Unix timestamp, proleptic Gregorian.
///
/// Howard Hinnant's `civil_from_days`, which is exact for every day this
/// encoding can represent and needs no table.
fn civil_from_unix(unix_seconds: u64) -> Result<(u64, u64, u64, u64, u64, u64), DerError> {
    let days = i64::try_from(unix_seconds / 86_400).map_err(|_| DerError::BadTime)?;
    let secs_of_day = unix_seconds % 86_400;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    let year = u64::try_from(year).map_err(|_| DerError::BadTime)?;
    let month = u64::try_from(m).map_err(|_| DerError::BadTime)?;
    let day = u64::try_from(d).map_err(|_| DerError::BadTime)?;
    Ok((
        year,
        month,
        day,
        secs_of_day / 3600,
        secs_of_day / 60 % 60,
        secs_of_day % 60,
    ))
}
