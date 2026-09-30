//! The application side of wave's `http_app` exchange contract.
//!
//! One request and its response, both streamed, every record naming the
//! exchange it belongs to. What kagi's endpoints need of that is narrower
//! than the contract allows: collect a request until its body is complete,
//! answer it once. The collecting is here rather than in each endpoint
//! because ten modules keeping their own copy of an exchange id and a body
//! accumulator is ten places for them to drift — and the drift is silent,
//! because a half-parsed record looks like a request that never arrived.
//!
//! Responses are a single HEAD with the body inline. That is a deliberate
//! narrowing, not an oversight: every document this issuer serves is bounded
//! well below one record, and an endpoint that cannot say what it means in
//! one record answers 500 rather than streaming a partial truth. The server
//! grants response credit up front and refuses a head whose body exceeds it,
//! so [`write_response`] reports the overflow instead of emitting a record
//! that would abort the exchange.
//!
//! Pure `no_std`, no syscalls: the module moves bytes between its ports and
//! this, and a host suite drives the same code.

use crate::http_app::{
    app_kind, app_parse_request, app_write_credit, app_write_response_head, AppId, AppRecord,
    AppRequestHead, AppResponseHead, APP_BODY_MAX, APP_HDR, APP_RESP_HEAD_FIXED,
};

/// Exchanges collected at once. An endpoint answers a request as soon as it
/// is complete, so this is depth for requests arriving together rather than
/// a queue of work.
pub const MAX_EXCHANGES: usize = 8;
/// Longest request target held.
pub const MAX_TARGET: usize = 128;
/// Longest request header block held.
///
/// Sized from what these endpoints actually authenticate with, not from a
/// round number. A device-authenticated request presents TWO compact JWSs —
/// the device certificate in `Authorization` and the DPoP proof in `DPoP` —
/// each of which `device_auth` admits up to [`device_auth::MAX_SEGMENT`]. The
/// block also carries the ordinary request headers (`Host`, `Content-Type`,
/// `Content-Length`, `Connection`) and each value's own name and framing, so
/// the two credentials are the floor rather than the whole figure.
///
/// Getting this wrong is quiet: `Authorization` and `DPoP` together cross 1 KiB
/// comfortably, and a block over the limit is refused at the HEAD, before any
/// handler sees a path or a method. Every authenticated request on the endpoint
/// fails identically and the endpoint's own counters stay at zero, because from
/// its point of view no request ever arrived.
pub const MAX_HEADERS: usize = 2 * MAX_CREDENTIAL + 512;

/// Longest compact JWS a request may present in one header.
///
/// Mirrors `device_auth::MAX_SEGMENT`. Restated rather than imported because
/// not every endpoint that collects exchanges authenticates devices, and a
/// fragment that pulled `device_auth` in would make the whole authentication
/// surface a dependency of plain request collection. The two are pinned
/// together by an assertion in each endpoint that mounts both, so they cannot
/// drift apart in silence.
pub const MAX_CREDENTIAL: usize = 1024;
/// Longest request body collected. Past this the request is refused rather
/// than truncated: a body this issuer cannot see all of is one it must not
/// decide on.
pub const MAX_BODY: usize = 4096;

/// The largest response body one record can carry, once the head's own
/// fields are accounted for.
pub const MAX_RESPONSE_BODY: usize = APP_BODY_MAX - APP_RESP_HEAD_FIXED;

/// Why a request was not collected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refuse {
    /// No free slot: more exchanges arrived at once than this endpoint holds.
    Busy,
    /// The target, headers or body passed what is held here.
    TooLarge,
    /// A record that does not belong to a collected exchange, or arrived out
    /// of order.
    Unexpected,
}

impl Refuse {
    /// The status a caller is owed for this refusal.
    ///
    /// A refusal has to reach the client. An endpoint that drops one answers
    /// the request with silence, and silence is the one failure a caller cannot
    /// act on or report: it looks the same as a server that is simply slow, so
    /// the caller waits out its own timeout and no status anywhere records that
    /// a decision was made.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            // The endpoint is holding as many exchanges as it can. Nothing is
            // wrong with the request and it may be repeated.
            Self::Busy => 503,
            Self::TooLarge => 413,
            Self::Unexpected => 400,
        }
    }

    /// The JSON error body that goes with [`Refuse::status`].
    #[must_use]
    pub const fn body(self) -> &'static [u8] {
        match self {
            Self::Busy => br#"{"error":"temporarily_unavailable"}"#,
            Self::TooLarge => br#"{"error":"request_too_large"}"#,
            Self::Unexpected => br#"{"error":"invalid_request"}"#,
        }
    }
}

#[derive(Clone, Copy)]
struct Slot {
    live: bool,
    done: bool,
    id: AppId,
    method: u8,
    flags: u8,
    target: [u8; MAX_TARGET],
    target_len: u16,
    headers: [u8; MAX_HEADERS],
    headers_len: u16,
    body: [u8; MAX_BODY],
    body_len: u16,
    resp_credit: u32,
}

impl Slot {
    const EMPTY: Slot = Slot {
        live: false,
        done: false,
        id: AppId {
            origin: 0,
            conn: 0,
            stream: 0,
        },
        method: 0,
        flags: 0,
        target: [0; MAX_TARGET],
        target_len: 0,
        headers: [0; MAX_HEADERS],
        headers_len: 0,
        body: [0; MAX_BODY],
        body_len: 0,
        resp_credit: 0,
    };
}

/// A request whose body is complete.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub id: AppId,
    pub method: u8,
    pub target: &'a [u8],
    pub headers: &'a [u8],
    pub body: &'a [u8],
    /// Response body bytes the server has already granted.
    pub resp_credit: u32,
}

/// The exchanges this endpoint is collecting.
pub struct Table {
    slots: [Slot; MAX_EXCHANGES],
    /// A request-body credit this endpoint owes the server.
    ///
    /// Flow is credit-based in both directions: the server sends request-body
    /// bytes only up to what the application has granted. An endpoint that
    /// grants nothing is an endpoint whose POST bodies never arrive — and the
    /// symptom is not an error but a request that stays half-collected, so
    /// the grant is owed the moment an exchange opens with a body to come.
    grant: Option<(AppId, u32)>,
    /// A refusal owed to a caller, with the exchange it answers.
    ///
    /// Refusing is a decision, and a decision the caller never hears is worse
    /// than no decision at all: it is indistinguishable from a server that
    /// hung. Kept beside the grant and taken the same way, because this
    /// fragment does no I/O — whoever owns the port sends it.
    refusal: Option<(AppId, u32, Refuse)>,
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    #[must_use]
    pub const fn new() -> Self {
        Table {
            slots: [Slot::EMPTY; MAX_EXCHANGES],
            grant: None,
            refusal: None,
        }
    }

    fn find(&self, id: &AppId) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.live && same_exchange(&s.id, id))
    }

    /// Take one inbound record.
    ///
    /// `Ok(Some(i))` is an exchange whose request is complete: read it with
    /// [`Table::request`] and release it with [`Table::release`] once
    /// answered. `Ok(None)` is progress with nothing finished yet.
    pub fn accept(&mut self, record: &[u8]) -> Result<Option<usize>, Refuse> {
        let parsed = app_parse_request(record).ok_or(Refuse::Unexpected)?;
        match parsed {
            AppRecord::Head(head) => self.open(&head),
            AppRecord::Body { id, flags, data } => self.extend(&id, flags, data),
            // An abort ends the exchange: the peer is gone or the server
            // gave up, and an answer would have nowhere to go.
            AppRecord::Abort { id, .. } => {
                if let Some(i) = self.find(&id) {
                    self.slots[i] = Slot::EMPTY;
                }
                Ok(None)
            }
            // Credit raises what a response may carry. These endpoints
            // answer inside the opening grant, so there is nothing to
            // release — recorded so the figure stays true.
            AppRecord::Credit { id, bytes } => {
                if let Some(i) = self.find(&id) {
                    self.slots[i].resp_credit = self.slots[i].resp_credit.saturating_add(bytes);
                }
                Ok(None)
            }
            AppRecord::Datagram { .. } => Ok(None),
        }
    }

    fn open(&mut self, head: &AppRequestHead<'_>) -> Result<Option<usize>, Refuse> {
        if head.target.len() > MAX_TARGET || head.headers.len() > MAX_HEADERS {
            return Err(self.refuse(head.id, head.resp_credit, Refuse::TooLarge));
        }
        // A repeat HEAD for an exchange already open is the server
        // restarting it; take the newer one rather than two half-requests.
        let at = match self.find(&head.id) {
            Some(i) => i,
            None => match self.slots.iter().position(|s| !s.live) {
                Some(i) => i,
                None => return Err(self.refuse(head.id, head.resp_credit, Refuse::Busy)),
            },
        };
        let slot = &mut self.slots[at];
        *slot = Slot::EMPTY;
        slot.live = true;
        slot.id = head.id;
        slot.method = head.method;
        slot.flags = head.flags;
        slot.resp_credit = head.resp_credit;
        slot.target[..head.target.len()].copy_from_slice(head.target);
        slot.headers[..head.headers.len()].copy_from_slice(head.headers);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "both lengths were bounded above"
        )]
        {
            slot.target_len = head.target.len() as u16;
            slot.headers_len = head.headers.len() as u16;
        }
        // No `MORE` means no body follows, so the request is already whole.
        slot.done = head.flags & crate::http_app::app_flag::MORE == 0;
        if !slot.done {
            // The whole body this endpoint will hold, granted at once: it
            // answers in one record and has no use for a smaller window.
            let id = slot.id;
            self.grant = Some((id, MAX_BODY as u32));
        }
        Ok(if self.slots[at].done { Some(at) } else { None })
    }

    fn extend(&mut self, id: &AppId, flags: u8, data: &[u8]) -> Result<Option<usize>, Refuse> {
        let at = self.find(id).ok_or(Refuse::Unexpected)?;
        let slot = &mut self.slots[at];
        if slot.done {
            return Err(Refuse::Unexpected);
        }
        let have = usize::from(slot.body_len);
        let want = have.checked_add(data.len()).ok_or(Refuse::TooLarge)?;
        if want > MAX_BODY {
            // Refused, not truncated, and the slot goes: a decision on part
            // of a body is worse than no decision.
            let (id, credit) = (slot.id, slot.resp_credit);
            *slot = Slot::EMPTY;
            return Err(self.refuse(id, credit, Refuse::TooLarge));
        }
        slot.body[have..want].copy_from_slice(data);
        #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_BODY")]
        {
            slot.body_len = want as u16;
        }
        slot.done = flags & crate::http_app::app_flag::MORE == 0;
        Ok(if slot.done { Some(at) } else { None })
    }

    /// The complete request in slot `at`.
    #[must_use]
    pub fn request(&self, at: usize) -> Option<Request<'_>> {
        let slot = self.slots.get(at)?;
        if !slot.live || !slot.done {
            return None;
        }
        Some(Request {
            id: slot.id,
            method: slot.method,
            target: slot.target.get(..usize::from(slot.target_len))?,
            headers: slot.headers.get(..usize::from(slot.headers_len))?,
            body: slot.body.get(..usize::from(slot.body_len))?,
            resp_credit: slot.resp_credit,
        })
    }

    /// Free slot `at`, once its answer is away.
    pub fn release(&mut self, at: usize) {
        if let Some(slot) = self.slots.get_mut(at) {
            *slot = Slot::EMPTY;
        }
    }

    /// A request-body credit to write to the server, if one is owed.
    ///
    /// Taken by the module after every [`Table::accept`]: the fragment does
    /// no I/O, so the record it needs sent is handed back to whoever owns the
    /// port.
    pub fn take_grant(&mut self) -> Option<(AppId, u32)> {
        self.grant.take()
    }

    /// A refusal to answer, and the exchange it belongs to. `None` when the
    /// record that was refused named no exchange this could answer — an
    /// unparseable record has no id, so there is nowhere to send a status.
    pub fn take_refusal(&mut self) -> Option<(AppId, u32, Refuse)> {
        self.refusal.take()
    }

    /// Record a refusal against the exchange it answers, and hand the reason
    /// back for the `Err` that reports it.
    fn refuse(&mut self, id: AppId, credit: u32, why: Refuse) -> Refuse {
        self.refusal = Some((id, credit, why));
        why
    }

    /// Exchanges being collected.
    #[must_use]
    pub fn live(&self) -> usize {
        self.slots.iter().filter(|s| s.live).count()
    }
}

/// Two records belong to the same exchange when all three id fields agree. A
/// TCP connection and a QUIC session may hold the same number, which is why
/// `origin` is part of the identity rather than decoration.
fn same_exchange(a: &AppId, b: &AppId) -> bool {
    a.origin == b.origin && a.conn == b.conn && a.stream == b.stream
}

/// Write one response: a HEAD carrying the whole body.
///
/// `None` when the body does not fit one record or the credit granted, which
/// is the caller's cue to answer something it can say in one — the server
/// refuses a head whose body is beyond its grant, and a refused head is an
/// aborted exchange rather than a short answer.
pub fn write_response(
    id: &AppId,
    status: u16,
    content_type: &[u8],
    body: &[u8],
    resp_credit: u32,
    out: &mut [u8],
) -> Option<usize> {
    if body.len() > MAX_RESPONSE_BODY || u64::from(resp_credit) < body.len() as u64 {
        return None;
    }
    let head = AppResponseHead {
        id: *id,
        flags: 0,
        status,
        content_type,
        headers: &[],
        body,
    };
    app_write_response_head(&head, out)
}

/// Write a request-body credit record for the server.
pub fn write_grant(id: &AppId, bytes: u32, out: &mut [u8]) -> Option<usize> {
    app_write_credit(id, bytes, out)
}

/// Where a response body sits when it is built in place, for a content type
/// of `ct_len` bytes and no extra headers.
#[must_use]
pub const fn response_body_at(ct_len: usize) -> usize {
    APP_HDR + APP_RESP_HEAD_FIXED + ct_len
}

/// Seal a response whose body is already at [`response_body_at`].
///
/// The counterpart to the contract's `app_seal_body`, for the documents this
/// issuer renders straight into the outgoing record: a JWKS or a revocation
/// bitmap is built where it will be sent, and copying it through a second
/// buffer to call [`write_response`] would double the largest allocation in
/// the module for nothing.
pub fn seal_response(
    id: &AppId,
    status: u16,
    content_type: &[u8],
    body_len: usize,
    resp_credit: u32,
    out: &mut [u8],
) -> Option<usize> {
    if body_len > MAX_RESPONSE_BODY || u64::from(resp_credit) < body_len as u64 {
        return None;
    }
    let at = response_body_at(content_type.len());
    let end = at.checked_add(body_len)?;
    if end > out.len() || content_type.len() > u8::MAX as usize {
        return None;
    }
    // The head's own fields, then the content type, leaving the body where
    // the caller put it.
    let head = AppResponseHead {
        id: *id,
        flags: 0,
        status,
        content_type,
        headers: &[],
        body: &[],
    };
    app_write_response_head(&head, out)?;
    Some(end)
}

/// The record kinds this fragment answers, for a module deciding whether a
/// frame on its request port is one of ours.
#[must_use]
pub const fn is_request_record(kind: u8) -> bool {
    matches!(
        kind,
        app_kind::HEAD | app_kind::BODY | app_kind::ABORT | app_kind::CREDIT | app_kind::DATAGRAM
    )
}

/// A record's kind byte, or `None` when it is too short to have one.
#[must_use]
pub fn record_kind(record: &[u8]) -> Option<u8> {
    if record.len() < APP_HDR {
        return None;
    }
    record.first().copied()
}

/// One outbound record staged and not yet placed on its port.
///
/// A response cannot be un-built, and `channel_write` on an edge that has no
/// room places nothing and says so. Letting that drop the record answers the
/// request with silence: the client waits out its own timeout and the only
/// evidence is a connection that went quiet, which is indistinguishable from a
/// hung server. Every refusal to write is therefore a reason to HOLD, and the
/// step loop retries before it reads anything else — which is what makes the
/// listener's back-pressure reach the place that governs the exchange instead
/// of being absorbed as a lost answer.
///
/// One slot is enough because a request record produces at most one outbound
/// record. [`Table::accept`] grants body credit exactly when the HEAD says a
/// body follows, and hands back a slot index exactly when it does not — so a
/// grant and a response can never arise from the same record.
///
/// The bytes live in the caller's own buffer; this holds only how many of them
/// are owed. A second record offered while one is held would overwrite it, so
/// [`Outbox::send`] refuses instead — and says so by returning false, which is
/// the same answer as "held", because in both cases the caller's record has not
/// been sent.
#[derive(Clone, Copy, Default)]
pub struct Outbox {
    len: usize,
}

impl Outbox {
    #[must_use]
    pub const fn new() -> Self {
        Self { len: 0 }
    }

    /// Place `len` bytes of `buf` now, or hold them for the step loop to retry.
    ///
    /// The common case is a write that lands, so it is tried first: holding
    /// every answer for a later step would add a step of latency to every
    /// request to protect against the case that is rare. True when the record
    /// is away, false when it is owed — which is not a failure, only a record
    /// that has not left yet.
    ///
    /// # Safety
    ///
    /// `sys` must be a valid syscall table per the module ABI, and `buf` must
    /// keep holding the record until [`Outbox::flush`] reports the slot clear.
    pub unsafe fn send(
        &mut self,
        sys: &crate::abi::SyscallTable,
        chan: i32,
        buf: &[u8],
        len: usize,
    ) -> bool {
        if self.len != 0 || len == 0 || len > buf.len() {
            return false;
        }
        if (sys.channel_write)(chan, buf.as_ptr(), len) > 0 {
            return true;
        }
        self.len = len;
        false
    }

    /// Try to place what is held, and report whether the slot is now clear.
    ///
    /// # Safety
    ///
    /// `sys` must be a valid syscall table per the module ABI, and `buf` must
    /// still hold the record that was staged.
    pub unsafe fn flush(&mut self, sys: &crate::abi::SyscallTable, chan: i32, buf: &[u8]) -> bool {
        if self.len == 0 {
            return true;
        }
        if self.len <= buf.len() && (sys.channel_write)(chan, buf.as_ptr(), self.len) > 0 {
            self.len = 0;
        }
        self.len == 0
    }
}
