//! A `storage.object` read that may have to wait, held across steps.
//!
//! The contract lets `GET`, `HEAD` and `RANGE_GET` answer `EAGAIN`: not
//! yet, ask again. That answer is not absence and not failure, and a
//! consumer that reports it as either decides something the store never
//! said — on the board, where lattice's store really does answer it, an
//! `EAGAIN` read as `ST_UNAVAILABLE` refuses a credential against a record
//! that exists, and one read as `ENXIO` would issue against a record that
//! is merely slow.
//!
//! So a read is a step machine, and this fragment is its decisions, kept
//! apart from the provider calls so a host can drive them with a provider
//! that waits on demand. Three stages, in the module note's order — `HEAD`
//! for the etag, `GET` for a handle, `RANGE_GET` for the body:
//!
//! - `HEAD` `EAGAIN`: nothing was written. Ask `HEAD` again on a later step.
//! - `GET` `EAGAIN`: no handle was opened. Ask `GET` again on a later step;
//!   the `HEAD` already answered stands, because a writer landing in the
//!   gap pairs a stale etag with a fresh value, which only fails the
//!   caller's next compare-and-swap.
//! - `RANGE_GET` `EAGAIN`: nothing was copied and the handle stays valid.
//!   The handle is HELD and the same `RANGE_GET` asked again on a later
//!   step — never a second `GET`, which abandons the fetch in flight and,
//!   against a provider serving one fetch per handle, never terminates.
//!
//! A read that waits decides nothing: [`Read::Held`] carries no status, and
//! the caller answers its requester nothing until a later step's answer.
//! Each stage is asked at most once per [`ObjectRead::step`], and stages
//! only move forward, so a step never spins on a provider that frees room
//! only between steps.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::auth_wire;

/// `EAGAIN` from a read: not yet, ask again.
pub const EAGAIN: i32 = -11;
/// `ENXIO`: the key is absent.
pub const ENXIO: i32 = -6;

const STAGE_IDLE: u8 = 0;
const STAGE_HEAD: u8 = 1;
const STAGE_GET: u8 = 2;
const STAGE_RANGE: u8 = 3;

/// What the caller makes of a `HEAD` record that answered.
pub enum HeadView {
    /// The record parsed, its view is strong enough to decide on, and the
    /// body is this many bytes.
    Size(u64),
    /// The view it was served from is below the namespace's read floor.
    TooWeak,
    /// The record does not parse.
    Unreadable,
}

/// The provider, as a read sees it. Each method is ONE ask.
pub trait ObjectReads {
    /// `HEAD` the read's key: bytes written, or a negative errno.
    fn head(&mut self) -> i32;
    /// Judge the `HEAD` record `head` just answered with `n` bytes.
    fn view(&mut self, n: usize) -> HeadView;
    /// Parse only the etag out of the `HEAD` record just answered: its
    /// length, or `None` when it does not parse.
    fn etag(&mut self, n: usize) -> Option<usize>;
    /// `GET` the read's key: a handle, or a negative errno.
    fn open(&mut self) -> i32;
    /// `RANGE_GET` `len` bytes from offset 0 of `handle` into the caller's
    /// value buffer: bytes copied, or a negative errno.
    fn range(&mut self, handle: i32, len: usize) -> i32;
    /// `CLOSE` `handle`.
    fn close(&mut self, handle: i32);
}

/// Where a read stands after a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// The provider has not answered. Nothing is decided and nothing may be
    /// answered: ask again on a later step.
    Held,
    /// The body, this many bytes, is in the caller's value buffer.
    Found(usize),
    /// The key is absent.
    Absent,
    /// Served from a view too weak to decide on.
    TooWeak,
    /// The store failed to answer — never "not yet", never "absent".
    Unavailable,
}

impl Read {
    /// The status the requester is owed, or `None` while the read is held.
    pub fn status(self) -> Option<u8> {
        match self {
            Self::Held => None,
            Self::Found(_) => Some(auth_wire::ST_OK),
            Self::Absent => Some(auth_wire::ST_NOT_FOUND),
            Self::TooWeak | Self::Unavailable => Some(auth_wire::ST_UNAVAILABLE),
        }
    }
}

/// One read in flight: its stage, the handle it holds, and the body size
/// the `HEAD` announced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectRead {
    stage: u8,
    handle: i32,
    want: usize,
}

impl ObjectRead {
    /// No read in flight.
    pub const fn idle() -> Self {
        Self {
            stage: STAGE_IDLE,
            handle: -1,
            want: 0,
        }
    }

    /// A read about to ask its `HEAD`.
    pub const fn start() -> Self {
        Self {
            stage: STAGE_HEAD,
            handle: -1,
            want: 0,
        }
    }

    /// True while a read is in flight (held or about to be asked).
    pub const fn live(&self) -> bool {
        self.stage != STAGE_IDLE
    }

    /// The handle this read holds, or -1.
    pub const fn handle(&self) -> i32 {
        self.handle
    }

    /// Advance the read as far as the provider answers this step. `cap` is
    /// the caller's value buffer. Anything but [`Read::Held`] ends the read
    /// (its handle closed) and leaves it idle.
    pub fn step<P: ObjectReads>(&mut self, p: &mut P, cap: usize) -> Read {
        if self.stage == STAGE_HEAD {
            let rc = p.head();
            if rc == EAGAIN {
                return Read::Held;
            }
            if rc < 0 {
                return self.end(
                    p,
                    if rc == ENXIO {
                        Read::Absent
                    } else {
                        Read::Unavailable
                    },
                );
            }
            let Ok(n) = usize::try_from(rc) else {
                return self.end(p, Read::Unavailable);
            };
            match p.view(n) {
                HeadView::TooWeak => return self.end(p, Read::TooWeak),
                HeadView::Unreadable => return self.end(p, Read::Unavailable),
                HeadView::Size(size) => match usize::try_from(size) {
                    Ok(want) if want <= cap => {
                        self.want = want;
                        self.stage = STAGE_GET;
                    }
                    _ => return self.end(p, Read::Unavailable),
                },
            }
        }
        if self.stage == STAGE_GET {
            let h = p.open();
            if h == EAGAIN {
                return Read::Held;
            }
            if h < 0 {
                return self.end(p, Read::Unavailable);
            }
            self.handle = h;
            self.stage = STAGE_RANGE;
        }
        if self.stage == STAGE_RANGE {
            let n = p.range(self.handle, self.want);
            if n == EAGAIN {
                // Nothing copied; the handle stays valid and is kept.
                return Read::Held;
            }
            let got = usize::try_from(n).ok().filter(|&got| got <= self.want);
            return self.end(p, got.map_or(Read::Unavailable, Read::Found));
        }
        Read::Unavailable
    }

    /// Settle the read: close any handle it holds and go idle.
    fn end<P: ObjectReads>(&mut self, p: &mut P, out: Read) -> Read {
        if self.handle >= 0 {
            p.close(self.handle);
        }
        *self = Self::idle();
        out
    }
}

/// The etag a decided write produced, re-read by `HEAD` so the caller can
/// chain a compare-and-swap without another round trip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Etag {
    /// The `HEAD` answered `EAGAIN`: the write's reply is held, unsent, and
    /// the `HEAD` asked again on a later step. An `ST_OK` with an empty
    /// etag would tell the caller there is nothing to chain against.
    Held,
    /// This many etag bytes are in the caller's etag buffer.
    Found(usize),
    /// The `HEAD` answered and named no etag: the write stands, unchained.
    None,
}

/// Ask the post-write `HEAD` once.
pub fn etag_after_write<P: ObjectReads>(p: &mut P) -> Etag {
    let rc = p.head();
    if rc == EAGAIN {
        return Etag::Held;
    }
    match usize::try_from(rc) {
        Ok(n) if n > 0 => p.etag(n).map_or(Etag::None, Etag::Found),
        _ => Etag::None,
    }
}
