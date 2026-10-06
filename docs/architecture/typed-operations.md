# Typed operations

A typed operation is a kagi module that takes one `auth_wire` request
message and answers it with one `auth_wire` answer message, and that other
projects compose: a pipeline builds the request bytes and branches on the
answer, and never sees a key, a signature or a claim it did not ask for.

| Module | Request types | Answer types |
|---|---|---|
| `token_verify` | `MSG_VERIFY_REQ` 0x42 | `MSG_VERIFY_RESP` 0x43 |
| `mint_admission` | `MSG_ADMIT_REQ` 0x35, `MSG_GRANT_REQ` 0x37 | `MSG_ADMIT_RESP` 0x36, `MSG_GRANT_RESP` 0x38 |
| `authcode` | `MSG_AUTHORIZE_REQ` 0x39, `MSG_CODE_EXCHANGE_REQ` 0x3B | `MSG_AUTHORIZE_RESP` 0x3A, `MSG_CODE_EXCHANGE_RESP` 0x3C |
| `token_mint` | `MSG_MINT_REQ` 0x31 | `MSG_MINT_RESP` 0x32 |
| `storage_key` | `msg::REQUEST` 0x80 | `msg::REPLY` 0x81 |

Each is a PROVIDER of the workspace exchange contract (fluxor's
`contracts/exchange.rs`; `docs/architecture/exchange.md` in fluxor): it
reads `request_in` (`ExchangeRequest`) and writes `response_out`
(`ExchangeResponse`). Any requester drives it — a chronicle pipeline, a kagi
endpoint, or wave's `http` on an app route, which is how the e2e suites drive
every one of them. The shared provider and requester code is
`modules/common/typed_exchange.rs`.

## The exchange

**Request.** One request HEAD (and BODY records under credit, if the body
does not fit the HEAD):

- `method` = `POST` (3).
- `target`, `headers` and `peer` are not read. They are bounded — target at
  most 256 bytes, headers at most 1024 — so the module can sit behind an HTTP
  route as well as a pipeline.
- `resp_credit` at least **8171** bytes (`ANSWER_CREDIT`: one record's body
  after a response HEAD with an empty content type). Every answer is one
  record, written once the decision is made, and a provider that had to wait
  for credit after deciding would be holding a verdict it could not deliver.
- The body is exactly ONE `auth_wire` envelope:

  ```text
  [msg_type u8][len u16 LE][payload: len bytes]     where len = body length - 3
  ```

  The envelope stays inside the body because its type byte is what tells
  `authorize` from `code exchange` on `authcode`'s one port, and `admit` from
  `grant` on `mint_admission`'s. A body with bytes past the envelope, or
  short of it, is not a message.

The exchange id is the correlation. None of these messages carries a
correlation field of its own: the provider echoes the requester's 14-byte id
verbatim on its answer, and that is the only matching there is.

**Answer.** One response HEAD, no `MORE`, empty content type, no headers:

| Status | When | Body |
|---|---|---|
| 200 | the operation produced its typed answer — **a refusal verdict included** | the answer envelope |
| 400 | the method is not `POST`; the body is not exactly one envelope of a request type this operation takes; `resp_credit` is below 8171 | empty |
| 413 | target over 256, headers over 1024, or the body over the operation's bound (below) | empty |
| 500 | the answer did not fit one record (the operation's own failure) | empty |
| 503 | the provider already holds four exchanges being collected | empty |

A request whose envelope is well framed but whose payload does not decode is
read by the operation, and answered **200 with the operation's own
`MALFORMED` verdict**. 400 means "this is not a request"; a `MALFORMED`
verdict means "this request does not say anything I can act on".

Body bounds: `token_verify` 8192 bytes; `token_mint`, `mint_admission` and
`authcode` 4099 (a 4096-byte payload and its envelope); `storage_key` 2052.

## Field encodings

All multi-byte integers are little-endian.

| Notation | Bytes |
|---|---|
| `u8` / `u16` / `u32` / `u64` | 1 / 2 / 4 / 8 bytes, LE |
| `f8` | `[len u8][len bytes]` |
| `f16` | `[len u16 LE][len bytes]` |

The tables below give each payload's fields in order. Offsets are from the
start of the payload, i.e. the body offset minus 3; where a field follows a
variable-length one its offset is written in terms of the lengths before it
(`c` = the credential's length, and so on). A payload decodes exactly these
fields in this order; bytes after the last field are not read.

## token_verify

Ports: `request_in` in[0], `response_out` out[0], `verify_key` in[1]
(`MSG_KEY_ADD` / `ACTIVATE` / `RETIRE` / `REMOVE` / `KEYSET_SNAPSHOT` — an
operator input, a byte stream of envelopes, not an exchange). No params.

### `MSG_VERIFY_REQ` 0x42

| Offset | Field | Encoding | Meaning |
|---|---|---|---|
| 0 | `credential` | f16 | the compact JWS |
| 2+c | `expected_profile` | u16 | required profile, 0 = no rule |
| 4+c | `expected_issuer` | f16 | required `iss`, empty = no rule |
| 6+c+i | `expected_audience` | f16 | required `aud`, empty = no rule |
| 8+c+i+a | `method` | f8 | the method a proof is bound to; empty when none |
| 9+c+i+a+m | `uri` | f16 | the URI a proof is bound to; empty when none |
| 11+c+i+a+m+u | `min_assurance` | u8 | floor: 0 aal1, 1 aal2, 2 aal3 |
| 12+c+i+a+m+u | `now_unix_secs` | u64 | carried; the module reads its own trusted clock |
| 20+c+i+a+m+u | `time_source_class` | u8 | carried |
| 21+c+i+a+m+u | `time_flags` | u8 | carried |

Payload length `22 + c + i + a + m + u`.

### `MSG_VERIFY_RESP` 0x43

| # | Field | Encoding |
|---|---|---|
| 1 | `status` | u8 — `verify_err` |
| 2 | `profile_id` | u16 |
| 3 | `issuer` | f16 |
| 4 | `kid` | f8 |
| 5 | `suite` | u16 |
| 6 | `subject` | f16 |
| 7 | `thumbprint_alg` | u8 — 0 none, 1 JWK SHA-256 |
| 8 | `key_thumbprint` | f8 |
| 9 | `audience` | f16 |
| 10 | `scope` | f16 |
| 11 | `issued_at` | u64 |
| 12 | `expires_at` | u64 |
| 13 | `auth_time` | u64 |
| 14 | `evidence.methods` | u16 — the `assurance` method bitset |
| 15 | `evidence.key_binding` | u8 |
| 16 | `evidence.flags` | u8 |
| 17 | `evidence.auth_time` | u64 |
| 18 | `credential_id` | f8 — the `jti` |
| 19 | `replay_id` | f8 |
| 20 | `application` | f16 — non-reserved claims, opaque, never an authorization input |

`status` is at payload offset 0 and `subject` at
`8 + issuer_len + kid_len`. A refusal carries every identity field empty or
zero — a refusal with a subject or scope does not decode — so a refusal
payload is exactly 56 bytes.

`verify_err`: 0 OK, 1 MALFORMED, 2 NO_KEY, 3 UNKNOWN_KID, 4 BAD_SIGNATURE,
5 EXPIRED, 6 SUITE_MISMATCH, 7 WRONG_AUDIENCE, 8 WRONG_ISSUER,
9 WRONG_PROFILE, 10 INSUFFICIENT_ASSURANCE, 11 NO_CLOCK. With no key loaded
every request is answered NO_KEY before its payload is decoded.

## mint_admission

Ports: `request_in` in[0], `response_out` out[0]; `verify_key` in[1] (the
device-certificate keyset, an operator input); `state_requests` out[1] /
`state_replies` in[2] (the ledger, module-private); `mint_out` out[2] /
`mint_in` in[3] — on these, admission is the REQUESTER of `token_mint`'s
exchange, used by `GRANT_REQ`. Params: `iss` (1, str), `aud` (2, str),
`scope` (3, str), `ttl_seconds` (4, u32), `suite` (5, credential suite id,
default 2 = Ed25519) — grant-mode policy, never client-supplied.

### `MSG_ADMIT_REQ` 0x35 and `MSG_GRANT_REQ` 0x37

The same payload:

| Offset | Field | Encoding |
|---|---|---|
| 0 | `method` | f8 — the request the DPoP proof is bound to |
| 1+m | `uri` | f16 |
| 3+m+u | `credential` | f16 — the device certificate (compact JWS) |
| 5+m+u+c | `proof` | f16 — the DPoP proof |
| 7+m+u+c+p | `otp` | f8 — a one-time code, or empty |

Payload length `8 + m + u + c + p + o`. An `ADMIT_REQ` with an empty method,
credential or proof does not decode, and is answered `MALFORMED`; a
`GRANT_REQ` with an empty credential decodes and is answered
`UNAUTHENTICATED`.

### `MSG_ADMIT_RESP` 0x36

| # | Field | Encoding |
|---|---|---|
| 1 | `status` | u8 — `admit_err` |
| 2 | `sub` | f16 |
| 3 | `device_id` | f16 |
| 4 | `thumbprint_alg` | u8 |
| 5 | `jkt` | f8 — exactly the length `thumbprint_alg` produces (43 for SHA-256) |
| 6 | `evidence.methods` | u16 |
| 7 | `evidence.key_binding` | u8 |
| 8 | `evidence.flags` | u8 |
| 9 | `evidence.auth_time` | u64 |

A refusal carries `sub`, `device_id` and `jkt` empty (it does not decode
otherwise): a refusal payload is `[status][0,0][0,0][alg][0]` and twelve
evidence bytes, 19 bytes.

### `MSG_GRANT_RESP` 0x38

| Offset | Field | Encoding |
|---|---|---|
| 0 | `status` | u8 — `grant_err` |
| 1 | `token` | f16 — the access token on OK, empty on every refusal |

`admit_err`: 0 OK, 1 UNAUTHENTICATED, 2 UNKNOWN_DEVICE, 3 REVOKED,
4 NOT_PERMITTED, 5 STALE_PROOF, 6 REPLAY, 7 STATE_UNAVAILABLE, 8 NO_CLOCK,
9 NO_KEY, 10 MALFORMED. `grant_err` is the same numbers plus 20
MINT_FAILED (admitted, then the signing failed — a 5xx, never the
presenter's fault).

## authcode

Ports: `request_in` in[0], `response_out` out[0]; `verify_key` in[1];
`state_requests` out[1] / `state_replies` in[2]; `mint_out` out[2] /
`mint_in` in[3] (authcode is the REQUESTER of `token_mint`'s exchange).
Params: `iss` (1, str), `aud` (2, str), `ttl_seconds` (3, u32),
`id_ttl_seconds` (4, u32), `suite` (5, default 2 = Ed25519).

### `MSG_AUTHORIZE_REQ` 0x39

| # | Field | Encoding |
|---|---|---|
| 1 | `method` | f8 |
| 2 | `uri` | f16 |
| 3 | `credential` | f16 — the subject's device certificate |
| 4 | `proof` | f16 — its DPoP proof |
| 5 | `client_id` | f8 |
| 6 | `redirect_uri` | f16 |
| 7 | `scope` | f16 — a request, clamped to the client's registered scope |
| 8 | `state` | f16 |
| 9 | `code_challenge` | f8 — PKCE S256, 43 characters |
| 10 | `nonce` | f16 — may be empty |

### `MSG_AUTHORIZE_RESP` 0x3A

| Offset | Field | Encoding |
|---|---|---|
| 0 | `status` | u8 — `authz_err` |
| 1 | `code` | f16 — the single-use code on OK |
| 3+k | `redirect_uri` | f16 — the REGISTERED redirect URI on OK |
| 5+k+r | `state` | f16 — echoed on OK |

A refusal carries all three empty: the payload is `[status][0,0][0,0][0,0]`.

### `MSG_CODE_EXCHANGE_REQ` 0x3B

| Offset | Field | Encoding |
|---|---|---|
| 0 | `code` | f16 |
| 2+k | `redirect_uri` | f16 |
| 4+k+r | `client_id` | f8 |
| 5+k+r+i | `code_verifier` | f16 |

### `MSG_CODE_EXCHANGE_RESP` 0x3C

| Offset | Field | Encoding |
|---|---|---|
| 0 | `status` | u8 — `authz_err` |
| 1 | `access_token` | f16 |
| 3+a | `id_token` | f16 |

OK carries both tokens; a refusal neither (`[status][0,0][0,0]`).

`authz_err`: 0 OK, 1 UNAUTHENTICATED, 2 UNKNOWN_CLIENT, 3 BAD_REDIRECT,
4 NO_PKCE, 5 INVALID_GRANT, 6 PKCE_FAILED, 7 MISMATCH, 8 STATE_UNAVAILABLE,
9 NO_CLOCK, 10 NO_KEY, 11 MALFORMED, 12 REPLAY, 20 MINT_FAILED.

## token_mint

Ports: `request_in` in[0], `response_out` out[0]; `key_material` in[1] (the
signing keyset by vault label, an operator input); `key_announce` out[1] (the
public half of each signing key, as a VERIFY `MSG_KEY_ADD`). Param: `posture`
(1: `development` | `production`; undeclared refuses to construct).

### `MSG_MINT_REQ` 0x31

| Offset | Field | Encoding |
|---|---|---|
| 0 | `request_type` | u8 — 1 MINT, 2 REISSUE, 3 SIGN_CHALLENGE |
| 1 | `suite` | u16 — credential suite id |
| 3 | `profile_id` | u16 |
| 5 | `kid` | f8 — empty = the profile's ACTIVE key |
| 6+k | `ttl_seconds` | u32 |
| 10+k | `iss` | f16 |
| 12+k+i | `sub` | f16 |
| 14+k+i+s | `aud` | f16 |
| 16+k+i+s+a | `scope` | f16 |
| 18+k+i+s+a+c | `thumbprint_alg` | u8 — 0 none |
| 19+k+i+s+a+c | `jkt` | f8 — empty when `thumbprint_alg` is 0, else exactly its length |
| 20+k+i+s+a+c+j | `extra_count` | u8 — at most 32 |

then `extra_count` claims, each `[key f8][valtype u8][value f16]` with
valtype 1 Str, 2 U64 (an 8-byte LE value inside its f16), 3 Bool (one 0/1
byte), 4 Raw JSON.

### `MSG_MINT_RESP` 0x32

| Offset | Field | Encoding |
|---|---|---|
| 0 | `status` | u8 — `mint_err` |
| 1 | `delivery` | u8 — 0 inline, 1 object handle |
| 2 | `required_len` | u32 — the credential's true length, whatever the delivery |
| 6 | `body` | f16 — the compact JWS on OK; empty on every refusal |

An answer carries a token of up to 4096 bytes in one record; a larger one is
refused `TOO_LARGE` with `required_len` saying how large.

`mint_err`: 0 OK, 1 MALFORMED, 2 NO_KEY, 3 UNKNOWN_KID,
4 UNSUPPORTED_SUITE, 5 SUITE_NOT_PERMITTED, 6 UNSUPPORTED_PROFILE,
7 TOO_LARGE, 8 SIGN_FAILED, 9 TTL_TOO_LONG.

## storage_key

Ports: `request_in` in[0], `response_out` out[0]; `signing_key` in[1];
`ledger_out` out[1] / `ledger_in` in[2]; `custodian_out` out[2] /
`custodian_in` in[3] (the addressed order bus to the three custodians,
module-private); `key_announce` out[3]. Param: `iss` (1, str).

`msg::REQUEST` 0x80 payload: `[op u8][resource kind u8][resource 16][body]`;
`msg::REPLY` 0x81 payload: `[op u8][status u8][refusal u8][audited u8]
[record f16][bundle f16][extra f16]`. The operations, their bodies and the
refusal codes are in [storage-key.md](storage-key.md).

## Requesters inside kagi

Kagi's own modules drive these operations through the same contract, as
requesters (`typed_exchange::write_call` / `read_answer`):

| Requester | Ports | Provider |
|---|---|---|
| `token_endpoint` | `admit_out` / `admit_in` | `mint_admission` |
| `token_endpoint` | `mint_out` / `mint_in` | `token_mint` |
| `mint_admission` | `mint_out` / `mint_in` | `token_mint` |
| `authcode` | `mint_out` / `mint_in` | `token_mint` |
| `storage_key_endpoint` | `service_out` / `service_in` | `storage_key` |
| `enrollment_endpoint` | `mail_out` / `mail_in` | wave's `smtp` |

A requester's exchange id is its counter followed by the channel handle of
its own request port (`typed_exchange::call_id`), so two requesters wired to
one provider — whose `response_out` fans out to both — never choose the same
id, and each takes only the answers to the exchanges it opened. A call ending
without a typed answer (a provider status, an ABORT) fails the request that
was waiting on it; a provider's LINK DOWN fails every call open to it and
refuses new ones until LINK UP.
