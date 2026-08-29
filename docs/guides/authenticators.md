# Authenticators and assurance

Kagi accepts several kinds of proof and tells the relying party which one
it got. This page describes the authenticators, how they combine into an
assurance level, and how a service built on kagi asks for more.

Source: `modules/common/assurance.rs`, `modules/common/recovery.rs`,
`modules/common/totp.rs`, `modules/common/webauthn.rs`, and
`modules/app/resource_gate` for the enforcing half.

## The shape of the problem

Email possession is a good way to bind a *first* device and a poor way to
authenticate afterwards. It is a bearer channel, it can be phished, and
it puts the security of an account in the hands of whoever runs the
tenant's mail. A device key held in a secure enclave has none of those
properties.

Kagi therefore treats the inbox as a bootstrap and the device key as the
credential. What makes that workable is the device *set*: an enrolled
device can vouch for the next one, so replacing a phone does not mean
falling back to the weakest proof in the system.

```text
  first device      email or bootstrap token, plus a new device key
  later devices     an enrolled device signs a cross-attestation
  every device lost a recovery code
```

## Authenticators

| Kind | What it proves | Recorded as |
| --- | --- | --- |
| Email possession | control of an inbox at enrollment | `email` |
| Bootstrap token | operator admission of a node or workload | `bootstrap` |
| Software device key | possession of a key that could be exported | `swk` |
| Hardware device key | possession of a non-exportable key | `hwk` |
| Authenticator app | a time-based one-time code | `otp` |
| Passkey | a `WebAuthn` assertion bound to this origin | `webauthn` |
| Recovery code | possession of something kept offline | `recovery` |

Every one of them also emits `pop` when a key signed for the request, and
`user` when the authenticator verified the person before signing.

### Authenticator apps

`modules/common/totp.rs` implements RFC 4226 and RFC 6238 with the HMAC
primitive injected, as with every other fragment, so the same code
derives a code on the host, on a Pi, and in the browser. Any standard
authenticator app interoperates: the shared secret is exchanged as
unpadded RFC 4648 base32, which is what an `otpauth://` provisioning URI
carries.

Two properties matter beyond deriving the right digits. Verification
sweeps a window either side of the current step so a client with a drifting
clock still authenticates, and it reports the step that matched so the
caller can refuse that step afterwards. Without the second part a code
stays valid for the rest of its own thirty seconds and can be replayed
inside that window.

### Passkeys

`modules/common/webauthn.rs` verifies both ceremonies. A registration is
checked for the challenge that was issued, an allowed origin, the
relying-party binding, and the user interaction the policy requires. An
assertion additionally verifies the signature over the authenticator data
and the client-data hash, and refuses a signature counter that has not
advanced, which is what a cloned authenticator looks like.

The origin check is the reason passkeys are worth the work. The signature
covers client data naming the origin the ceremony ran on, so an assertion
produced against a look-alike site does not verify at the real one.

Two limits, stated plainly. Attestation statements are parsed far enough
to read the credential out of them, and the `none` and `packed` formats
are recognised, but no attestation certificate chain is validated against
a metadata service: kagi does not tell you which authenticator model a
credential came from. And a passkey that syncs between a person's devices
is recorded as software-bound however capable the authenticator is,
because the credential exists on more than one device by design.

### Recovery codes

Recovery codes are derived, not stored: each is HKDF over a per-tenant
root with the code's index in the info string, rendered as sixteen base32
characters. The issuer therefore keeps one root per tenant instead of a
table of hashes, and the only mutable state is a bitmap of which codes
have been spent.

A redeemed code is capped at `aal1` whatever else it is combined with.
Recovery restores access; it does not reproduce the strength of the
authenticator that was lost. A recovery flow should enroll a fresh device
immediately.

## Assurance levels

Kagi scores the combination onto the NIST SP 800-63B ladder and puts the
result in `acr`, the methods in `amr`, and the time of the proof in
`auth_time`.

| Level | Reached by |
| --- | --- |
| `aal1` | a single factor, of any kind |
| `aal2` | two distinct factor categories, or one hardware key that verifies the user |
| `aal3` | a hardware-bound, origin-bound, user-verified authenticator |

What counts is distinct *categories*, not the number of entries in `amr`.
An inbox proof and a device key are both possession, so presenting both
is one factor twice, not two factors. A device key plus a code from an
authenticator app is possession plus knowledge, and reaches `aal2`.

A hardware key with no user verification is a single-factor cryptographic
authenticator: being non-exportable and origin-bound raises the cost of
stealing it, but it demonstrates the device rather than the person, so it
stays at `aal1` until a second factor joins it.

`mfa` appears in `amr` when the evidence reaches `aal2` or above. It is
derived from the other methods and cannot be asserted by a caller.

### Where the claims come from

Enrolment records what it proved — the channel that established control,
and where the device's key lives — in the device record. Admission reads
that back, adds the possession proof the request in front of it just made,
and hands both to the mint as `amr`, `acr` and `auth_time`. The level is
never stored: it is scored from the recorded facts at mint time by the same
fragment a relying party scores with, so a record written before a rung was
added still scores correctly under the ladder that has it.

`auth_time` is the possession proof, not the enrolment. A device that
enrolled last month and signed a proof a second ago authenticated a second
ago, and a policy asking for a recent proof should see that.

A deployment whose devices enrol by mailed code and present a DPoP proof
reaches `aal1`: both proofs are possession, which is one category however
many proofs are collected. Reaching `aal2` needs a genuinely different
factor. The `totp` fragment implements one, pinned against the RFC 4226 and
6238 vectors, and the `webauthn` fragment another, driven through ceremonies
assembled in the shapes a browser and authenticator produce — but neither
has a wired endpoint, so `aal2` is reachable by the ladder and not yet by
this deployment.

### A claim may not exceed its evidence

`acr` is a summary and `amr` is the evidence for it, so a credential naming
a level its own methods do not reach is refused — by `token_verify`, and by
`resource_gate` even where the deployment sets no floor at all. The
contradiction belongs to the credential, not to the policy reading it.

That is what makes the summary safe to read. A relying party can compare
`acr` against its floor without re-deriving the level, knowing the two ends
cannot disagree about a credential that passed.

## Asking for more

A relying party holds the policy; kagi never sees it. `AssurancePolicy`
evaluates the claims of a token whose signature, issuer, audience and
expiry have already been checked:

```rust
use assurance::{AssuranceLevel, AssurancePolicy, AuthMethod};

// One privileged operation: a strong proof, made in the last five minutes.
let transfer = AssurancePolicy::at_least(AssuranceLevel::Aal2).within(300);

// Or a specific method, whatever the level.
let unlock = AssurancePolicy::default().requiring(AuthMethod::Webauthn);

policy.evaluate(level, methods, auth_time, now)?;
```

A whole-surface floor needs no code: `resource_gate`'s `min_acr` and
`max_auth_age` params are the same policy, set in the graph.

Two behaviours are deliberate. A policy above the floor refuses a token
carrying no `acr` rather than guessing, so a token minted before a
deployment adopted these claims can never be read as a strong one. And
the default policy demands nothing, so a relying party that has not opted
in is unaffected.

When a request falls short, `resource_gate` answers 401 with an RFC 9470
step-up challenge naming what is needed:

```
WWW-Authenticate: DPoP error="insufficient_user_authentication",
                  error_description="…", acr_values="aal2"
```

A 403 would tell the client it may never perform the operation. The truth
is that it may, once it authenticates more strongly, and 401 with the
level attached is what lets a client act on that.

## Adding a device

An enrolled device authorises the next one by signing a cross-attestation:
a JWS with `cty=da+jwt`, naming the new key by its thumbprint, answering
a nonce the issuer minted, and addressed to this issuer. The signature is
verified against the key the directory already holds, never against a key
carried in the token.

The new device inherits nothing from the attester except the fact of
having been vouched for. Its own authenticator kind decides what its
tokens may claim: a phone that vouches for a laptop does not lend the
laptop its enclave.

Revoking a device retires everything it vouched for, transitively. A
device compromised while it was enrolling successors has extended the
compromise to all of them, so revoking it alone would leave the
attacker's device enrolled. Revoked records are kept rather than deleted,
because that chain is the evidence of what happened.

## What is deliberately absent

- **Secret-rotation plugins.** Rotating database and cloud credentials
  exists to paper over systems that only speak username and password.
  Everything in this stack presents a certificate or a token already.
- **SMS and push codes.** SIM swapping makes a phone number a weaker
  possession proof than the device key kagi already holds, so offering it
  as a second factor would lower assurance while appearing to raise it.
- **Passwords.** There is no password to phish, reuse, or store, which is
  what makes the inbox a bootstrap rather than a credential.
