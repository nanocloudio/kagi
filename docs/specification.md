# Stateless Email-Bound Authentication with Device Binding  
**Specification v1.0**

---

## 1. Overview

This document defines a **stateless authentication mechanism** based on:

- Email verification via signed, short-lived challenges (magic link or code).
- Device-bound key pairs held in secure storage on the client.
- Proof-of-possession (POP) at every trust boundary.
- Deterministic, pseudonymous tenant identifiers.
- No user database: all trust derives from cryptographic proofs and email control.

The system is designed for minimal backend state, deterministic identifiers, and easy horizontal scalability.

---

## 2. Entities

| Entity | Description |
|---------|--------------|
| **Client App** | Mobile app holding a device key pair and secure local storage. Handles all user-facing verification flows. |
| **Issuer (Auth Service)** | Stateless service issuing challenge tokens, device certificates, and access tokens. Holds only a signing key and configuration. |
| **Mail Renderer** | Independent service consuming queued `SendEmail` jobs, rendering templates, and sending via SMTP or SES. |
| **Resource Servers** | Validate device-bound access tokens using the Issuer’s public keys. No per-user state. |
| **Analytics Pipeline (optional)** | Receives fire-and-forget event payloads for metrics. Non-blocking to authentication. |

---

## 3. Deterministic Identifiers

### 3.1 Tenant ID

```
tenant_id = base64url( HKDF(issuer_secret, "tenant-id", lowercase(email)) )[0:22]
```

- Stable per email address.
- Not reversible without the issuer’s secret.
- Used as the `sub` claim in all tokens.

### 3.2 Device ID

```
device_id = base64url( SHA256(device_pubkey) )[0:22]
```

- Stable per key pair.
- Used for correlation and analytics only.

---

## 4. Key Material

| Key | Owner | Lifetime | Use |
|------|--------|-----------|-----|
| **Device Key Pair (Ed25519)** | Client App | Until re-registration | Proof of possession, DPoP signing |
| **Issuer Signing Key (Ed25519 / P-256)** | Issuer | Long-term | Signing JWTs (challenges, DCs, ATs) |
| **Issuer Public JWKS** | Resource Servers | Rotated via standard JWKS endpoint | Verification |

---

## 5. Protocol Flows

### 5.1 Registration (Email Proof + Device Binding)

1. **Device key creation**  
   App generates Ed25519 key pair in secure enclave. Private key protected by local unlock (PIN/biometric).

2. **Start request**

   ```
   POST /start
   {
     "email": "user@example.com",
     "device_pubkey": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
     "code_challenge": "b64url(SHA256(code_verifier))"
   }
   ```

3. **Issuer constructs challenge JWT (`J_chal`)**

   ```
   {
     "iss": "https://issuer.example",
     "aud": "registration",
     "email": "user@example.com",
     "email_hash": "b64url(SHA256(lower(email)))",
     "pubkey_hash": "b64url(SHA256(jwk(device_pubkey)))",
     "code_challenge": "b64url(SHA256(code_verifier))",
     "nonce": "b64url(rand96)",
     "iat": now(),
     "nbf": now(),
     "exp": now() + 10m
   }
   ```

   - Issuer signs the JWT.
   - Generates a `rid` (unique request ID).
   - Enqueues a `SendEmail` message:

     ```
     {
       "template_id": "auth_verification_v1",
       "to_email": "user@example.com",
       "personalisation": {
         "code": "ABCD-1234",
         "link": "https://login.example.com/#token=<J_chal>",
         "expires_at": "2025-10-31T12:35:00Z",
         "rid": "<uuid>"
       },
       "headers": {
         "Message-ID": "<uuid@example.com>",
         "X-Request-ID": "<uuid>"
       }
     }
     ```

4. **Mail Renderer → SMTP / SES**
   - Renders the message.
   - Sends via MailHog (dev) or SES (prod).
   - No callback required.

5. **User receives email**
   - Preferred: enters the `code` into the app.
   - Fallback: taps the deep link, which routes to the app via OS-level association.

6. **App redemption**

   ```
   POST /redeem
   {
     "J_chal": "<jwt>",
     "device_pubkey": { ... },
     "code_verifier": "<random_128bit_b64url>",
     "pop_sig": "b64url(Sign_device(SHA256(J_chal_header || '.' || J_chal_payload)))"
   }
   ```

7. **Issuer verification**
   - Verify JWT signature, expiry, `aud == registration`.
   - Validate `code_challenge == SHA256(code_verifier)`.
   - Verify `pop_sig` using `device_pubkey`.
   - If all checks pass, issue Device Certificate (DC):

     ```
     {
       "iss": "https://issuer.example",
       "sub": "tenant_<id>",
       "email_hash": "b64url(SHA256(lower(email)))",
       "device_id": "dev_<id>",
       "device_pubkey": { ... },
       "attestation": "not_present",
       "iat": now(),
       "exp": now() + 30d,
       "typ": "dc+jwt"
     }
     ```

   - Return `DC` to app.

---

### 5.2 Token Exchange (Sessionless Access)

1. **DPoP proof**

   App prepares a DPoP JWT:

   ```
   {
     "htu": "https://issuer.example/token",
     "htm": "POST",
     "jti": "<uuid>",
     "iat": now()
   }
   ```

   Signed with the device private key.

2. **Token request**

   ```
   POST /token
   {
     "device_certificate": "<DC>",
     "dpop": "<dpop_jwt>"
   }
   ```

3. **Issuer validates**
   - Verify `DC` signature, expiry, audience.
   - Verify DPoP signature using `device_pubkey` from `DC`.
   - Return short-lived Access Token (AT):

     ```
     {
       "iss": "https://issuer.example",
       "sub": "tenant_<id>",
       "aud": "https://api.example",
       "cnf": { "jkt": "b64url(SHA256(jwk(device_pubkey)))" },
       "scope": "read:data write:data",
       "amr": ["email", "mfa", "otp", "pop"],
       "acr": "aal2",
       "auth_time": 1700000000,
       "iat": now(),
       "exp": now() + 10m
     }
     ```

     `scope` is a space-separated string, following OAuth 2.0. `amr`,
     `acr` and `auth_time` state what proof backed the authentication and
     how strong it was; they are absent when the issuer recorded no
     method. See `guides/authenticators.md`.

---

### 5.3 Token Verification (Resource Server)

1. Validate JWT signature against Issuer JWKS.  
2. Ensure `aud` matches API audience.  
3. Validate `exp`, `nbf`.  
4. Confirm DPoP proof matches `cnf.jkt`.  
5. Authorise the request on `sub`, `scope`, and — where the operation
   warrants it — `acr` and `auth_time`.

---

### 5.4 Renewal

- The app obtains a fresh access token, and a rotated SPIFFE leaf, by
  calling `/token` again with its device certificate and a new DPoP proof.
  There is no separate renewal endpoint.
- Before the device certificate itself expires, the app re-runs
  enrollment. An app that holds another enrolled device can instead have
  that device vouch for a freshly generated key.

---

## 6. Email Transport & Rendering

### 6.1 Message Queue

Issuer enqueues `SendEmail` jobs to a durable queue (SQS, NATS, RabbitMQ).

**Queue message schema**
```
{
  "template_id": "auth_verification_v1",
  "to_email": "user@example.com",
  "personalisation": {
    "code": "ABCD-1234",
    "link": "https://login.example.com/#token=<J_chal>",
    "expires_at": "2025-10-31T12:35:00Z",
    "rid": "<uuid>"
  },
  "headers": {
    "Message-ID": "<uuid@example.com>",
    "X-Request-ID": "<uuid>"
  }
}
```

### 6.2 Renderer

- Standalone stateless service.
- Renders HTML + plaintext templates.
- Sends via:
  - **Dev:** MailHog or Mailpit.
  - **Prod:** Amazon SES (SMTP or HTTPS API).

### 6.3 No server callbacks

- No delivery confirmation is required for authentication.
- SES bounces/complaints are routed to SNS/SQS purely for analytics.

---

## 7. Anti-Phishing UX

1. **Code-first verification**
   - Primary path is entering the email-delivered code inside the app.
   - Link is optional fallback.

2. **Consistent sender**
   - `From: Auth Team <no-reply@example.com>`
   - Fixed domain and typography.

3. **Domain education**
   - Each email footer:  
     “Verification links always point to `login.example.com`.”

4. **Deep links**
   - iOS Universal Links / Android App Links.
   - Only `login.example.com` may deep-link into the app.

5. **In-app confirmation**
   - Display masked email and short key fingerprint (e.g., `DEV-MA7Q-9U2K`).
   - Show expiry countdown and a “Not me” cancel action.

6. **Short validity**
   - Challenge TTL: 10 minutes.
   - Access token TTL: 10 minutes.
   - Device certificate TTL: 7–30 days.

---

## 8. Link Theft Protections

| Mechanism | Purpose |
|------------|----------|
| **POP signature** | Only the device possessing the private key can redeem. |
| **Code challenge (PKCE)** | Challenge useless without client-held verifier. |
| **Short-lived challenge** | Expired links fail fast. |
| **Strict audience** | Prevent use in wrong endpoint. |
| **HTTPS + HSTS** | Mitigate downgrade. |
| **QR fallback for desktops** | Browser never directly redeems; app scans QR. |
| **JWT in fragment (`#token=`)** | Prevents intermediary leakage. |

---

## 9. Shared Inbox Model

- Identity scope is **email control at verification time**.
- Multiple devices (people) can independently register under the same email.
- Each receives a unique device certificate tied to its key.
- Tenant ID is deterministic from email; shared inbox acceptable.
- Capability isolation via `device_pubkey` and `cnf.jkt` in tokens.

---

## 10. Revocation Strategy

Because the issuer maintains no user state:

- Tokens are short-lived.
- Device certificates expire quickly.
- Optional: global revocation list (Bloom filter of revoked `device_id`s) published at `/.well-known/revocations.json`.
- Resource servers cache and refresh periodically.

---

## 11. Analytics (Optional, Non-Blocking)

- Fire-and-forget emission; no blocking on auth.
- Schema:

  ```
  {
    "evt": "token_issued",
    "iat": now(),
    "tenant_id": "<id>",
    "device_id": "<id>",
    "result": "ok",
    "rid": "<uuid>"
  }
  ```

- Signed with HMAC for integrity.
- Delivery failures are ignored.

---

## 12. Security Checklist

| Item | Status |
|------|--------|
| All JWTs signed with Ed25519 or P-256 | ✅ |
| All endpoints require HTTPS | ✅ |
| HSTS on `login.example.com` | ✅ |
| Short TTLs for challenges/tokens | ✅ |
| POP proof required on redemption | ✅ |
| Code challenge (PKCE) used | ✅ |
| Deep link verification enforced | ✅ |
| DKIM/SPF/DMARC/BIMI configured | ✅ |
| No email callbacks required | ✅ |
| Analytics non-blocking | ✅ |

---

## 13. Example Token Sizes

| Token | Typical Size | TTL |
|--------|---------------|-----|
| `J_chal` | ~600 bytes | 10 min |
| `DC` | ~750 bytes | 7–30 days |
| `AT` | ~450 bytes | 10 min |

---

## 14. Example Email Template (Plain Text)

```
Subject: Your Example verification code: {{code}}

Hello,

Your Example verification code is: {{code}}

If you are on your phone, you can verify instantly:
{{link}}

This link expires at {{expires_at}}.

For your security, Example verification links always point to login.example.com.
Do not share this code or click links from other domains.

– The Example Auth Team
```

---

## 15. Implementation Notes

- **Crypto:** Ed25519 recommended for all signatures and POP proofs.
- **Libraries:** Use FIPS-validated primitives where required.
- **DPoP:** Enforce unique `jti` per request; replay detection window ≤ 5 min.
- **Time sync:** Issuer and resource servers tolerate ±2 minutes skew.
- **Attestation:** If available, include Play Integrity or Apple App Attest result in DC claim `attestation`.

---

## 16. Summary

| Goal | Achieved By |
|------|--------------|
| Stateless authentication | JWT-based flow, no DB |
| Email verification | Signed challenge, local POP |
| Device binding | Persistent local keypair |
| Revocation avoidance | Short-lived certs/tokens |
| Analytics decoupling | Fire-and-forget events |
| Anti-phishing | Code-first UX, deep-link validation |
| Link-theft resistance | POP + PKCE + short TTL |

---
