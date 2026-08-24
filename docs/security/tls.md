# TLS and Security Headers

All public services enforce HTTPS and strict security headers.

## TLS

- Use TLS 1.2+ with modern cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
- Disable HTTP (`--redirect`) at the load balancer level.
- Issue certificates via ACME/Let's Encrypt or ACM.

## HTTP Security Headers

Issuer responses include:

- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`

Ensure reverse proxies preserve these headers and add `Content-Security-Policy` for any UI endpoints.
