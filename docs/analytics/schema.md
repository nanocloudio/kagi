# Analytics Event Schema

Analytics events are signed JSON documents. Each event follows the schema in
[`event-schema.json`](event-schema.json) and is protected with an HMAC-SHA256
signature distributed via configuration management.

**This is a schema, not a shipped feature.** Nothing in this repository emits
these events: the modules that make up the issuer expose the fixed-layout
telemetry their manifests declare, and analytics is a downstream concern. The
schema is here so that a deployment which wants such a feed builds one shape
rather than inventing its own.

## Fields

| Field        | Type    | Description |
|--------------|---------|-------------|
| `event`      | string  | Event identifier (e.g. `token_issued`, `challenge_redeemed`). |
| `at`         | int64   | UTC timestamp in seconds when the event occurred. |
| `tenant_id`  | string  | Deterministic tenant identifier derived from email. |
| `device_id`  | string? | Optional device identifier derived from device public key. |
| `rid`        | string? | Optional request identifier for correlating traces. |
| `payload`    | object  | Event-specific payload (scopes, results, error codes, etc.). |

## Signing Process

1. Serialize the event using canonical JSON ordering (`serde_json` in Rust, `JSON.stringify` in JS).
2. Compute HMAC-SHA256 over the serialized bytes using the shared analytics secret.
3. Encode the MAC using Base64URL without padding.
4. Deliver events with headers:
   - `X-Kagi-Analytics-Signature`: Base64URL signature
   - `X-Kagi-Analytics-Key-Id`: Identifier for rotating secrets

An emitter must canonicalise before signing, or a verifier reserialising the event will compute a different MAC over the same document.

## Example Event

```json
{
  "event": "token_issued",
  "at": 1730478642,
  "tenant_id": "tenant_af82kj1",
  "device_id": "dev_9a82jsh",
  "rid": "req-123",
  "payload": {
    "scp": ["read:data"],
    "result": "ok"
  }
}
```

[`dashboard.json`](dashboard.json) is a Grafana dashboard over a store fed by such events. The consumer that verifies the signatures and populates that store is not part of this repository.
