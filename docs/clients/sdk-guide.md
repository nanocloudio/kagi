# Device SDK Guide

What a client must generate and sign to complete an enrollment, and the
`DeviceKeyManager` shape the Kotlin Multiplatform and Swift packages expose
for it.

**The packages are not in this repository.** The paths below name where they
live in a client tree; what is normative here is the API shape and the
signing semantics, which `../specification.md` gives exactly.

## Common Concepts

- **Key Pair** – 32-byte public key and 64-byte private key (seed + public component).
- **Signing** – Produce a detached Ed25519 signature for request payloads.
- **Storage** – Persist private key material locally so the device identity remains stable. Kotlin exposes a `DeviceKeyStore` abstraction while Swift persists keys in the Secure Enclave Keychain.

## Kotlin Multiplatform (`clients/sdk/kmp`)

```kotlin
val store = InMemoryDeviceKeyStore() // replace with platform-secure storage
val keyPair = DeviceKeyManager.ensureKeyPair(store)

val payload = "challenge".encodeToByteArray()
val signature = DeviceKeyManager.sign(payload, keyPair.privateKey)

if (DeviceKeyManager.verify(payload, signature, keyPair.publicKey)) {
    println("signature valid – send to issuer")
}
```

Implement `DeviceKeyStore` to back keys with secure storage (e.g. Android Keystore or iOS Keychain via expect/actual).

## Swift (`clients/sdk/ios/KagiDeviceKit`)

```swift
import KagiDeviceKit

let keyPair = try DeviceKeyManager.ensureKeyPair()
let payload = Data("challenge".utf8)
let signature = try DeviceKeyManager.sign(data: payload)

if try DeviceKeyManager.verify(data: payload, signature: signature, publicKey: keyPair.publicKey) {
    print("signature valid – send to issuer")
}
```

`DeviceKeyManager` stores keys in the Secure Enclave by default (`ensureKeyPair`), and `deleteKey` removes the persisted material when required (sign-out, device reset, etc.).

## Next Steps

- Integrate signing into the `/start`, `/redeem`, and `/token` client flows.
- Encode public keys with `publicKeyBase64Url` before transmitting to the issuer.
- Mirror the same payload signing semantics across platforms to keep telemetry consistent.
