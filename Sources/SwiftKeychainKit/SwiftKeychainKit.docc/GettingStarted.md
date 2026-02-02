# Getting Started

Learn how to use SwiftKeychainKit to securely store and retrieve passwords, keys, and other sensitive data.

## Overview

SwiftKeychainKit provides a simple, type-safe API for working with the Keychain.
The goal is to make correct use of the Data Protection Keychain straightforward,
even though the underlying Apple APIs are complex and easy to misuse.

## Passwords

Store, retrieve, and update generic passwords.
For passwords associated with a URL or network endpoint, use ``Keychain/InternetPassword`` instead.

```swift
import SwiftKeychainKit

// Store a password
// Source string may remain in memory (Copy-on-Write)
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "MySecretPassword")
try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.myapp"
)

// Retrieve a password
if let password = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.myapp"
) {
    // Prefer withUnsafeBytes for memory-safe access;
    // makeUnsafeUTF8String() is convenient but leaves an unprotected copy
    let string = password.makeUnsafeUTF8String()
}

// Update a password
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "MyNewPassword")
try await Keychain.GenericPassword.update(
    account: "user@example.com",
    service: "com.example.myapp",
    to: newPassword
)
```

## CryptoKit Keys

### SecKeyConvertible (NIST Curves)

CryptoKit NIST curve keys (P-256, P-384, P-521) conform to ``SecKeyConvertible`` and can be
stored directly via ``Keychain/Keys``:

```swift
import CryptoKit

let privateKey = P256.Signing.PrivateKey()
let tag = "com.example.myapp.p256-key".data(using: .utf8)!

// Store directly — no SecKey conversion needed
try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: tag
)

// Retrieve as CryptoKit type
let retrievedKey: P256.Signing.PrivateKey? = try await Keychain.Keys.queryOne(
    applicationTag: tag
)
```

### GenericPasswordConvertible (Curve25519)

Curve25519 keys cannot be represented as `SecKey` and are stored as generic passwords instead:

```swift
import CryptoKit

let privateKey = Curve25519.KeyAgreement.PrivateKey()

// Store as generic password
try await Keychain.GenericPassword.add(
    privateKey,
    account: "com.example.myapp.curve25519-key",
    service: "com.example.myapp"
)

// Retrieve as CryptoKit type
let retrievedKey: Curve25519.KeyAgreement.PrivateKey? = try await Keychain.GenericPassword.get(
    account: "com.example.myapp.curve25519-key",
    service: "com.example.myapp"
)
```

## Deleting Items

Remove items from the Keychain:

```swift
try await Keychain.GenericPassword.delete(
    account: .specific("user@example.com"),
    service: .specific("com.example.myapp"),
    accessGroup: .any
)
```

## Access Control with Biometry

Require biometric authentication for sensitive data:

```swift
let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .biometryAny
)

let tag = "com.example.myapp.signing".data(using: .utf8)!
try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: tag,
    accessControl: accessControl
)
```

## See Also

- ``SecretData``
- ``Keychain/GenericPassword``
- ``Keychain/InternetPassword``
- ``Keychain/Keys``
- ``Keychain/AccessControl``
