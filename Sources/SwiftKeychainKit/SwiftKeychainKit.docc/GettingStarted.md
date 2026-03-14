# Getting Started

Learn how to use SwiftKeychainKit to securely store and retrieve passwords, keys, and other sensitive data.

## Overview

SwiftKeychainKit provides a simple, type-safe API for working with the Keychain.
The goal is to make correct use of the Data Protection Keychain straightforward,
even though the underlying Apple APIs are complex and easy to misuse.

All Keychain operations in SwiftKeychainKit are asynchronous. Each operation
performs I/O against the system's Keychain database, and async/await allows
the caller to suspend while waiting for the result, keeping the calling
context responsive.

## Passwords

Store, retrieve, and update generic passwords.
For passwords associated with a URL or network endpoint, use
``Keychain/InternetPassword`` instead.

```swift
import SwiftKeychainKit

// Store a password
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "MySecretPassword")
try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.myapp"
)

// Retrieve a password
let password = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.myapp"
)

// Update a password
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "MyNewPassword")
try await Keychain.GenericPassword.update(
    account: "user@example.com",
    service: "com.example.myapp",
    to: newPassword
)
```

## Item References

Every `add()` method returns an ``ItemReference`` that uniquely identifies the stored item. You can use it to retrieve, update, or delete the item later without repeating the original query parameters:

```swift
let itemReference = try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.myapp"
)

let password = try await Keychain.GenericPassword.get(itemReference: itemReference)
```

Item references are `Codable` and can be persisted across app launches. For details, see <doc:UsingItemReferences>.

## CryptoKit Keys

CryptoKit keys can be stored directly in the Keychain. NIST curve keys
(P-256, P-384, P-521) are stored via ``Keychain/Keys``:

```swift
import CryptoKit

let privateKey = P256.Signing.PrivateKey()
let tag = "com.example.myapp.p256-key".data(using: .utf8)!

try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: tag
)

let retrievedKey: P256.Signing.PrivateKey? = try await Keychain.Keys.queryOne(
    applicationTag: tag
)
```

Curve25519 keys are stored as generic passwords using
``Keychain/GenericPasswordConvertible``. For details and examples, see
<doc:UsingCryptoKit>.

## Deleting Items

To remove items from the Keychain, specify the item's primary key attributes
and an access group scope:

```swift
try await Keychain.GenericPassword.delete(
    account: "user@example.com",
    service: "com.example.myapp",
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

For application passwords and other access constraints, see
<doc:ProtectingItemsWithCustomPassword>.

## See Also

- ``Keychain/GenericPassword``
- ``Keychain/InternetPassword``
- ``Keychain/Keys``
- ``Keychain/AccessControl``
