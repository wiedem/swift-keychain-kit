# Using CryptoKit with SwiftKeychainKit

Store and retrieve CryptoKit cryptographic keys securely in the Keychain.

## Overview

SwiftKeychainKit supports all CryptoKit elliptic curve private key types.
NIST curve keys ([P256](https://developer.apple.com/documentation/cryptokit/p256),
[P384](https://developer.apple.com/documentation/cryptokit/p384),
[P521](https://developer.apple.com/documentation/cryptokit/p521)) conform to
``SecKeyConvertible`` and are stored via ``Keychain/Keys``.
[Curve25519](https://developer.apple.com/documentation/cryptokit/curve25519)
keys conform to ``Keychain/GenericPasswordConvertible`` and are stored as
generic passwords.

## NIST Curve Keys

[P256](https://developer.apple.com/documentation/cryptokit/p256),
[P384](https://developer.apple.com/documentation/cryptokit/p384), and
[P521](https://developer.apple.com/documentation/cryptokit/p521) keys can be
stored and retrieved directly through
``Keychain/Keys``:

```swift
import CryptoKit
import SwiftKeychainKit

let privateKey = P256.Signing.PrivateKey()
let tag = "com.example.myapp.signing-key".data(using: .utf8)!

try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: tag
)

let retrievedKey: P256.Signing.PrivateKey? = try await Keychain.Keys.queryOne(
    applicationTag: tag
)
```

The same approach works for [P384](https://developer.apple.com/documentation/cryptokit/p384)
and [P521](https://developer.apple.com/documentation/cryptokit/p521), as well
as for KeyAgreement keys.

### Deleting a Key

To remove a NIST curve key, delete it by its application tag:

```swift
try await Keychain.Keys.delete(
    keyType: .ellipticCurve(.privateKey),
    applicationTag: .utf8("com.example.myapp.signing-key")
)
```

## Curve25519 Keys

[Curve25519](https://developer.apple.com/documentation/cryptokit/curve25519)
keys cannot be represented as
[SecKey](https://developer.apple.com/documentation/security/seckey) and are
stored as generic passwords using ``Keychain/GenericPasswordConvertible``:

```swift
import CryptoKit
import SwiftKeychainKit

let privateKey = Curve25519.Signing.PrivateKey()

try await Keychain.GenericPassword.add(
    privateKey,
    account: "com.example.myapp.curve25519-key",
    service: "com.example.myapp"
)

let retrievedKey: Curve25519.Signing.PrivateKey? = try await Keychain.GenericPassword.get(
    account: "com.example.myapp.curve25519-key",
    service: "com.example.myapp"
)
```

### Deleting a Key

```swift
try await Keychain.GenericPassword.delete(
    account: "com.example.myapp.curve25519-key",
    service: "com.example.myapp",
    accessGroup: .any
)
```

## Reading the Application Label

When storing a private key, the Keychain automatically sets its application label to the hash of the
public key. You can obtain this value from a key without storing it in the Keychain:

```swift
import CryptoKit

let privateKey = P256.Signing.PrivateKey()

// Get the public key hash computed by the Security framework
let applicationLabel = try Keychain.Keys.ApplicationLabel.resolve(for: privateKey)
```

This is useful for querying keys by their application label or for matching a private key to its
corresponding certificate.

## Access Control

Both storage paths support access control. Use
``Keychain/AccessControl/make(accessibility:constraint:)`` to protect keys
with biometry or other constraints:

```swift
let privateKey = P256.Signing.PrivateKey()
let tag = "com.example.myapp.protected-key".data(using: .utf8)!

try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: tag,
    accessControl: .make(
        accessibility: .whenUnlockedThisDeviceOnly,
        constraint: .biometryAny
    )
)
```

## iCloud Synchronization

NIST curve keys can be synchronized across the user's devices:

```swift
let privateKey = P256.Signing.PrivateKey()
let tag = "com.example.myapp.synced-key".data(using: .utf8)!

try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: tag,
    synchronizable: true
)
```

[Curve25519](https://developer.apple.com/documentation/cryptokit/curve25519)
keys stored as generic passwords can also be synchronized using the
`synchronizable` parameter on ``Keychain/GenericPassword``.

## See Also

- ``SecKeyConvertible``
- ``Keychain/GenericPasswordConvertible``
- ``Keychain/Keys``
- ``Keychain/AccessControl``
