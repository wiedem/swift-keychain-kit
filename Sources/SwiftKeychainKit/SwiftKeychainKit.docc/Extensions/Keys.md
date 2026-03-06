# ``Keychain/Keys``


## Overview

The Keys API provides secure storage and retrieval of cryptographic keys in the Keychain. Use this entry type to manage:
- RSA private keys
- Elliptic Curve (EC) private keys
- Other asymmetric cryptographic keys

The Keys API only supports storing private keys. Public keys should be derived from private keys or stored separately using certificates.

## Adding Private Keys

Store a CryptoKit key:

```swift
import CryptoKit

let privateKey = P256.Signing.PrivateKey()

// Store directly, no SecKey conversion needed
try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: "com.example.myapp.p256-key".data(using: .utf8)!
)
```

Store a `SecKey` directly:

```swift
// Generate an RSA key pair
let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecAttrKeySizeInBits as String: 2048
]
var error: Unmanaged<CFError>?
guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    throw error!.takeRetainedValue() as any Error
}

try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: "com.example.myapp.signing-key".data(using: .utf8)!
)
```

## Retrieving Keys

Retrieve a CryptoKit key directly:

```swift
import CryptoKit

let tag = "com.example.myapp.p256-key".data(using: .utf8)!

// Type inference determines the key type automatically
let retrievedKey: P256.Signing.PrivateKey? = try await Keychain.Keys.queryOne(
    applicationTag: tag
)
```

Retrieve a `SecKey` by its application tag:

```swift
let tag = "com.example.myapp.signing-key".data(using: .utf8)!

if let key = try await Keychain.Keys.queryOne(
    keyType: .rsa(.privateKey),
    applicationTag: tag
) {
    // Use the SecKey for cryptographic operations
}
```

Query all RSA keys:

```swift
let rsaKeys = try await Keychain.Keys.query(
    keyType: .rsa(.privateKey),
    skipItemsIfUIRequired: true,
    limit: .unlimited
)
```

> Important: Querying multiple keys may trigger an authentication prompt for each individual key that has access constraints. Use `skipItemsIfUIRequired` to silently skip those keys instead.

## Querying Key Attributes

Get metadata about a key without retrieving the key itself:

```swift
let attributes = try await Keychain.Keys.queryAttributes(
    keyType: .rsa(.privateKey),
    applicationTag: .utf8("com.example.myapp.signing-key")
)

if let attr = attributes.first {
    print("Key size: \(attr.keySizeInBits) bits")
    print("Algorithm: \(attr.algorithm)")

    // Use the item reference for subsequent operations
    let key: SecKey? = try await Keychain.Keys.get(
        itemReference: attr.itemReference
    )
}
```

## Deleting Keys

Delete a CryptoKit key by its type:

```swift
try await Keychain.Keys.delete(
    keyType: .keyType(P256.Signing.PrivateKey.self),
    applicationTag: .utf8("com.example.myapp.signing-key")
)
```

Delete a SecKey by its algorithm and class:

```swift
try await Keychain.Keys.delete(
    keyType: .rsa(.privateKey),
    applicationTag: .utf8("com.example.myapp.signing-key")
)
```

## Primary Key

Keys are uniquely identified by:
- **keyClass**: The class of the key (public, private, or symmetric)
- **keyType**: The algorithm type (RSA, Elliptic Curve, etc.)
- **applicationLabel**: An identifier for the key (defaults to the public key hash for private keys)
- **applicationTag**: An application-specific tag (optional)

For most use cases, you'll identify keys using the `applicationTag` attribute, which serves as a convenient, application-defined identifier.

## Application Label vs Application Tag

- **applicationLabel**: Typically set automatically to the public key hash when storing private keys using `.publicKeyHash` (default). This links the private key to its corresponding public key.
- **applicationTag**: A custom identifier you define. Use this to logically identify keys in your app (e.g., "signing-key", "encryption-key").

In most queries, you'll search by `applicationTag` since it's more meaningful to your application logic.

However, when using the default `.publicKeyHash` application label, `applicationTag` alone does not guarantee uniqueness. Each key has a distinct public key hash as its `applicationLabel`, so adding two different keys with the same tag but different key material succeeds without a ``KeychainError/duplicateItem`` error.

Use ``ApplicationLabel/resolve(for:)-52yqf`` to obtain the application label from a key without storing it in the Keychain:

```swift
import CryptoKit

let privateKey = P256.Signing.PrivateKey()

// Get the public key hash that the Keychain would use as application label
let label = try Keychain.Keys.ApplicationLabel.resolve(for: privateKey)
```

## Topics

### Adding Keys

- ``addPrivateKey(_:applicationTag:applicationLabel:label:accessGroup:synchronizable:accessControl:authenticationContext:)-5iytt``
- ``addPrivateKey(_:applicationTag:applicationLabel:label:accessGroup:synchronizable:accessControl:authenticationContext:)-1pfhf``

### Retrieving Keys by Reference

- ``get(itemReference:skipIfUIRequired:authenticationContext:)-21ynx``
- ``get(itemReference:skipIfUIRequired:authenticationContext:)-4cu19``

### Querying Keys

- ``query(keyType:applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)-3xzad``
- ``query(keyType:applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)-6xkhp``
- ``query(_:keyType:applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``
- ``query(_:applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``
- ``query(applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``
- ``queryOne(keyType:applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)-2xhhe``
- ``queryOne(keyType:applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)-1gb4n``
- ``queryOne(applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)``

### Deleting Keys

- ``delete(keyType:applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:authenticationContext:)-5qero``
- ``delete(keyType:applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:authenticationContext:)-40x5f``
- ``delete(itemReference:authenticationContext:)-198hc``
- ``delete(itemReference:authenticationContext:)-8ksyd``

### Attributes

- ``Attributes``
- ``attributes(itemReference:skipIfUIRequired:authenticationContext:)``
- ``queryAttributes(keyType:applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``

### Key Types

- ``KeyClass``
- ``AsymmetricKeyClass``
- ``KeyAlgorithm``
- ``ApplicationLabel``

### Key Conversion

- ``SecKeyConvertible``

## See Also

- ``Keychain/Certificates``
- ``Keychain/Identities``
- ``Keychain/QueryScope``
