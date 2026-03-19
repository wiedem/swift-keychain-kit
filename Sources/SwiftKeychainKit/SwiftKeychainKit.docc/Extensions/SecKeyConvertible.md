# ``SwiftKeychainKit/SecKeyConvertible``

## Overview

``SecKeyConvertible`` combines ``SecKeyInitializable`` and ``SecKeyRepresentable``. A type that conforms to it can use
``Keychain/Keys`` operations because it can be converted to and from
[SecKey](https://developer.apple.com/documentation/security/seckey).

The ``SecKeyInitializable/init(secKey:)`` initializer is used when a key is returned from the Keychain and is
converted into the custom type. The ``SecKeyRepresentable/makeSecKey()`` method is used when the custom type is
stored in the Keychain.

## Conforming to SecKeyConvertible

The ``SecKeyInitializable/init(secKey:)`` initializer typically calls
[SecKeyCopyExternalRepresentation](https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:))
to obtain the key's data, then parses it into the conforming type. The returned data is an immutable `CFData` object
that cannot be zeroized after use, so the key material may remain in memory until the object is deallocated. Keys that
are not marked as extractable, as well as Secure Enclave keys, cannot be exported this way and will produce an error.

The ``SecKeyRepresentable/makeSecKey()`` method typically calls
[SecKeyCreateWithData](https://developer.apple.com/documentation/security/seckeycreatewithdata(_:_:_:))
to create a [SecKey](https://developer.apple.com/documentation/security/seckey) from the key's data representation.

Implement both the ``SecKeyInitializable/init(secKey:)`` initializer and ``SecKeyRepresentable/makeSecKey()`` method:

```swift
struct CustomPrivateKey: SecKeyConvertible {
    init() {
        // Designated initializer to create your private key type
    }

    init(secKey: SecKey) throws {
        // Create your private key type from a SecKey
    }

    func makeSecKey() throws -> SecKey {
        // Convert your private key type to a SecKey
        secKey
    }
}

let applicationTag = "com.example.key".data(using: .utf8)!
let customKey = CustomPrivateKey()

try await Keychain.Keys.addPrivateKey(
    customKey,
    applicationTag: applicationTag
)

if let storedKey: CustomPrivateKey = try await Keychain.Keys.queryOne(
    keyType: .ellipticCurve(.privateKey),
    applicationTag: applicationTag
) {
    // Use the stored key ...
}
```

## Built-in Conformances

SwiftKeychainKit provides `SecKeyConvertible` conformance for all [CryptoKit](https://developer.apple.com/documentation/cryptokit) elliptic curve key types:

- [P256.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/p256/signing/privatekey)
- [P256.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/p256/keyagreement/privatekey)
- [P384.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/p384/signing/privatekey)
- [P384.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/p384/keyagreement/privatekey)
- [P521.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/p521/signing/privatekey)
- [P521.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/p521/keyagreement/privatekey)

## See Also

- ``Keychain/Keys``
- [Storing Keys as Data](https://developer.apple.com/documentation/security/storing-keys-as-data)
