# Using CryptoKit with SwiftKeychainKit

Store and retrieve CryptoKit cryptographic keys securely in the Keychain.

## Overview

SwiftKeychainKit provides seamless integration with Apple's CryptoKit framework, allowing you to store CryptoKit private keys in the Keychain and retrieve them later. This is particularly useful for:

- Persistent key storage across app launches
- Secure key backup with iCloud Keychain synchronization
- Biometric protection for cryptographic operations
- Key sharing between app and extensions via shared access groups

## Supported CryptoKit Key Types

SwiftKeychainKit supports all CryptoKit elliptic curve private key types:

- **P256**: [P256.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/p256/signing/privatekey) and [P256.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/p256/keyagreement/privatekey)
- **P384**: [P384.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/p384/signing/privatekey) and [P384.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/p384/keyagreement/privatekey)
- **P521**: [P521.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/p521/signing/privatekey) and [P521.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/p521/keyagreement/privatekey)

## Storing CryptoKit Keys

### Basic Storage

Generate a CryptoKit key and store it in the Keychain:

```swift
import CryptoKit
import SwiftKeychainKit

// Generate a signing key
let privateKey = P256.Signing.PrivateKey()

// Store in Keychain with a unique tag
let tag = "com.example.myapp.signing-key".data(using: .utf8)!
try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: tag
)
```

### Storage with Access Control

Require biometric authentication for key usage:

```swift
let privateKey = P256.Signing.PrivateKey()

// Require Face ID or Touch ID
let accessControl = Keychain.AccessControl(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .biometryAny
)

let tag = "com.example.myapp.protected-key".data(using: .utf8)!
try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: tag,
    accessControl: accessControl
)
```

### Storage with iCloud Sync

Enable key synchronization across user's devices:

```swift
let privateKey = P256.Signing.PrivateKey()

let tag = "com.example.myapp.synced-key".data(using: .utf8)!
try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: tag,
    synchronizable: true
)
```

## Retrieving CryptoKit Keys

### Basic Retrieval

Retrieve a key and convert it back to CryptoKit:

```swift
let tag = "com.example.myapp.signing-key".data(using: .utf8)!

// Query the Keychain
if let privateKey: P256.Signing.PrivateKey = try await Keychain.Keys.queryOne(
    applicationTag: tag
) {
    // Use the key for signing
    let data = "Hello, World!".data(using: .utf8)!
    let signature = try privateKey.signature(for: data)
}
```

### Retrieval with Biometric Authentication

When a key is protected by biometrics, the system automatically prompts for authentication:

```swift
let tag = "com.example.myapp.protected-key".data(using: .utf8)!

// System shows Face ID / Touch ID prompt automatically
if let privateKey: P256.Signing.PrivateKey = try await Keychain.Keys.queryOne(
    applicationTag: tag
) {
    // Key is now ready to use
}
```

### Pre-Authenticated Access

Avoid repeated biometric prompts by pre-authenticating with [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext):

```swift
import LocalAuthentication

let context = LAContext()
var error: NSError?

// Authenticate once
guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
    throw error ?? KeychainError.authenticationFailed
}

_ = try await context.evaluatePolicy(
    .deviceOwnerAuthenticationWithBiometrics,
    localizedReason: "Access your signing keys"
)

// Now use the context for multiple key operations
let tag = "com.example.myapp.protected-key".data(using: .utf8)!
if let privateKey: P256.Signing.PrivateKey = try await Keychain.Keys.queryOne(
    applicationTag: tag,
    authenticationContext: context  // No prompt shown
) {
    // Use privateKey without additional prompts
}
```

## Complete Example: Signing with CryptoKit

Here's a complete example of generating, storing, retrieving, and using a signing key:

```swift
import CryptoKit
import SwiftKeychainKit

// 1. Generate or retrieve key
let tag = "com.example.myapp.signing-key".data(using: .utf8)!

let privateKey: P256.Signing.PrivateKey
if let existingKey: P256.Signing.PrivateKey = try? await Keychain.Keys.queryOne(
    applicationTag: tag
) {
    // Key exists
    privateKey = existingKey
} else {
    // Generate new key
    privateKey = P256.Signing.PrivateKey()
    
    // Store in Keychain
    try await Keychain.Keys.addPrivateKey(
        privateKey,
        applicationTag: tag
    )
}

// 2. Use the key for signing
let dataToSign = "Important message".data(using: .utf8)!
let signature = try privateKey.signature(for: dataToSign)

// 3. Verify with public key
let publicKey = privateKey.publicKey
if publicKey.isValidSignature(signature, for: dataToSign) {
    print("Signature is valid")
}
```

## Key Agreement Example

Use key agreement keys for shared secret generation:

```swift
import CryptoKit
import SwiftKeychainKit

// Generate and store Alice's key
let alicePrivateKey = P256.KeyAgreement.PrivateKey()
let aliceTag = "com.example.alice.agreement-key".data(using: .utf8)!

try await Keychain.Keys.addPrivateKey(
    alicePrivateKey,
    applicationTag: aliceTag
)

// Bob generates his key (not stored)
let bobPrivateKey = P256.KeyAgreement.PrivateKey()
let bobPublicKey = bobPrivateKey.publicKey

// Retrieve Alice's key
if let alicePrivateKey: P256.KeyAgreement.PrivateKey = try await Keychain.Keys.queryOne(
    applicationTag: aliceTag
) {
    // Perform key agreement
    let sharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
    
    // Derive symmetric key
    let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data(),
        sharedInfo: Data(),
        outputByteCount: 32
    )
    
    // Use symmetricKey for encryption/decryption
}
```

## Error Handling

Handle common errors when working with CryptoKit keys:

```swift
do {
    let tag = "com.example.myapp.key".data(using: .utf8)!
    guard let secKey = try await Keychain.Keys.queryOne(
        keyType: .ellipticCurve(.privateKey),
        applicationTag: tag
    ) else {
        print("Key not found")
        return
    }
    
    // Wrong curve type throws SecKeyConversionError
    let privateKey = try P256.Signing.PrivateKey(secKey: secKey)
    
} catch KeychainError.authenticationFailed {
    print("User cancelled biometric authentication")
} catch let error as SecKeyConversionError {
    print("Key conversion failed: \(error)")
} catch {
    print("Unexpected error: \(error)")
}
```

## Best Practices

### Use Appropriate Accessibility

Choose the right accessibility level for your use case:

```swift
// Most secure: only accessible when device is unlocked
let accessControl = Keychain.AccessControl(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .biometryAny
)

// Available after first unlock (after reboot, locked until first unlock)
let accessControl = Keychain.AccessControl(
    accessibility: .afterFirstUnlockThisDeviceOnly,
    constraint: .biometryAny
)
```

### Tag Naming Convention

Use reverse-domain notation with descriptive key purpose:

```swift
// Good
let tag = "com.example.myapp.user-signing-key".data(using: .utf8)!
let tag = "com.example.myapp.message-encryption-key".data(using: .utf8)!

// Avoid
let tag = "key1".data(using: .utf8)!  // Too generic
```

### Key Deletion

Delete keys when no longer needed:

```swift
try await Keychain.Keys.delete(
    keyType: .ellipticCurve(.privateKey),
    applicationTag: .utf8("com.example.myapp.signing-key")
)
```

## See Also

- ``SecKeyConvertible``
- ``Keychain/Keys``
- ``Keychain/AccessControl``
- <doc:GettingStarted>
