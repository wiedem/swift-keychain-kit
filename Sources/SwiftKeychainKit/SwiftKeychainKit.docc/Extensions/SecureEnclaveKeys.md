# ``Keychain/SecureEnclaveKeys``


## Overview

The SecureEnclaveKeys API provides generation and management of cryptographic keys in the Secure Enclave. Keys stored in the Secure Enclave benefit from hardware-backed security and cannot be exported from the device.

The Secure Enclave is available on:
- iPhone 5s and later
- iPad Air and later
- iPad mini 2 and later
- iPad Pro (all models)
- Mac computers with Apple silicon or the T2 chip

Only 256-bit elliptic curve (ECC) keys are supported. Keys must be generated directly in the Secure Enclave and cannot be imported.

## Checking Availability

Before using Secure Enclave keys, check if the feature is available on the current device:

```swift
if Keychain.SecureEnclaveKeys.isAvailable {
    // Generate and use Secure Enclave keys
} else {
    // Fall back to regular keychain keys or inform the user
}
```

The `isAvailable` property returns `false` on simulators and devices without a Secure Enclave.

## Generating Keys

Generate a new key in the Secure Enclave:

```swift
let tag = "com.example.myapp.secure-key".data(using: .utf8)!

let privateKey = try await Keychain.SecureEnclaveKeys.generate(
    applicationTag: tag,
    accessControl: .init(
        accessibility: .whenUnlockedThisDeviceOnly,
        constraint: .biometryAny
    )
)

// The key is now stored in the Secure Enclave and ready to use
```

## Access Control Requirements

Secure Enclave keys have specific access control requirements:

1. **ThisDeviceOnly Accessibility**: Only accessibility values ending with `ThisDeviceOnly` are allowed:
   - `.whenUnlockedThisDeviceOnly` (recommended)
   - `.afterFirstUnlockThisDeviceOnly`
   - `.whenPasscodeSetThisDeviceOnly`

2. **Private Key Usage**: The `.privateKeyUsage` flag is automatically added to enable cryptographic operations.

3. **No Synchronization**: Secure Enclave keys cannot be synchronized to iCloud Keychain.

## Retrieving Keys

Query for a specific key by its application tag:

```swift
if let key = try await Keychain.SecureEnclaveKeys.query(
    applicationTag: .utf8("com.example.myapp.secure-key")
).first {
    // Use the key for signing or decryption
}
```

Query all Secure Enclave keys:

```swift
let keys = try await Keychain.SecureEnclaveKeys.query(
    limit: .unlimited
)
```

## Using Keys for Cryptographic Operations

Sign data with a Secure Enclave key:

```swift
guard let privateKey = try await Keychain.SecureEnclaveKeys.query(
    applicationTag: .utf8("com.example.myapp.secure-key")
).first else {
    return
}

let dataToSign = "Important message".data(using: .utf8)!
var error: Unmanaged<CFError>?

guard let signature = SecKeyCreateSignature(
    privateKey,
    .ecdsaSignatureMessageX962SHA256,
    dataToSign as CFData,
    &error
) as Data? else {
    throw error!.takeRetainedValue()
}

// Verify with the public key
if let publicKey = SecKeyCopyPublicKey(privateKey) {
    let verified = SecKeyVerifySignature(
        publicKey,
        .ecdsaSignatureMessageX962SHA256,
        dataToSign as CFData,
        signature as CFData,
        &error
    )
    print("Signature valid: \(verified)")
}
```

### Authentication for Cryptographic Operations

**Important**: For Secure Enclave keys with access constraints, authentication is triggered when **using** the key for cryptographic operations, not when querying it:

```swift
// Generate key with biometry constraint
let tag = "com.example.myapp.secure-key".data(using: .utf8)!
let privateKey = try await Keychain.SecureEnclaveKeys.generate(
    applicationTag: tag,
    accessControl: .init(
        accessibility: .whenUnlockedThisDeviceOnly,
        constraint: .biometryAny
    )
)

// Query returns the key WITHOUT prompting for authentication
guard let queriedKey = try await Keychain.SecureEnclaveKeys.query(
    applicationTag: .utf8("com.example.myapp.secure-key")
).first else {
    return
}

let dataToSign = "Important message".data(using: .utf8)!

// Authentication prompt appears HERE when using the key
let signature = SecKeyCreateSignature(
    queriedKey,
    .ecdsaSignatureMessageX962SHA256,
    dataToSign as CFData,
    &error
)
```

This behavior is different from other keychain item types (GenericPassword, InternetPassword, etc.), where authentication is required during the query operation itself.

## Querying Key Attributes

Retrieve metadata about a key without loading the key itself:

```swift
let attributes = try await Keychain.SecureEnclaveKeys.queryAttributes(
    applicationTag: .utf8("com.example.myapp.secure-key")
)

if let attr = attributes.first {
    print("Tag: \(String(data: attr.applicationTag, encoding: .utf8) ?? "unknown")")
    print("Label: \(attr.label ?? "none")")
    print("Access Group: \(attr.accessGroup ?? "default")")
}
```

## Deleting Keys

Remove a specific key:

```swift
try await Keychain.SecureEnclaveKeys.delete(
    applicationTag: .utf8("com.example.myapp.secure-key")
)
```

### Special Behavior with Application Password Constraint

**Important**: When a Secure Enclave key is protected with an `applicationPassword` access constraint, deleting it requires authentication:

```swift
import LocalAuthentication

// Set up authentication context with password
let context = LAContext()
let password = "my-app-password".data(using: .utf8)!
context.setCredential(password, type: .applicationPassword)

// Delete with authentication context
let deleted = try await Keychain.SecureEnclaveKeys.delete(
    applicationTag: .utf8("com.example.myapp.secure-key"),
    authenticationContext: context
)
```

**Note**: This is specific to Secure Enclave keys. Other keychain item types (GenericPassword, InternetPassword, etc.) can be deleted without authentication, regardless of access constraints.

## Primary Key

Secure Enclave keys are uniquely identified by:
- **keyType**: Always `.ellipticCurve(.privateKey)` for Secure Enclave keys
- **applicationLabel**: An identifier for the key (defaults to the public key hash)
- **applicationTag**: An application-specific tag

For most use cases, you'll identify keys using the `applicationTag` attribute, which serves as a convenient, application-defined identifier.

## Limitations

- **256-bit ECC only**: Only 256-bit elliptic curve keys are supported
- **No export**: Keys cannot be exported from the Secure Enclave
- **No import**: Keys must be generated in the Secure Enclave; existing keys cannot be imported
- **ThisDeviceOnly**: Keys cannot migrate to other devices
- **No synchronization**: Keys cannot be synchronized via iCloud Keychain
- **Device required**: Secure Enclave is not available on simulators

## Topics

### Availability

- ``isAvailable``

### Generating Keys

- ``generate(applicationTag:applicationLabel:label:accessGroup:accessControl:authenticationContext:)``

### Querying Keys

- ``query(applicationTag:applicationLabel:accessGroup:authenticationContext:limit:)``

### Deleting Keys

- ``delete(applicationTag:applicationLabel:accessGroup:authenticationContext:)-6t36``
- ``delete(applicationTag:applicationLabel:accessGroup:authenticationContext:)-94714``

### Attributes

- ``Attributes``
- ``queryAttributes(applicationTag:applicationLabel:accessGroup:authenticationContext:limit:)``

### Access Control

- ``AccessControl``
- ``ItemAccessibility``

## See Also

- ``Keychain/Keys``
- ``Keychain/AccessControl``
- [Storing Keys in the Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave)
