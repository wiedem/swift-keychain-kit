# Using Secure Enclave Keys

Generate and manage hardware-backed cryptographic keys in the Secure Enclave.

## Overview

The Secure Enclave provides hardware-backed storage for cryptographic keys.
Keys stored in the Secure Enclave cannot be exported from the device, providing
strong protection even if your app is compromised.

There are two ways to work with Secure Enclave keys: through
[CryptoKit](https://developer.apple.com/documentation/cryptokit)
(recommended for most use cases) or through the Security framework via
``Keychain/SecureEnclaveKeys``.

## Checking Availability

Before using Secure Enclave keys, check if the feature is available on the
current device:

```swift
if Keychain.SecureEnclaveKeys.isAvailable {
    // Generate and use Secure Enclave keys
} else {
    // Fall back to regular keychain keys or inform the user
}
```

The `isAvailable` property returns `false` on simulators and devices without a
Secure Enclave.

## Using CryptoKit

CryptoKit provides a high-level API for Secure Enclave keys through
[`SecureEnclave.P256`](https://developer.apple.com/documentation/cryptokit/secureenclave/p256).
Keys are stored in the Keychain as generic passwords using
``Keychain/GenericPasswordConvertible``.

### Generating and Storing a Key

```swift
import CryptoKit
import SwiftKeychainKit

let privateKey = try SecureEnclave.P256.Signing.PrivateKey()

try await Keychain.GenericPassword.add(
    privateKey,
    account: "com.example.myapp.signing-key",
    service: "com.example.myapp"
)
```

The `dataRepresentation` stored in the Keychain is an encrypted blob that only
the Secure Enclave on this device can use to restore the key.

### Retrieving a Key

```swift
let privateKey: SecureEnclave.P256.Signing.PrivateKey? = try await Keychain.GenericPassword.get(
    account: "com.example.myapp.signing-key",
    service: "com.example.myapp"
)
```

### Deleting a Key

```swift
try await Keychain.GenericPassword.delete(
    account: "com.example.myapp.signing-key",
    service: "com.example.myapp",
    accessGroup: .any
)
```

## Using the Security Framework

For direct access to [SecKey](https://developer.apple.com/documentation/security/seckey)
references, use the ``Keychain/SecureEnclaveKeys`` namespace. This is useful
when you need Security framework APIs for cryptographic operations or
fine-grained control over key attributes.

### Generating a Key

```swift
let tag = "com.example.myapp.secure-key".data(using: .utf8)!

let privateKey = try await Keychain.SecureEnclaveKeys.generate(
    applicationTag: tag,
    accessControl: .init(
        accessibility: .whenUnlockedThisDeviceOnly,
        constraint: .biometryAny
    )
)
```

The returned [SecKey](https://developer.apple.com/documentation/security/seckey)
is a reference that lets you request cryptographic operations from the Secure
Enclave. The actual key material never leaves the hardware.

### Retrieving a Key

To retrieve a previously generated key, query it by its application tag:

```swift
if let key = try await Keychain.SecureEnclaveKeys.query(
    applicationTag: .utf8("com.example.myapp.secure-key")
).first {
    // Use the key for cryptographic operations
}
```

> Important: For keys with access constraints, authentication is triggered
when **using** the key for cryptographic operations, not when querying it.
This is different from other Keychain item types (GenericPassword,
InternetPassword, etc.), where authentication is required during the query
itself.

### Deleting a Key

To remove a Secure Enclave key, delete it by its application tag:

```swift
try await Keychain.SecureEnclaveKeys.delete(
    applicationTag: .utf8("com.example.myapp.secure-key")
)
```

## Access Control

Secure Enclave keys have specific access control requirements:

1. Secure Enclave keys never leave the device. The available accessibility
   levels reflect this:
   - ``Keychain/SecureEnclaveKeys/ItemAccessibility/whenUnlockedThisDeviceOnly`` (recommended)
   - ``Keychain/SecureEnclaveKeys/ItemAccessibility/afterFirstUnlockThisDeviceOnly``
   - ``Keychain/SecureEnclaveKeys/ItemAccessibility/whenPasscodeSetThisDeviceOnly``

2. The [`.privateKeyUsage`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/privatekeyusage)
   flag is automatically added to enable cryptographic operations.

3. Secure Enclave keys cannot be synchronized to iCloud Keychain.

## Limitations

- **256-bit ECC only**: Only 256-bit elliptic curve keys are supported
- **No export**: Keys cannot be exported from the Secure Enclave
- **No import**: Keys must be generated in the Secure Enclave; existing keys
  cannot be imported
- **No migration**: Keys cannot migrate to other devices
- **No synchronization**: Keys cannot be synchronized via iCloud Keychain
- **Device required**: Secure Enclave is not available on simulators and
  requires specific hardware (iPhone 5s and later, iPad Air and later,
  Mac with Apple silicon or T2 chip)

## See Also

- ``Keychain/SecureEnclaveKeys``
- ``Keychain/Keys``
- ``Keychain/AccessControl``
- <doc:UsingCryptoKit>
- [Protecting Keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Storing CryptoKit Keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain)
