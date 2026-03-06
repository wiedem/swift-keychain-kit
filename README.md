# SwiftKeychainKit

A modern Swift package for convenient, type-safe Keychain operations on iOS and macOS.

[![Swift 6.2](https://img.shields.io/badge/Swift-6.2-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2015+%20|%20macOS%2012+-blue.svg)](https://swift.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.txt)

## Overview

**SwiftKeychainKit** provides a type-safe, modern Swift API for working with the [Data Protection Keychain](https://developer.apple.com/documentation/security/keychain-services) on iOS and macOS.

Apple's [Security framework](https://developer.apple.com/documentation/security) offers a powerful but low-level C API based on untyped dictionaries. SwiftKeychainKit wraps it with dedicated Swift methods for each item class, making it straightforward to store and retrieve sensitive data correctly.

The APIs are designed to guide you towards correct usage. Invalid attribute combinations are caught at compile time, and operation-specific parameter types help prevent common Keychain mistakes.

## Features

- ✅ **Common Keychain types** - Passwords, cryptographic keys, certificates, and identities
- ✅ **Sensitive Data Handling** - Designed to keep passwords and secrets safe in memory
- ✅ **Access Control** - Restrict access with biometry, device passcode, or application passwords
- ✅ **Secure Enclave** - Generate and use keys backed by dedicated security hardware
- ✅ **iCloud Sync** - Share Keychain items across devices via iCloud
- ✅ **[Apple CryptoKit](https://developer.apple.com/documentation/cryptokit) Integration** - Work with CryptoKit keys without manual conversion
- ✅ **Swift 6** - Async/await and strict concurrency throughout
- ✅ **Complete Documentation** - DocC documentation with guides and code examples

## Usage

### Generic Password

```swift
import SwiftKeychainKit

// Store a password and keep a reference
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
let itemReference = try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.app"
)

// Retrieve by reference
let password = try await Keychain.GenericPassword.get(itemReference: itemReference)

// Update by reference
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "new-secret")
try await Keychain.GenericPassword.update(itemReference: itemReference, to: newPassword)

// Delete by reference
try await Keychain.GenericPassword.delete(itemReference: itemReference)
```

You can also retrieve and manage items by their attributes (e.g. account and service). See the [documentation](https://wiedem.github.io/swift-keychain-kit/documentation/swiftkeychainkit/) for details.

### Apple CryptoKit Keys

NIST curve keys (P-256, P-384, P-521) can be stored directly via `Keychain.Keys`:

```swift
import CryptoKit

let privateKey = P256.Signing.PrivateKey()
let tag = "com.example.signing-key".data(using: .utf8)!

let itemReference = try await Keychain.Keys.addPrivateKey(privateKey, applicationTag: tag)

// Retrieve by reference, or use queryOne(applicationTag:) to query by tag
let retrieved: P256.Signing.PrivateKey? = try await Keychain.Keys.get(itemReference: itemReference)
```

Curve25519 keys are stored as generic passwords:

```swift
let privateKey = Curve25519.KeyAgreement.PrivateKey()
try await Keychain.GenericPassword.add(
    privateKey,
    account: "com.example.curve25519-key",
    service: "com.example.app"
)
```

For a complete guide including key agreement and signing workflows, see the [CryptoKit integration guide](https://wiedem.github.io/swift-keychain-kit/documentation/swiftkeychainkit/usingcryptokit).

## Error Handling

All Keychain operations can throw `KeychainError`. Use convenience properties for common cases:

```swift
do {
    try await Keychain.GenericPassword.add(password, account: "user", service: "app")
} catch KeychainError.duplicateItem {
    // Item already exists
} catch KeychainError.itemNotFound {
    // Item not found
}
```

SwiftKeychainKit does not conform to `LocalizedError`, giving you full control over user-facing messages. See the [error handling guide](https://wiedem.github.io/swift-keychain-kit/documentation/swiftkeychainkit/errorhandling) for patterns including localization.

## Installation

### Swift Package Manager

Add the dependency to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/wiedem/swift-keychain-kit.git", from: "1.3.0")
]
```

Then add it to your target:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "SwiftKeychainKit", package: "swift-keychain-kit"),
    ]
)
```

Or add it in Xcode:
1. **File → Add Package Dependencies...**
2. Enter: `https://github.com/wiedem/swift-keychain-kit.git`

## Requirements

- iOS 15.0+ / macOS 12.0+
- Swift 6.2+
- Xcode 16.3+

## Testing

The package includes unit tests and integration tests:

```bash
swift test
```

Integration tests require the TestHost Xcode project with Keychain entitlements. Open `TestHost/TestHost.xcodeproj` and run tests with `⌘U`.

## Documentation

Full DocC documentation is available online:

**[SwiftKeychainKit Documentation →](https://wiedem.github.io/swift-keychain-kit/documentation/swiftkeychainkit/)**

Build documentation locally in Xcode:
```
Product → Build Documentation
```

Or via Swift Package Manager:
```bash
swift package generate-documentation
```

## Contributing

Contributions are welcome! Please feel free to:

- Report bugs or request features via [GitHub Issues](https://github.com/wiedem/swift-keychain-kit/issues)
- Submit pull requests with improvements
- Improve documentation or add examples

## References

- [Apple Developer: Keychain Services](https://developer.apple.com/documentation/security/keychain-services)
- [Apple Developer: Protecting Keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple Developer: CryptoKit](https://developer.apple.com/documentation/cryptokit)

## License

This project is licensed under the MIT License. See [LICENSE.txt](LICENSE.txt) for details.

## Author

Created and maintained by [Holger Wiedemann](https://github.com/wiedem)
