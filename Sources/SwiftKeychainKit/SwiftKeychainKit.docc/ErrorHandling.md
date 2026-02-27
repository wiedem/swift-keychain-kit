# Handling Errors

Respond to errors from Keychain operations and display meaningful messages to your users.

## Overview

SwiftKeychainKit uses typed throws with ``KeychainError`` for all Keychain
operation failures. The compiler knows the error type, so you can match
against specific cases directly in your `catch` clauses without casting.

Each error carries a strongly-typed ``KeychainError/Code`` that you can match
against. Convenience properties like ``KeychainError/duplicateItem`` and
``KeychainError/itemNotFound`` make common cases easy to handle.

## Matching Common Errors

Use convenience properties to handle frequently encountered errors:

```swift
do {
    let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
    try await Keychain.GenericPassword.add(
        password,
        account: "user@example.com",
        service: "com.example.app"
    )
} catch KeychainError.duplicateItem {
    // Item already exists, update it instead
    let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
    try await Keychain.GenericPassword.update(
        account: "user@example.com",
        service: "com.example.app",
        to: newPassword
    )
} catch KeychainError.itemNotFound {
    print("Item not found")
} catch {
    print("Unexpected error: \(error)")
}
```

## Matching Security Framework Errors

For `OSStatus` codes that don't have convenience properties, match against
the ``SecurityFrameworkError`` directly:

```swift
do {
    try await Keychain.GenericPassword.update(
        account: "user@example.com",
        service: "com.example.app",
        to: newPassword
    )
} catch let error as KeychainError {
    if case let .securityError(error) = error.code {
        switch error.status {
        case errSecParam:
            print("Invalid parameters passed to the Security API")
        case errSecDecode:
            print("Security framework failed to decode the item")
        default:
            print("Security error: \(error.message ?? "Unknown")")
        }
    }
}
```

The ``SecurityFrameworkError/message`` property provides the Security
framework's error description for a given `OSStatus` code.

## Logging Errors

All error types in SwiftKeychainKit provide detailed technical descriptions
through `CustomDebugStringConvertible`. Use `String(reflecting:)` to include
these descriptions in your logs:

```swift
} catch {
    logger.error("\(String(reflecting: error))")
    // Example output:
    // "Security error -25299: The specified item already exists in the keychain."
    // "Failed to decode Keychain data as UTF-8 string"
}
```

## Providing Localized Error Messages

SwiftKeychainKit does not conform to
[LocalizedError](https://developer.apple.com/documentation/foundation/localizederror).
This gives you full control over the wording, tone, and supported languages of
error messages shown to your users.

Add the conformance in your app to map error codes to your own localized strings:

```swift
import Security
import SwiftKeychainKit

extension KeychainError: @retroactive LocalizedError {
    public var errorDescription: String? {
        switch self {
        case KeychainError.duplicateItem:
            String(localized: "error.duplicateItem")
        case KeychainError.itemNotFound:
            String(localized: "error.itemNotFound")
        case KeychainError.authenticationFailed:
            String(localized: "error.authenticationFailed")
        case KeychainError.securityError(errSecDecode):
            String(localized: "error.decodeFailed")
        default:
            String(localized: "error.keychainOperationFailed")
        }
    }
}
```

The `default` branch provides a generic localized message for all remaining
error codes, including other Security framework errors.

## See Also

- ``KeychainError``
- ``SecurityFrameworkError``
- ``SecretDataError``
