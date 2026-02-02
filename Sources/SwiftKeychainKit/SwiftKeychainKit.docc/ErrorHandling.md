# Handling Errors

Respond to errors from Keychain operations and display meaningful messages to your users.

## Overview

SwiftKeychainKit uses ``KeychainError`` for all Keychain operation failures.
Each error carries a strongly-typed ``KeychainError/Code`` that you can match
against in `catch` clauses. Convenience properties like ``KeychainError/duplicateItem``
and ``KeychainError/itemNotFound`` make common cases easy to handle.

## Matching Common Errors

For common Security framework errors, use the convenience properties for cleaner pattern matching:

```swift
do {
    let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
    try await Keychain.GenericPassword.update(
        account: "user@example.com",
        service: "com.example.app",
        to: newPassword
    )
} catch KeychainError.itemNotFound {
    // Update target not found
    print("Item not found")
}
```

```swift
do {
    let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
    try await Keychain.GenericPassword.add(
        password,
        account: "user@example.com",
        service: "com.example.app"
    )
} catch KeychainError.duplicateItem {
    // Item already exists, handle accordingly
    print("Password already exists for this account")
}
```

## Matching Security Framework Errors

Use this pattern when you need to handle OSStatus codes that don't have convenience properties:

```swift
do {
    let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
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

The ``SecurityFrameworkError/message`` property provides the Security framework's
error description for a given `OSStatus` code.

## Handling Multiple Error Types

Combine different error types for comprehensive error handling:

```swift
do {
    let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "new-secret")
    try await Keychain.GenericPassword.update(
        account: "user@example.com",
        service: "com.example.app",
        to: newPassword
    )
} catch KeychainError.itemNotFound {
    // Item doesn't exist, add it instead
    let fallbackPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "new-secret")
    try await Keychain.GenericPassword.add(
        fallbackPassword,
        account: "user@example.com",
        service: "com.example.app"
    )
} catch KeychainError.invalidParameters {
    // Invalid parameters provided
    print("Invalid parameters")
} catch {
    // Other errors
    print("Unexpected error: \(error)")
}
```

## Logging Errors

All error types in SwiftKeychainKit provide detailed technical descriptions through
`CustomDebugStringConvertible`. Use `String(reflecting:)` to include these
descriptions in your logs:

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
        switch code {
        case let .securityError(error) where error.status == errSecDuplicateItem:
            String(localized: "error.duplicateItem")
        case let .securityError(error) where error.status == errSecItemNotFound:
            String(localized: "error.itemNotFound")
        case let .securityError(error) where error.status == errSecAuthFailed:
            String(localized: "error.authenticationFailed")
        case .multipleItemsFound:
            String(localized: "error.multipleItems")
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
- ``SecretDataError``
