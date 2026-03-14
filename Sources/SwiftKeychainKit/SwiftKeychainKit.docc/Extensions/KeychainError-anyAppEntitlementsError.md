# ``SwiftKeychainKit/KeychainError/anyAppEntitlementsError``

## Overview

The `anyAppEntitlementsError` error indicates that the app's entitlements are not properly configured for Keychain operations, or could not be read at runtime.

Common causes include:

- The app is missing required Keychain entitlements entirely, causing all Keychain operations to fail.
- The app has no default access group configured (no keychain access groups and no application identifier in entitlements).
- The app's entitlements could not be read at runtime when resolving the `.default` access group.

## Usage Examples

### Catching Entitlement Errors

```swift
do {
    let password = try await Keychain.GenericPassword.get(
        account: "user@example.com",
        service: "com.example.app"
    )
} catch KeychainError.anyAppEntitlementsError {
    // Entitlements are missing, incomplete, or could not be read
    print("Check your app's Keychain entitlements configuration")
}
```

### Inspecting the Underlying Error

If you need details about the failure, match against the error code directly to access the underlying error:

```swift
} catch let error as KeychainError {
    if case let .appEntitlementsError(underlyingError) = error.code {
        print("Entitlement error: \(underlyingError.map(String.init(reflecting:)) ?? "unknown")")
    }
}
```

## Resolution

1. Verify that your app's entitlements include at least one of:
   - [keychain-access-groups](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
   - [application-identifier](https://developer.apple.com/documentation/bundleresources/entitlements/application-identifier)
   - [com.apple.security.application-groups](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
2. Ensure the app is properly code-signed with the correct provisioning profile.
3. If the error occurs during `.default` access group resolution and you don't need to target a specific access group, use a broader search with `any` instead:

```swift
// Searches across all access groups without resolving the default group
let passwords = try await Keychain.GenericPassword.query(
    account: "user@example.com",
    service: "com.example.app",
    accessGroup: .any
)
```

## See Also

- ``SwiftKeychainKit/KeychainError``
- ``Keychain/AccessGroupScope``
