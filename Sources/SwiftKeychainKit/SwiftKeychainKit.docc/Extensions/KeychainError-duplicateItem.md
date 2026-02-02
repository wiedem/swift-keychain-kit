# ``SwiftKeychainKit/KeychainError/duplicateItem``


## Overview

The `duplicateItem` error occurs when attempting to add an item to the Keychain that already exists with the same primary key attributes (e.g., account and service for passwords).

## Usage Example

### Catching Duplicate Item Errors

```swift
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")

do {
    try await Keychain.GenericPassword.add(
        password,
        account: "user@example.com",
        service: "com.example.app"
    )
} catch KeychainError.duplicateItem {
    // Item already exists, update it instead
    let newPassword = try password.duplicate()
    try await Keychain.GenericPassword.update(
        account: "user@example.com",
        service: "com.example.app",
        to: newPassword
    )
}
```

## See Also

- ``SwiftKeychainKit/KeychainError/itemNotFound``
- ``SwiftKeychainKit/KeychainError``
