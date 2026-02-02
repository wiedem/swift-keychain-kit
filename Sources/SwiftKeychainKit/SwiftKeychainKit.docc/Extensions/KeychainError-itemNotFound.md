# ``SwiftKeychainKit/KeychainError/itemNotFound``


## Overview

The `itemNotFound` error occurs when attempting to update an item that doesn't exist in the Keychain.

## Usage Examples

### Catching Item Not Found Errors

```swift
do {
    let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "default")
    try await Keychain.GenericPassword.update(
        account: "user@example.com",
        service: "com.example.app",
        to: newPassword
    )
} catch KeychainError.itemNotFound {
    // Item doesn't exist, add it
    let defaultPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "default")
    try await Keychain.GenericPassword.add(
        defaultPassword,
        account: "user@example.com",
        service: "com.example.app"
    )
}
```

### Handling Delete Operations

```swift
// Delete returns a boolean and does not throw itemNotFound
let deleted = try await Keychain.GenericPassword.delete(
    account: .specific("user@example.com"),
    service: .specific("com.example.app")
)
if deleted == false {
    print("Item was already deleted or never existed")
}
```

### Query and Get Behavior

`query()` returns an empty array when no items match, and `get()` / `queryOne()` return `nil`.

## See Also

- ``SwiftKeychainKit/KeychainError/duplicateItem``
- ``SwiftKeychainKit/KeychainError``
