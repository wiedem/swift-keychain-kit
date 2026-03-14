# ``Keychain/AccessGroupScope``


## Overview

Access group scopes allow you to control which access groups are searched during Keychain operations. This is particularly useful when your app shares Keychain items with other apps or app extensions.

## Examples

### Searching Across All Access Groups

By default, queries search all of the app's access groups:

```swift
// Search across all access groups
let passwords = try await Keychain.GenericPassword.query(
    account: .any,
    service: "com.example.app",
    accessGroup: .any,
    limit: .unlimited
)
```

### Searching a Specific Access Group

Limit your search to a particular access group for shared items:

```swift
// Search only in a shared access group
let password = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    accessGroup: "ABCDE12345.com.example.shared",
    synchronizable: false
)
```

This is useful when sharing Keychain items between your app and an app extension, or between multiple apps from the same team.

### Using the Default Access Group

Limit your search to the app's default access group:

```swift
// Delete from default access group only
try await Keychain.GenericPassword.delete(
    account: "user@example.com",
    service: "com.example.app",
    accessGroup: .default
)
```

The default access group is typically the first keychain access group in your app's entitlements, or the app ID if no keychain groups are defined.

> Important: Using `.default` requires resolving the app's default access group at runtime, which can throw
> ``KeychainError/anyAppEntitlementsError`` if the entitlements are missing or cannot be read. In contrast, `.any`
> does not require access group resolution and therefore cannot throw this error.

## See Also

- ``Keychain/AccessGroup``
- ``SwiftKeychainKit/KeychainError/anyAppEntitlementsError``
