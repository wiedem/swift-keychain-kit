# Sharing Keychain Items

Share Keychain items between your app, extensions, and other apps from the same team.

## Overview

By default, Keychain items are only accessible to the app that created them.
To share items with app extensions or other apps from the same development team,
store them in a shared access group.

## Setting Up Keychain Access Groups

Add a shared Keychain access group in your Xcode project:

1. Select your target and open the **Signing & Capabilities** tab
2. Add the **Keychain Sharing** capability
3. Add an access group identifier (e.g. `com.example.shared`)

Xcode automatically prefixes the identifier with your team ID, resulting in a
full group identifier like `ABCDE12345.com.example.shared`. Add the same group
to every target that needs access.

### Using App Groups

Alternatively, you can share Keychain items through
[App Groups](https://developer.apple.com/documentation/xcode/configuring-app-groups).
App Groups also enable sharing non-Keychain data like UserDefaults and file
containers.

There are two important differences to Keychain access groups:

- App Group identifiers are **not** prefixed with the team ID. They use the
  `group.` prefix instead (e.g. `group.com.example.shared`).
- An App Group can **never** be the default Keychain access group, because the
  app's application identifier always takes precedence.

## Storing Items in a Shared Group

Use `.identifier()` to store an item in a specific access group:

```swift
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "shared-secret")

try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.app",
    accessGroup: .identifier("ABCDE12345.com.example.shared")
)
```

When no access group is specified, `.default` is used, which stores the item
in the app's default group.

## Retrieving Shared Items

For operations that target a single item (`get`, `update`), specify the access
group directly:

```swift
let password = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    accessGroup: .identifier("ABCDE12345.com.example.shared")
)
```

For operations that can match multiple items (`query`, `delete`), use
``Keychain/AccessGroupScope`` to control which groups are searched:

```swift
// Search only in a specific group
let passwords = try await Keychain.GenericPassword.query(
    service: .specific("com.example.app"),
    accessGroup: .specific("ABCDE12345.com.example.shared"),
    limit: .unlimited
)

// Search across all of the app's access groups
let allPasswords = try await Keychain.GenericPassword.query(
    service: .specific("com.example.app"),
    accessGroup: .any,
    limit: .unlimited
)
```

## Why Two Types for Access Groups?

When storing or retrieving a specific item (`add`, `get`, `update`), the item
belongs to exactly one group. These operations use ``Keychain/AccessGroup``.

When searching or deleting (`query`, `delete`), you may want to match items
across multiple groups. These operations use ``Keychain/AccessGroupScope``,
which adds the `.any` option to search all groups the app has access to.

## Default Access Group

The system determines the default access group from a concatenation of:

1. Keychain access groups (from the `keychain-access-groups` entitlement)
2. The app's application identifier (team ID + bundle ID)
3. App Groups (from the `com.apple.security.application-groups` entitlement)

The first entry in this list becomes the default. If no Keychain access groups
are configured, the application identifier is the default.

You can read the available access groups and the default group at runtime
through ``AppEntitlementsAccessGroupProvider``:

```swift
let defaultGroup = try AppEntitlementsAccessGroupProvider.defaultKeychainAccessGroup
let keychainGroups = try AppEntitlementsAccessGroupProvider.keychainAccessGroups
let appGroups = try AppEntitlementsAccessGroupProvider.applicationGroups
```

> Important: The default access group depends on the app's application
identifier. If the App ID prefix changes (for example, after an
[App Transfer](https://developer.apple.com/help/app-store-connect/transfer-an-app/overview-of-app-transfer)),
items stored in the previous default group become inaccessible. To avoid this,
store shared items in an explicit Keychain access group rather than relying on
the default.

> Important: Using `.default` in an ``Keychain/AccessGroupScope`` requires
resolving the app's default access group at runtime, which can throw
``KeychainError/anyAppEntitlementsError`` if the entitlements cannot be read.
In contrast, `.any` does not require resolution and cannot throw this error.

## See Also

- ``Keychain/AccessGroupScope``
- ``Keychain/AccessGroup``
- ``AppEntitlementsAccessGroupProvider``
- [Configuring Keychain Sharing](https://developer.apple.com/documentation/xcode/configuring-keychain-sharing)
- [Sharing Access to Keychain Items Among a Collection of Apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
- [Technical Note TN2311: Managing Multiple App ID Prefixes](https://developer.apple.com/library/archive/technotes/tn2311/_index.html)
