# ``Keychain/QueryScope``


## Overview

`QueryScope<T>` provides explicit control over attribute matching in operations that support flexible filtering, such as ``Keychain/InternetPassword/updateMatching(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:to:authenticationContext:)``.

Use `.any` to match entries regardless of an attribute's value, or `.specific(value)` to match only entries with that exact value.

## Access Groups

Access groups are unique identifiers that control which apps can share Keychain items.

For **add operations**, use ``Keychain/AccessGroup`` to specify:
- `.default` - Use the app's default access group
- `.identifier("...")` - Use a specific access group

For **query, update, and delete operations**, use `QueryScope<String>` for the `accessGroup` parameter:
- `.any` - Search across all access groups
- `.specific("group.identifier")` - Target a specific access group

```swift
// Add: Use AccessGroup
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.app",
    accessGroup: .identifier("group.com.example.shared")
)

// Query: Use QueryScope<String>
let password = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    accessGroup: .specific("group.com.example.shared")
)

// Delete across all groups
try await Keychain.GenericPassword.delete(
    account: .specific("user@example.com"),
    service: .specific("com.example.app"),
    accessGroup: .any  // Searches all access groups
)
```

## Usage Examples

### Matching Any Value

Match all entries regardless of a specific attribute:

```swift
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "new-password")
// Update all passwords for this server, regardless of port
try await Keychain.InternetPassword.updateMatching(
    account: "user@example.com",
    server: "api.example.com",
    port: .any,  // Matches all ports
    to: newPassword
)
```

### Matching Specific Value

Match only entries with a specific attribute value:

```swift
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "new-password")
// Update only passwords on port 443
try await Keychain.InternetPassword.updateMatching(
    account: "user@example.com",
    server: "api.example.com",
    port: .specific(443),  // Matches only port 443
    to: newPassword
)
```

### Combining Multiple Scopes

Combine different scopes for precise filtering:

```swift
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "new-password")
// Update only HTTPS passwords on port 443 with a specific path
try await Keychain.InternetPassword.updateMatching(
    account: "user@example.com",
    server: "api.example.com",
    protocol: .specific(.https),
    port: .specific(443),
    path: .specific("/api/v2"),
    to: newPassword
)
```

## Topics

### AccessGroup Cases

- ``Keychain/ProviderAccessGroup/default``
- ``Keychain/ProviderAccessGroup/identifier(_:)``

### QueryScope Cases

- ``Keychain/QueryScope/any``
- ``Keychain/QueryScope/specific(_:)``

## See Also

- ``Keychain/InternetPassword/updateMatching(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:to:authenticationContext:)``
