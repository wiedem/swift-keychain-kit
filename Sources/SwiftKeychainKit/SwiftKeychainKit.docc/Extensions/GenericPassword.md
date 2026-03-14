# ``Keychain/GenericPassword``


## Overview

Generic passwords are the most common type of Keychain item. They store arbitrary password data along with an account identifier and optional service name.

Use generic passwords for:
- App-specific credentials
- API keys and tokens
- User passwords
- Any secret data associated with an account

## Usage Examples

### Adding a Password

```swift
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret123")

try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.app"
)
```

### Retrieving a Password

```swift
let password = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app"
)

if let password {
    let string = password.makeUnsafeUTF8String()
}
```

> Note: ``SecretData/makeUnsafeUTF8String()`` creates an unprotected `String` copy that remains in memory. For security-sensitive scenarios, prefer ``SecretData/withUnsafeBytes(_:)-1qbde`` to work with the data directly.

### Updating a Password

```swift
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "newPassword456")

try await Keychain.GenericPassword.update(
    account: "user@example.com",
    service: "com.example.app",
    to: newPassword
)
```

### Deleting a Password

```swift
try await Keychain.GenericPassword.delete(
    account: "user@example.com",
    service: "com.example.app",
    accessGroup: .any
)
```

## Querying Attributes

Get metadata about stored passwords and obtain item references for subsequent operations:

```swift
let attributes = try await Keychain.GenericPassword.queryAttributes(
    service: "com.example.app",
    limit: .unlimited
)

for attr in attributes {
    print("Account: \(attr.account)")

    // Use the item reference to retrieve, update, or delete the item
    let password = try await Keychain.GenericPassword.get(
        itemReference: attr.itemReference
    )
}
```

## Primary Key

Generic passwords are uniquely identified by:
- **Account** (required): The account identifier
- **Service** (optional): The service name

If two items have the same account and service, they are considered duplicates.

## Topics

### Adding Passwords

- ``Keychain/GenericPassword/add(_:account:service:label:accessGroup:synchronizable:accessControl:authenticationContext:)-7kltu``
- ``Keychain/GenericPassword/add(_:account:service:label:accessGroup:synchronizable:accessControl:authenticationContext:)-5du5t``

### Retrieving Passwords

- ``Keychain/GenericPassword/get(account:service:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)-1w6be``
- ``Keychain/GenericPassword/get(account:service:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)-p27p``
- ``Keychain/GenericPassword/get(itemReference:skipIfUIRequired:authenticationContext:)-1f1np``
- ``Keychain/GenericPassword/get(itemReference:skipIfUIRequired:authenticationContext:)-85sp2``

### Updating Passwords

- ``Keychain/GenericPassword/update(account:service:accessGroup:synchronizable:to:authenticationContext:)``
- ``Keychain/GenericPassword/update(itemReference:to:authenticationContext:)-9ljqx``

### Deleting Passwords

- ``Keychain/GenericPassword/delete(account:service:accessGroup:synchronizable:authenticationContext:)-9zdmx``
- ``Keychain/GenericPassword/delete(account:service:accessGroup:synchronizable:authenticationContext:)-9wgwr``
- ``Keychain/GenericPassword/delete(itemReference:authenticationContext:)-3867x``
- ``Keychain/GenericPassword/delete(itemReference:authenticationContext:)-78klb``

### Querying Multiple Items

- ``Keychain/GenericPassword/query(account:service:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``
- ``Keychain/GenericPassword/query(_:account:service:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``
- ``Keychain/GenericPassword/queryAttributes(account:service:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``

### Attributes

- ``Attributes``
- ``attributes(itemReference:skipIfUIRequired:authenticationContext:)``

## See Also

- ``Keychain/InternetPassword``
- ``Keychain/Keys``
- ``SwiftKeychainKit/KeychainError``
- ``SwiftKeychainKit/SecretData``
