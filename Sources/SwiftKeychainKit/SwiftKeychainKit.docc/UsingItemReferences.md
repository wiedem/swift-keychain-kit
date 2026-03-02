# Using Item References

Store a reference to a Keychain item for later retrieval without repeating the original query.

## Overview

Every `add()` method returns an ``ItemReference``, an opaque handle that uniquely identifies the stored item for as long as it exists in the Keychain. Instead of keeping track of the primary key attributes, you can use the reference to retrieve, update, or delete the item directly.

Item references are especially useful for:
- **Token storage**: Store an access token at login, retrieve it on next launch.
- **Item bookmarking**: Let the user pick a credential once, then access it directly.

Item references are supported for all item types except ``Keychain/SecureEnclaveKeys``.

## Working with References

Store an item and keep the returned reference:

```swift
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "s3cret")

let itemReference = try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.myapp"
)
```

Use the reference to retrieve, update, or delete the item. No additional query
parameters are needed:

```swift
let password = try await Keychain.GenericPassword.get(itemReference: itemReference)

let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "new-password")
try await Keychain.GenericPassword.update(itemReference: itemReference, to: newPassword)

let deleted = try await Keychain.GenericPassword.delete(itemReference: itemReference)
```

The reference remains valid after an update but becomes invalid after deletion.
`get(itemReference:)` returns `nil` for deleted items. Adding a new item with
the same primary keys creates a separate entry with its own, new reference. The
previous reference remains invalid.

Because a reference always points to exactly one item, operations on it can
never accidentally affect other items. Compare deleting by reference with
deleting by query parameters:

```swift
// Deletes exactly the referenced item
try await Keychain.GenericPassword.delete(itemReference: itemReference)

// Could match multiple items, e.g. if the same account and service exist in more than one access group
try await Keychain.GenericPassword.delete(
    account: .specific("user@example.com"),
    service: .specific("com.example.app"),
    accessGroup: .any
)
```

## Persisting a Reference

``ItemReference`` conforms to `Codable`, so you can serialize it with any encoder for persistent storage:

```swift
struct AppState: Codable {
    var tokenReference: ItemReference<Keychain.GenericPassword>
}

// Encode
let data = try JSONEncoder().encode(appState)

// Decode
let restored = try JSONDecoder().decode(AppState.self, from: data)
let token = try await Keychain.GenericPassword.get(itemReference: restored.tokenReference)
```

## Security Considerations

- An item reference is **not** a secret. It does not contain the item's data, only a lookup handle.
- Item references may become **invalid** after a Keychain restore from backup. Always handle `nil` returns from `get(itemReference:)` gracefully.
- Store references using the same level of protection as any other app state. While they don't reveal secrets, they do indicate which Keychain items your app uses.
