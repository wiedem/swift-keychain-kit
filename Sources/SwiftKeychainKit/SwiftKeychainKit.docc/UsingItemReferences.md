# Using Item References

Store a reference to a Keychain item for later retrieval without repeating the original query.

## Overview

Every `add()` method returns an ``ItemReference``, an opaque handle that uniquely identifies the stored item. Instead of keeping track of the primary key attributes, you can use the reference to retrieve, update, or delete the item directly.

Item references are especially useful for:
- **Token storage**: Store an access token at login, retrieve it on next launch.
- **Item bookmarking**: Let the user pick a credential once, then access it directly.

Item references are supported for all item types except ``Keychain/SecureEnclaveKeys``.

## Storing and Retrieving by Reference

Store an item and keep the returned reference:

```swift
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "s3cret")

let itemReference = try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.myapp"
)
```

Pass the reference to `get(itemReference:)` to retrieve the item later:

```swift
let password = try await Keychain.GenericPassword.get(itemReference: itemReference)
```

No additional query parameters are needed. If the item has been deleted,
`get(itemReference:)` returns `nil`. If you don't need the reference, simply
ignore the return value of `add()`.

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
