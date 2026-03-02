# Using Item References

Store a reference to a Keychain item for later retrieval without repeating the original query.

## Overview

When your app stores a token or credential in the Keychain, you typically need to retrieve it later, often without reconstructing the full set of query parameters. An ``ItemReference`` solves this by providing an opaque handle that uniquely identifies a Keychain item.

Item references are especially useful for:
- **Token storage**: Store an access token at login, retrieve it on next launch.
- **Item bookmarking**: Let the user pick a credential once, then access it directly.

Item references are supported for all item types except ``Keychain/SecureEnclaveKeys``.

## Obtaining an Item Reference

Call any `add()` method and assign the result to get an ``ItemReference``:

```swift
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "s3cret")

let itemReference = try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.myapp"
)
```

If you don't need the reference, you can simply ignore the result.

## Retrieving an Item by Reference

Pass the reference to `get(itemReference:)` to retrieve the item:

```swift
if let password = try await Keychain.GenericPassword.get(itemReference: itemReference) {
    let string = password.makeUnsafeUTF8String()
}
```

Because the reference uniquely identifies a single item, no additional query parameters are needed.
If the item has been deleted, `get(itemReference:)` returns `nil`.

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
