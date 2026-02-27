# Handling Sensitive Data in Memory

Protect passwords, keys, and tokens from lingering in memory.

## Overview

Standard types like
[Data](https://developer.apple.com/documentation/foundation/data) and
[String](https://developer.apple.com/documentation/swift/string) are designed
for general-purpose use, not for secrets. They use Copy-on-Write, which can
create implicit copies, and secrets can linger in memory long after they are
no longer needed. Pages holding secret data may also be swapped to disk.

``SecretData`` addresses these risks:

- **No implicit copies**: Move-only semantics prevent accidental duplication
- **Memory locking**: Pages are locked to reduce the risk of swapping to disk
- **Guaranteed cleanup**: Memory is securely overwritten on deallocation
- **Clear ownership**: Factory methods explicitly indicate whether data is
  copied

## Insecure to Secure

Most secrets originate from insecure sources: user input, network responses, or
other APIs that return `Data` or `String`. The `makeByCopying` factory methods
copy these bytes into locked, protected memory.

The important thing to understand: the source data remains in memory and is
**not** protected. Only the ``SecretData`` copy benefits from locking and
cleanup.

```swift
// The original string remains in unprotected memory
let password = "MyPassword123"
let secret = try SecretData.makeByCopyingUTF8(fromUnsafeString: password)
```

### Choosing the Right Factory Method

**Direct generation** avoids copies entirely:

```swift
// Cryptographically random bytes, no insecure source
let key = try SecretData.makeRandom(count: 32)

// Custom initialization, bytes are written directly into locked memory
let secret = try SecretData(count: 16) { buffer in
    for i in 0..<buffer.count {
        buffer[i] = // ...
    }
}
```

**Copying from existing data** when the source is already in memory:

```swift
// From a String (e.g. user input from a text field)
let secret = try SecretData.makeByCopyingUTF8(fromUnsafeString: userInput)

// From Data (e.g. a network response)
let secret = try SecretData.makeByCopying(from: responseData)

// From CFData (e.g. Security framework results)
let secret = try SecretData.makeByCopying(fromUnsafeData: cfData)
```

**Copying and wiping the source** when possible:

```swift
// Copies from a mutable buffer and zeroes the source
let secret = try SecretData.makeByCopyingAndWiping(from: mutableBuffer)

// Copies from NSMutableData and zeroes its buffer
let secret = try SecretData.makeByCopyingAndWiping(unsafeData: mutableData)
```

These methods overwrite the source buffer with zeros after copying, reducing the
window in which the secret exists in unprotected memory. This only works with
mutable sources.

## Secure Access

Access the protected bytes through ``SecretData/withUnsafeBytes(_:)-1qbde``.
The buffer pointer is only valid for the duration of the closure:

```swift
secret.withUnsafeBytes { bytes in
    // Use the bytes directly, e.g. for HMAC computation
    performCryptographicOperation(with: bytes)
}
```

Avoid escaping the pointer or copying the bytes into unprotected memory inside
the closure.

## Secure to Insecure

Sometimes you need to convert protected data back to standard types, for
example to display a password or pass it to an API that requires `Data`. These
conversions deliberately have `Unsafe` in their name:

```swift
// Creates an unprotected Data copy
let data = secret.makeUnsafeData()

// Creates an unprotected String copy (nil if not valid UTF-8)
let string = secret.makeUnsafeUTF8String()
```

These copies lose all protection: they are not memory-locked, not zeroed on
deallocation, and subject to Copy-on-Write. Use them only when necessary and
keep the result short-lived.

## Duplication

``SecretData`` is move-only and cannot be implicitly copied. When you need a
second reference to the same secret, use ``SecretData/duplicate()``:

```swift
let copy = try secret.duplicate()
```

This creates a second locked buffer with the same content. Both the original and
the copy are independently protected and cleaned up in their respective
`deinit`.

## Keychain Integration

The Keychain APIs consume ``SecretData`` on storage and return it on retrieval:

```swift
// add() consumes the SecretData (move semantics)
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: userInput)
try await Keychain.GenericPassword.add(
    password,
    account: "user@example.com",
    service: "com.example.app"
)
// password is no longer accessible here

// get() returns a new SecretData instance
if let retrieved = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app"
) {
    retrieved.withUnsafeBytes { bytes in
        // Work with the secret
    }
    // retrieved is cleaned up when it goes out of scope
}
```

### Custom Types with GenericPasswordConvertible

For domain-specific types, conform to ``Keychain/GenericPasswordConvertible`` to store
and retrieve them directly:

```swift
struct APIToken: GenericPasswordConvertible {
    let tokenData: SecretData

    init(genericPasswordRepresentation data: consuming some SecretDataProtocol & ~Copyable) throws {
        self.tokenData = try SecretData(count: 32) { buffer in
            data.withUnsafeBytes { source in
                buffer.copyMemory(from: source)
            }
        }
    }

    func genericPasswordRepresentation() throws -> any (SecretDataProtocol & ~Copyable) {
        try tokenData.duplicate()
    }
}

// Store directly
try await Keychain.GenericPassword.add(
    token,
    account: "api-token",
    service: "com.example.app"
)

// Retrieve as your type
let token: APIToken? = try await Keychain.GenericPassword.get(
    account: "api-token",
    service: "com.example.app"
)
```

## Minimizing Exposure

Keep ``SecretData`` instances alive only as long as necessary:

```swift
// Good: short-lived secret
func authenticate(password: String) async throws {
    let secret = try SecretData.makeByCopyingUTF8(fromUnsafeString: password)
    try await performAuthentication(with: secret)
    // secret is deallocated here, memory is wiped
}
```

Avoid storing secrets as long-lived properties. The security benefits diminish
the longer secrets remain in memory.

## See Also

- ``SecretData``
- ``SecretDataProtocol``
- ``SecretDataError``
