# ``SwiftKeychainKit/SecretData``


## Overview

``SecretData`` provides enhanced security guarantees for handling sensitive information in memory. Unlike standard data types like [Data](https://developer.apple.com/documentation/foundation/data) or [NSData](https://developer.apple.com/documentation/foundation/nsdata), it uses move-only semantics to prevent accidental duplication and ensures that secret data is securely erased from memory when no longer needed.

### Security Features

- **No implicit copies**: Move-only semantics ([~Copyable](https://developer.apple.com/documentation/swift/copyable)) prevent accidental duplication of secrets in memory
- **Memory locking**: Pages are locked to reduce the risk of swapping to disk (best-effort)
- **Guaranteed cleanup**: Memory is securely overwritten when deallocated, ensuring secrets don't linger
- **Clear ownership**: Factory methods explicitly indicate whether data is copied or consumed

### When to Use SecretData

Use ``SecretData`` for:
- User passwords and PINs
- Cryptographic keys (symmetric and private keys)
- Authentication tokens and session secrets
- Any data that should be minimally exposed in memory

Avoid using ``SecretData`` for:
- Public keys or certificates (not secret)
- Data that needs to be frequently copied or shared
- Large data sets where performance is critical

## Usage Guidelines

### Minimize Lifetime

Keep ``SecretData`` instances alive only as long as necessary. The security benefits diminish the longer secrets remain in memory.

```swift
// Good: Short-lived secret
func authenticate(password: String) async throws {
    let secretPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: password)
    try await performAuthentication(with: secretPassword)
    // secretPassword is deallocated here, memory is wiped
}

// Avoid: Long-lived secret
class UserSession {
    let password: SecretData  // Don't store secrets longer than needed
}
```

### Avoid Extraction

Minimize converting to [Data](https://developer.apple.com/documentation/foundation/data) or [String](https://developer.apple.com/documentation/swift/string), as these types lack the same security guarantees:

```swift
// Avoid if possible
secretData.withUnsafeBytes { bytes in
    let unsafeData = Data(bytes)  // Now in unprotected memory
}

// Better: Use the bytes directly
secretData.withUnsafeBytes { bytes in
    // Work with bytes directly
    performOperation(with: bytes)
}
```

### Choose the Right Factory Method

Select the appropriate creation method based on your data source:

| Factory Method | Use Case |
|----------------|----------|
| **Direct Generation (Most Secure)** ||
| ``makeRandom(count:)`` | Generate cryptographically random secrets |
| ``init(count:initializer:)`` | Generate secrets with custom initialization logic |
| **Copying from Buffer Pointers** ||
| ``makeByCopying(from:)-(UnsafeRawBufferPointer)`` | Copy from [UnsafeRawBufferPointer](https://developer.apple.com/documentation/swift/unsaferawbufferpointer); source remains unchanged |
| ``makeByCopying(from:)-(ContiguousBytes)`` | Copy from any [ContiguousBytes](https://developer.apple.com/documentation/foundation/contiguousbytes) type; source remains unchanged |
| **Copying from Foundation/Core Foundation Types** ||
| ``makeByCopying(fromUnsafeData:)`` | Copy from [CFData](https://developer.apple.com/documentation/corefoundation/cfdata) (Keychain/Core Foundation APIs); source remains unchanged |
| ``makeByCopying(fromUnsafeSource:)`` | Copy from [Data](https://developer.apple.com/documentation/foundation/data) or `UInt8` collections; source remains unchanged |
| **Copying from Strings** ||
| ``makeByCopyingUTF8(fromUnsafeString:)-(String)`` | Copy UTF-8 bytes from [String](https://developer.apple.com/documentation/swift/string); source remains unchanged |
| ``makeByCopyingUTF8(fromUnsafeString:)-(NSString)`` | Copy UTF-8 bytes from [NSString](https://developer.apple.com/documentation/foundation/nsstring); source remains unchanged |
| **Copying with Source Wiping (Best-Effort)** ||
| ``makeByCopyingAndWiping(from:)`` | Copy from [UnsafeMutableRawBufferPointer](https://developer.apple.com/documentation/swift/unsafemutablerawbufferpointer) and overwrite source with zeros |
| ``makeByCopyingAndWiping(unsafeData:)`` | Copy from [NSMutableData](https://developer.apple.com/documentation/foundation/nsmutabledata) and overwrite source buffer with zeros |


### Examples

#### Creating from User Input

```swift
func savePassword(_ password: String) async throws {
    let secretPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: password)
    try await Keychain.GenericPassword.add(
        secretPassword,
        account: "user@example.com",
        service: "com.example.app"
    )
}
```

#### Generating Random Keys

```swift
func generateEncryptionKey() throws -> SecretData {
    try SecretData.makeRandom(count: 32)
}
```

#### Reading from Keychain

```swift
func loadPassword() async throws -> SecretData? {
    try await Keychain.GenericPassword.get(
        account: "user@example.com",
        service: "com.example.app"
    )
}
```

## Security Considerations

### Copy-on-Write Semantics

When creating ``SecretData`` from types like [Data](https://developer.apple.com/documentation/foundation/data) or [String](https://developer.apple.com/documentation/swift/string), be aware that these types use Copy-on-Write. The original data remains in memory and is not protected:

```swift
let password = "MyPassword123"  // String remains in memory
let secret = try SecretData.makeByCopyingUTF8(fromUnsafeString: password)
// Only 'secret' is protected; the original 'password' string is not
```

For maximum security, use ``init(count:initializer:)`` to generate secrets directly.

### Memory Locking Limitations

Memory locking is best-effort. The system may:
- Deny locking due to resource limits
- Still swap pages under extreme memory pressure (rare)
- Not support locking on all platforms

Initialization will fail if memory locking fails, ensuring you're aware when protection cannot be guaranteed.

### Thread Safety

``SecretData`` itself is not thread-safe. If you need to access the same secret from multiple threads, ensure proper synchronization.

## Topics

### Creating SecretData

- ``init(count:initializer:)``
- ``makeRandom(count:)``
- ``makeByCopying(from:)-(UnsafeRawBufferPointer)``
- ``makeByCopying(from:)-(ContiguousBytes)``
- ``makeByCopying(fromUnsafeData:)``
- ``makeByCopyingUTF8(fromUnsafeString:)-(String)``
- ``makeByCopyingUTF8(fromUnsafeString:)-(NSString)``
- ``makeByCopying(fromUnsafeSource:)``
- ``makeByCopyingAndWiping(from:)``
- ``makeByCopyingAndWiping(unsafeData:)``

### Accessing Data

- ``withUnsafeBytes(_:)-1qbde``
- ``withUnsafeBytes(_:)-lk68``
- ``duplicate()``

### Comparing Data

- ``==(_:_:)``

## See Also

- ``SecretDataError``
- ``Keychain/GenericPassword``
- ``Keychain/InternetPassword``
