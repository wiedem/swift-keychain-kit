public import Foundation

public extension SecretData {
    /// Creates an unsafe copy of the secret data as a [Data](https://developer.apple.com/documentation/foundation/data)
    /// instance.
    ///
    /// This method creates a [Data](https://developer.apple.com/documentation/foundation/data) copy of the secret data's
    /// contents. The returned [Data](https://developer.apple.com/documentation/foundation/data) uses copy-on-write semantics
    /// and does not have the memory protection guarantees of ``SecretData``.
    ///
    /// - Returns: A [Data](https://developer.apple.com/documentation/foundation/data) instance containing a copy of the
    ///   secret bytes.
    ///
    /// - Warning: This creates an uncontrolled copy of the secret in memory.
    /// The returned [Data](https://developer.apple.com/documentation/foundation/data) uses copy-on-write semantics, which may
    /// create additional copies that cannot be securely wiped. Only use this when interfacing with APIs that require
    /// [Data](https://developer.apple.com/documentation/foundation/data) and no alternative exists.
    ///
    /// - Important: Clear the returned [Data](https://developer.apple.com/documentation/foundation/data) from memory as soon as possible.
    /// Avoid passing it to APIs that may retain or copy it unnecessarily.
    ///
    /// - Note: Security Consideration: Prefer using ``withUnsafeBytes(_:)-1qbde``
    /// whenever possible to avoid creating copies of the secret data.
    borrowing func makeUnsafeData() -> Data {
        withUnsafeBytes { Data($0) }
    }

    /// Creates an unsafe copy of the secret data as a UTF-8 encoded `String`.
    ///
    /// This method creates a `String` by interpreting the secret data's bytes as UTF-8 encoded text. The returned `String` may
    /// be copied by Swift's runtime and does not have the memory protection guarantees of ``SecretData``.
    ///
    /// - Returns: A UTF-8 encoded `String`, or `nil` if the bytes are not valid UTF-8.
    ///
    /// - Warning: This creates an uncontrolled copy of the secret in memory.
    /// The returned `String` may be copied by Swift's runtime and cannot be securely wiped. Only use this when interfacing with
    /// APIs that require `String` and no alternative exists.
    ///
    /// - Important: Clear the returned `String` from memory as soon as possible.
    /// Avoid passing it to APIs that may retain or copy it unnecessarily.
    ///
    /// - Note: Security Consideration: Prefer using ``withUnsafeBytes(_:)-1qbde``
    /// with UTF-8 decoding whenever possible to avoid creating `String` copies of the secret data.
    borrowing func makeUnsafeUTF8String() -> String? {
        withUnsafeBytes { String(bytes: $0, encoding: .utf8) }
    }
}
