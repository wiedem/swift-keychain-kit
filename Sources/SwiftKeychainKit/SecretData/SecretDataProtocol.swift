/// A type that provides secure storage for sensitive data.
///
/// Conforming types represent containers for secrets such as passwords, cryptographic keys, or authentication tokens.
/// They are expected to protect the stored data against unintended disclosure, for example through memory locking,
/// secure cleanup on deallocation, or other platform-specific mechanisms. The specific security guarantees are the
/// responsibility of each conforming type.
///
/// ``SecretDataProtocol`` is a [noncopyable
/// type](https://github.com/swiftlang/swift-evolution/blob/main/proposals/0390-noncopyable-structs-and-enums.md),
/// preventing uncontrolled duplication of secret material. Access to the underlying bytes is exclusively provided
/// through ``withUnsafeBytes(_:)``, ensuring that the conforming type retains control over its memory.
///
/// The library provides ``SecretData`` as its built-in conforming type, which uses memory locking (`mlock`) and
/// guaranteed zeroization on deallocation.
public protocol SecretDataProtocol: ~Copyable, Sendable {
    /// Provides read-only access to the stored bytes.
    ///
    /// The closure receives a buffer pointer that is only valid for the duration of the call. Conforming types must
    /// ensure that the pointer remains valid and the memory is not modified while the closure executes.
    ///
    /// - Parameter body: A closure that receives an `UnsafeRawBufferPointer` to the stored bytes and returns a value.
    ///
    /// - Returns: The value returned by the closure.
    ///
    /// - Throws: Rethrows any error thrown by the closure.
    ///
    /// - Important: Do not store or escape the buffer pointer beyond the closure scope.
    borrowing func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R
}
