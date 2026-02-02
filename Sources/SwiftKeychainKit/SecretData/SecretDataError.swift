public import Foundation
public import System

/// Errors that can occur when working with ``SecretData``.
public enum SecretDataError: Error, Equatable, Sendable {
    /// Failed to lock memory with `mlock`.
    ///
    /// The operating system failed to lock the allocated memory, preventing it from being swapped to disk. This is a
    /// critical security failure. A common cause is exceeding the process memory lock limit (`RLIMIT_MEMLOCK`).
    ///
    /// - Parameter errno: The system error that caused the failure.
    case memoryLockFailed(errno: Errno)

    /// The provided buffer is empty (zero bytes).
    ///
    /// This error occurs when attempting to create a ``SecretData`` instance with an empty buffer. Secret data must contain at
    /// least one byte.
    case emptyBuffer

    /// The provided buffer has a nil base address.
    ///
    /// This error occurs when the buffer pointer's `baseAddress` is `nil`, indicating invalid or uninitialized memory.
    case invalidBuffer

    /// Failed to convert string to contiguous bytes.
    ///
    /// This occurs when a string cannot provide its UTF-8 bytes as contiguous storage, which is required for secure
    /// copying into ``SecretData``. This is rare in practice, as Swift strings are almost always stored contiguously.
    case stringConversionFailed

    /// Failed to generate random bytes.
    ///
    /// This error occurs when the system's cryptographically secure random number generator
    /// [SecRandomCopyBytes](https://developer.apple.com/documentation/security/secrandomcopybytes(_:_:_:)) fails to generate
    /// the requested random data.
    ///
    /// - Parameter status: The OSStatus error code from
    ///   [SecRandomCopyBytes](https://developer.apple.com/documentation/security/secrandomcopybytes(_:_:_:)).
    case randomGenerationFailed(status: OSStatus)
}

extension SecretDataError: CustomDebugStringConvertible {
    /// A human-readable description of the error for debugging purposes.
    public var debugDescription: String {
        switch self {
        case let .memoryLockFailed(errno):
            "Failed to lock memory with mlock (errno: \(errno))"
        case .emptyBuffer:
            "The provided buffer is empty (zero bytes)"
        case .invalidBuffer:
            "The provided buffer has a nil base address"
        case .stringConversionFailed:
            "Failed to convert string to contiguous bytes"
        case let .randomGenerationFailed(status):
            if let securityErrorMessage {
                "SecRandomCopyBytes failed (status: \(status)): \(securityErrorMessage)"
            } else {
                "SecRandomCopyBytes failed (status: \(status))"
            }
        }
    }
}
