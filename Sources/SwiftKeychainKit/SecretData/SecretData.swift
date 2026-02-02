private import Foundation

/// A secure container for sensitive data that prevents unintended copies and ensures secure cleanup.
///
/// ``SecretData`` is a [move-only
/// type](https://github.com/swiftlang/swift-evolution/blob/main/proposals/0390-noncopyable-structs-and-enums.md) designed
/// for handling secrets such as passwords, cryptographic keys, and authentication tokens. It provides memory locking to
/// reduce swapping risk and guarantees secure cleanup when deallocated.
///
/// Use factory methods like ``makeByCopying(from:)-(ContiguousBytes)`` or ``makeByCopyingUTF8(fromUnsafeString:)-(String)``
/// to create instances from existing data, or use ``init(count:initializer:)`` to generate secrets directly in secure
/// memory.
///
/// - Note: This type is Sendable because its buffer is initialized once and never mutated
/// after init; only deinit wipes and frees it, and all byte access is read-only.
public struct SecretData: ~Copyable, SecretDataProtocol, @unchecked Sendable {
    let count: Int
    private let buffer: UnsafeMutableRawPointer

    /// Creates a new ``SecretData`` instance with a specified size, initialized using a closure.
    ///
    /// This is the designated initializer for ``SecretData``. It allocates secure memory, locks the pages to reduce swapping
    /// risk, and allows direct initialization of the buffer contents. The memory is automatically cleaned up when deallocated.
    ///
    /// Use this initializer when you can generate or write secrets directly into the secure buffer without intermediate copies.
    ///
    /// - Parameters:
    ///   - count: The number of bytes to allocate. Must be greater than 0.
    ///   - initializer: A closure that receives an `UnsafeMutableRawBufferPointer` to initialize the memory. The buffer
    ///     is pre-zeroed before this closure is called.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if `count` is 0 or negative.
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if memory locking fails.
    ///   - Rethrows any error thrown by the initializer closure.
    ///
    /// - Note: Security Consideration: This is the most secure way to create ``SecretData``
    /// as it avoids intermediate copies. Use this for generating random keys, reading from secure sources, or any scenario
    /// where you can write directly to the buffer.
    public init(
        count: Int,
        initializer: (UnsafeMutableRawBufferPointer) throws -> Void
    ) throws {
        guard count > 0 else {
            throw SecretDataError.emptyBuffer
        }

        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: count,
            alignment: 1
        )

        // Zero buffer to avoid uninitialized memory
        secureZero(buffer, count)

        try withCleanupOnError(buffer: buffer, count: count) {
            try lockMemory(buffer, count: count)

            // Initialize buffer contents
            try initializer(UnsafeMutableRawBufferPointer(
                start: buffer,
                count: count
            ))
        }

        self.count = count
        self.buffer = buffer
    }

    deinit {
        cleanup(buffer, count: count)
    }
}

public extension SecretData {
    /// Provides read-only access to the secret data's bytes.
    ///
    /// This method allows safe access to the secret data without exposing the internal buffer. The closure is called
    /// synchronously with a buffer pointer to the data.
    ///
    /// - Parameter body: A closure that takes an `UnsafeRawBufferPointer` to the secret data and returns a value.
    ///
    /// - Returns: The value returned by the closure.
    ///
    /// - Throws: Rethrows any error thrown by the closure.
    ///
    /// - Important: The buffer pointer is only valid within the closure scope.
    /// Do not store or escape the pointer. Any copies made from this buffer (e.g., to
    /// [Data](https://developer.apple.com/documentation/foundation/data) or `String`) will not have the same security
    /// protections and must be handled carefully.
    borrowing func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        let bufferPointer = UnsafeRawBufferPointer(
            start: buffer,
            count: count
        )
        return try body(bufferPointer)
    }

    /// Provides read-only access to the secret data's bytes with a move-only return type.
    ///
    /// Use this overload when the closure returns a noncopyable value.
    ///
    /// - Parameter body: A closure that takes an `UnsafeRawBufferPointer` to the secret data and returns a noncopyable
    ///   value.
    ///
    /// - Returns: The value returned by the closure.
    ///
    /// - Throws: Rethrows any error thrown by the closure.
    ///
    /// - Important: The buffer pointer is only valid within the closure scope.
    /// Do not store or escape the pointer. Any copies made from this buffer (e.g., to
    /// [Data](https://developer.apple.com/documentation/foundation/data) or `String`) will not have the same security
    /// protections and must be handled carefully.
    borrowing func withUnsafeBytes<R: ~Copyable, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        let bufferPointer = UnsafeRawBufferPointer(
            start: buffer,
            count: count
        )
        return try body(bufferPointer)
    }

    /// Creates an independent copy of this ``SecretData`` instance.
    ///
    /// This method duplicates the secret data into a new, independent ``SecretData`` instance with its own secure buffer. Both
    /// instances will exist in memory simultaneously until one is deallocated.
    ///
    /// - Returns: A new ``SecretData`` instance containing the same bytes.
    ///
    /// - Throws:
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if memory locking fails for the new buffer.
    ///
    /// - Note: Security Consideration: This necessarily duplicates the secret in memory,
    /// creating two locked buffers. Use only when you truly need independent ownership of the same secret data.
    borrowing func duplicate() throws -> SecretData {
        try withUnsafeBytes { buffer in
            try SecretData.makeByCopying(from: buffer)
        }
    }
}

@inline(__always)
func secureZero(
    _ buffer: UnsafeMutableRawPointer,
    _ count: Int
) {
    _ = memset_s(buffer, count, 0, count)
}

@inline(__always)
private func lockMemory(
    _ buffer: UnsafeMutableRawPointer,
    count: Int
) throws(SecretDataError) {
    guard mlock(buffer, count) == 0 else {
        throw SecretDataError.memoryLockFailed(errno: .init(rawValue: errno))
    }
}

@inline(__always)
private func unlockMemory(
    _ buffer: UnsafeMutableRawPointer,
    count: Int
) {
    _ = munlock(buffer, count)
}

private func withCleanupOnError<E: Error>(
    buffer: UnsafeMutableRawPointer,
    count: Int,
    operation: () throws(E) -> Void
) throws(E) {
    do {
        try operation()
    } catch {
        cleanup(buffer, count: count)
        throw error
    }
}

@inline(__always)
private func cleanup(
    _ buffer: UnsafeMutableRawPointer,
    count: Int
) {
    // Zeroize memory (guaranteed not to be optimized away)
    secureZero(buffer, count)

    // Unlock memory (best effort, ignore errors)
    unlockMemory(buffer, count: count)

    // Deallocate
    buffer.deallocate()
}
