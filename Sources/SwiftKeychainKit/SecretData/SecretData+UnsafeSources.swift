public import Foundation

public extension SecretData {
    /// Creates a new ``SecretData`` instance by copying bytes from a buffer pointer.
    ///
    /// This factory method allocates its own secure buffer, applies best-effort memory protection, and ensures the buffer is
    /// securely wiped when deallocated.
    ///
    /// - Parameter bytes: An `UnsafeRawBufferPointer` to the bytes to copy into secure storage. The caller must ensure
    ///   the pointer is valid for the duration of this call.
    ///
    /// - Returns: A new ``SecretData`` instance containing the copied data.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the buffer is empty (count == 0).
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    ///
    /// - Note: Security Consideration: This method creates a copy of the input data.
    /// The original data remains in memory and must be handled securely by the caller. This is the safest factory method for
    /// creating ``SecretData`` from existing data, as it uses raw pointers without any hidden Copy-on-Write semantics.
    static func makeByCopying(from bytes: UnsafeRawBufferPointer) throws -> SecretData {
        try SecretData(count: bytes.count) { destinationBuffer in
            destinationBuffer.copyMemory(from: bytes)
        }
    }

    /// Creates a new ``SecretData`` instance by copying bytes from a contiguous byte source.
    ///
    /// This factory method allocates its own secure buffer, applies best-effort memory protection, and ensures the buffer is
    /// securely wiped when deallocated.
    ///
    /// - Parameter bytes: A value providing contiguous bytes to copy into secure storage.
    ///
    /// - Returns: A new ``SecretData`` instance containing the copied data.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the source is empty.
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    ///
    /// - Note: Security Consideration: This method creates a copy of the input data. The original
    /// data remains in memory and must be handled securely by the caller. Types conforming to
    /// [ContiguousBytes](https://developer.apple.com/documentation/foundation/contiguousbytes) may use Copy-on-Write
    /// semantics, which can create additional copies that cannot be securely wiped.
    static func makeByCopying(from bytes: some ContiguousBytes) throws -> SecretData {
        var secretData: SecretData!
        try bytes.withUnsafeBytes { buffer in
            secretData = try makeByCopying(from: buffer)
        }
        return secretData
    }

    /// Creates a new ``SecretData`` instance by copying from a
    /// [CFData](https://developer.apple.com/documentation/corefoundation/cfdata).
    ///
    /// - Parameter cfData: The CFData whose bytes should be copied into secure storage.
    ///
    /// - Returns: A new ``SecretData`` instance containing the copied data.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the CFData is empty.
    ///   - ``SecretDataError/invalidBuffer`` if the CFData has no base address.
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    ///
    /// - Note: Security Consideration: This method creates a copy of the input data. The original
    /// [CFData](https://developer.apple.com/documentation/corefoundation/cfdata) remains in memory and must be handled
    /// securely by the caller.
    static func makeByCopying(fromUnsafeData cfData: CFData) throws -> SecretData {
        guard let sourceBuffer = CFDataGetBytePtr(cfData) else {
            throw SecretDataError.invalidBuffer
        }
        let count = CFDataGetLength(cfData)

        return try SecretData(count: count) { secretBuffer in
            secretBuffer.baseAddress!.copyMemory(
                from: sourceBuffer,
                byteCount: count
            )
        }
    }

    /// Creates ``SecretData`` from a Swift `String` using UTF-8 encoding.
    ///
    /// - Parameter string: The string whose UTF-8 bytes should be copied into secure storage.
    ///
    /// - Returns: A new ``SecretData`` instance containing the UTF-8 encoded bytes.
    ///
    /// - Warning:
    /// This is a convenience API with reduced security guarantees. A Swift `String` cannot be reliably wiped, and encoding may
    /// allocate temporary buffers outside of ``SecretData``'s control. Only the resulting buffer is protected and securely
    /// wiped.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the string is empty.
    ///   - ``SecretDataError/stringConversionFailed`` if a contiguous UTF-8 view
    /// is not available.
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    static func makeByCopyingUTF8(fromUnsafeString string: String) throws -> SecretData {
        let utf8View = string.utf8
        let count = utf8View.count

        return try SecretData(count: count) { secretBuffer in
            let success = utf8View.withContiguousStorageIfAvailable { stringBuffer -> Bool in
                secretBuffer.copyMemory(from: UnsafeRawBufferPointer(stringBuffer))
                return true
            } ?? false

            guard success else {
                throw SecretDataError.stringConversionFailed
            }
        }
    }

    /// Creates ``SecretData`` from an [NSString](https://developer.apple.com/documentation/foundation/nsstring) using UTF-8
    /// encoding.
    ///
    /// - Parameter string: The [NSString](https://developer.apple.com/documentation/foundation/nsstring) whose UTF-8 bytes
    ///   should be copied into secure storage.
    ///
    /// - Returns: A new ``SecretData`` instance containing the UTF-8 encoded bytes.
    ///
    /// - Warning:
    /// This is a convenience API with reduced security guarantees. An
    /// [NSString](https://developer.apple.com/documentation/foundation/nsstring) cannot be reliably wiped, and encoding may
    /// allocate temporary buffers outside of ``SecretData``'s control. Only the resulting buffer is protected and securely
    /// wiped.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the string is empty.
    ///   - ``SecretDataError/stringConversionFailed`` if a UTF-8 representation
    /// is not available.
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    static func makeByCopyingUTF8(fromUnsafeString string: NSString) throws -> SecretData {
        let count = string.lengthOfBytes(using: String.Encoding.utf8.rawValue)
        guard let cString = string.utf8String else {
            throw SecretDataError.stringConversionFailed
        }

        return try SecretData(count: count) { destinationBuffer in
            destinationBuffer.baseAddress!.copyMemory(
                from: cString,
                byteCount: count
            )
        }
    }

    /// Creates a new ``SecretData`` instance by consuming data from an unsafe source.
    ///
    /// This factory method takes ownership of the provided data and copies it into secure storage. The consuming parameter
    /// signals that the caller should not use the original data after this call.
    ///
    /// - Parameter data: The data to consume and copy into secure storage.
    ///
    /// - Returns: A new ``SecretData`` instance containing the copied data.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the data is empty.
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    ///
    /// - Note: Security Consideration: This is a convenience method for types conforming
    /// to [ContiguousBytes](https://developer.apple.com/documentation/foundation/contiguousbytes) and `Collection` with `UInt8`
    /// elements. The original data remains in memory after copying due to Copy-on-Write semantics. For mutable sources where
    /// best-effort wiping is desired, use ``SecretData/makeByCopyingAndWiping(unsafeData:)``, though this cannot guarantee
    /// absence of other copies. For the most secure approach, use ``SecretData/init(count:initializer:)`` to generate secrets
    /// directly in the secure buffer.
    static func makeByCopying<T: Collection & ContiguousBytes>(fromUnsafeSource data: consuming T) throws -> SecretData where T.Element == UInt8 {
        try SecretData(count: data.count) { destinationBuffer in
            data.withUnsafeBytes { sourceBuffer in
                destinationBuffer.copyMemory(from: sourceBuffer)
            }
        }
    }
}

public extension SecretData {
    /// Creates a new ``SecretData`` instance by copying from a mutable buffer pointer and wiping the source.
    ///
    /// This factory method allocates its own secure buffer, applies best-effort memory protection, and ensures the buffer is
    /// securely wiped when deallocated. After a successful copy, the source buffer is overwritten with zeros.
    ///
    /// - Parameter bytes: A mutable buffer pointer whose bytes should be copied and then wiped. The caller must ensure
    ///   the pointer is valid for the duration of this call.
    ///
    /// - Returns: A new ``SecretData`` instance containing the copied data.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the buffer is empty (count == 0).
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    ///
    /// - Note: Security Consideration: This method creates a copy of the input data. The source
    /// buffer is overwritten after the copy, but any other copies that existed before this call are unaffected. The caller is
    /// responsible for ensuring there are no additional copies.
    static func makeByCopyingAndWiping(from bytes: UnsafeMutableRawBufferPointer) throws -> SecretData {
        let secretData = try SecretData(count: bytes.count) { destinationBuffer in
            destinationBuffer.copyMemory(from: UnsafeRawBufferPointer(bytes))
        }
        secureZero(bytes.baseAddress!, bytes.count)
        return secretData
    }

    /// Creates a new ``SecretData`` instance by copying from an unsafe
    /// [NSMutableData](https://developer.apple.com/documentation/foundation/nsmutabledata) source and wiping the source buffer.
    ///
    /// This factory method copies the data from the mutable data object into secure storage, then securely overwrites the
    /// source buffer with zeros to reduce the window where unprotected secrets exist in memory.
    ///
    /// - Parameter mutableData: The mutable data to copy and wipe.
    ///
    /// - Returns: A new ``SecretData`` instance containing the copied data.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the mutable data is empty.
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    ///
    /// - Note: Security Consideration: This provides best-effort wiping of the source buffer,
    /// but cannot guarantee absence of other copies. The
    /// [NSMutableData](https://developer.apple.com/documentation/foundation/nsmutabledata) object itself remains allocated
    /// (only its buffer is zeroed), and there may be other references or copies that were created before this call. For the
    /// most secure approach, use ``SecretData/init(count:initializer:)`` to generate secrets directly in the secure buffer
    /// without intermediate copies.
    ///
    /// - Important: The [NSMutableData](https://developer.apple.com/documentation/foundation/nsmutabledata) buffer will be overwritten with zeros after the copy.
    /// Do not use the buffer contents after passing the object to this method.
    static func makeByCopyingAndWiping(unsafeData mutableData: NSMutableData) throws -> SecretData {
        let buffer = UnsafeMutableRawBufferPointer(
            start: mutableData.mutableBytes,
            count: mutableData.length
        )

        return try makeByCopyingAndWiping(from: buffer)
    }
}
