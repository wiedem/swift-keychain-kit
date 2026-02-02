public import Foundation

public extension Keychain {
    /// A type that can be initialized from a secure generic password representation.
    ///
    /// Conforming types provide an initializer that consumes a ``SecretDataProtocol`` value to build an instance.
    ///
    /// - Note: Security Consideration: The initializer consumes secret data. Implementations
    /// should avoid unnecessary copies and ensure secrets are not retained longer than needed.
    protocol GenericPasswordInitializable: ~Copyable {
        /// Creates a new instance from a secure generic password representation.
        ///
        /// - Parameter data: The secret bytes that represent the value.
        ///
        /// - Throws: Any error that occurs while interpreting the secret bytes.
        ///
        /// - Note: Security Consideration: The input contains sensitive information.
        /// Minimize copies and clear from memory when no longer needed.
        init(genericPasswordRepresentation data: consuming some SecretDataProtocol & ~Copyable) throws
    }

    /// A type that can provide a secure generic password representation.
    ///
    /// Conforming types expose a ``SecretDataProtocol`` value that represents their secret bytes.
    ///
    /// - Note: Security Consideration: The returned data contains sensitive information.
    /// Minimize copies and clear from memory when no longer needed.
    protocol GenericPasswordRepresentable: ~Copyable {
        /// Returns a secure generic password representation of this value.
        ///
        /// - Returns: The secret bytes representing this value.
        ///
        /// - Throws: Any error that occurs while producing the representation.
        ///
        /// - Note: Security Consideration: The returned data contains sensitive information.
        /// Minimize copies and clear from memory when no longer needed.
        func genericPasswordRepresentation() throws -> any (SecretDataProtocol & ~Copyable)
    }

    /// A type that can both provide and consume a generic password representation.
    typealias GenericPasswordConvertible = GenericPasswordInitializable & GenericPasswordRepresentable
}

public extension Keychain.GenericPasswordInitializable {
    /// Creates a new instance by copying generic password bytes from a raw buffer.
    ///
    /// This initializer copies the provided bytes into secure storage before initializing the value.
    ///
    /// - Parameter bytes: A raw buffer containing the generic password bytes.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the buffer is empty (count == 0).
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    ///
    /// - Note: Security Consideration: This initializer creates a copy of the input data.
    /// The original buffer remains in memory and must be handled securely by the caller.
    init(genericPasswordRepresentation bytes: UnsafeRawBufferPointer) throws {
        let secretData = try SecretData.makeByCopying(from: bytes)
        try self.init(genericPasswordRepresentation: secretData)
    }

    /// Creates a new instance by copying generic password bytes from a contiguous byte source.
    ///
    /// This initializer copies the provided bytes into secure storage before initializing the value.
    ///
    /// - Parameter data: A value providing contiguous bytes to copy into secure storage.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the source is empty.
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    ///
    /// - Note: Security Consideration: This initializer creates a copy of the input data. The original
    /// data remains in memory and must be handled securely by the caller.
    init(genericPasswordRepresentation data: some ContiguousBytes) throws {
        let secretData = try SecretData.makeByCopying(from: data)
        try self.init(genericPasswordRepresentation: secretData)
    }

    /// Creates a new instance by copying and wiping generic password bytes from a mutable buffer.
    ///
    /// This factory method copies the provided bytes into secure storage and then overwrites the source buffer with zeros.
    ///
    /// - Parameter bytes: A mutable buffer containing the generic password bytes to copy and wipe.
    ///
    /// - Returns: A new instance initialized from the copied data.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if the buffer is empty (count == 0).
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    ///
    /// - Note: Security Consideration: This method creates a copy of the input data. The source
    /// buffer is overwritten after the copy, but any other copies that existed before this call are unaffected. The caller is
    /// responsible for ensuring there are no additional copies.
    static func makeByCopyingAndWiping(
        genericPasswordRepresentation bytes: UnsafeMutableRawBufferPointer
    ) throws -> Self {
        let secretData = try SecretData.makeByCopyingAndWiping(from: bytes)
        return try Self(genericPasswordRepresentation: secretData)
    }
}
