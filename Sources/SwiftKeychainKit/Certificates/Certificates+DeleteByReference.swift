public import LocalAuthentication

public extension Keychain.Certificates {
    /// Deletes a certificate using an item reference.
    ///
    /// Removes the specific certificate identified by the given ``ItemReference`` from the Keychain.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `add()` call.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///
    /// - Returns: `true` if the certificate was deleted, `false` if the referenced item no longer exists.
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails (other than item not found).
    @discardableResult
    static func delete(
        itemReference: ItemReference<Self>,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> Bool {
        try performDelete(
            itemReference: itemReference,
            authenticationContext: authenticationContext
        )
    }

    /// Synchronously deletes a certificate using an item reference.
    ///
    /// This is the synchronous variant of ``delete(itemReference:authenticationContext:)-35dbf`` and can be safely
    /// used in `deinit` implementations or other synchronous contexts.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `add()` call.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///
    /// - Returns: `true` if the certificate was deleted, `false` if the referenced item no longer exists.
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails (other than item not found).
    @discardableResult
    static func delete(
        itemReference: ItemReference<Self>,
        authenticationContext: LAContext? = nil
    ) throws(KeychainError) -> Bool {
        try performDelete(
            itemReference: itemReference,
            authenticationContext: authenticationContext
        )
    }
}

private extension Keychain.Certificates {
    @discardableResult
    static func performDelete(
        itemReference: ItemReference<Self>,
        authenticationContext: LAContext?
    ) throws(KeychainError) -> Bool {
        let query = Keychain.persistentReferenceQuery(
            itemReference.persistentReferenceData,
            skipIfUIRequired: false,
            authenticationContext: authenticationContext
        )
        return try Keychain.deleteItems(query: query)
    }
}
