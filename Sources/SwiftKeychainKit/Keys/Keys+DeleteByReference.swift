public import LocalAuthentication

public extension Keychain.Keys {
    /// Deletes a key using an item reference.
    ///
    /// Removes the specific key identified by the given ``ItemReference`` from the Keychain.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `addPrivateKey()` call.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///
    /// - Returns: `true` if the key was deleted, `false` if the referenced item no longer exists.
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

    /// Synchronously deletes a key using an item reference.
    ///
    /// This is the synchronous variant of ``delete(itemReference:authenticationContext:)-198hc`` and can be safely
    /// used in `deinit` implementations or other synchronous contexts.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `addPrivateKey()` call.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///
    /// - Returns: `true` if the key was deleted, `false` if the referenced item no longer exists.
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

private extension Keychain.Keys {
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
