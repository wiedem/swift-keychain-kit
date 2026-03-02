public import LocalAuthentication

public extension Keychain.GenericPassword {
    /// Gets the attributes of a generic password using an item reference.
    ///
    /// Retrieves the metadata for the item identified by the given ``ItemReference``. The reference uniquely identifies
    /// a specific Keychain item, so this method guarantees at most one result.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `add()` call.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: The ``Attributes`` if found, `nil` if the referenced item no longer exists (or skipped due to
    ///   `skipIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` for Keychain operation failures.
    static func attributes(
        itemReference: ItemReference<Self>,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> Attributes? {
        let query = Keychain.persistentReferenceQuery(
            itemReference.persistentReferenceData,
            skipIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext
        )

        let results = try Keychain.queryAttributes(
            query: query,
            limit: .one
        ) { items throws(KeychainError) in
            try items.map { attributes throws(KeychainError) in
                try parseAttributes(from: attributes)
            }
        }

        return results.first
    }
}
