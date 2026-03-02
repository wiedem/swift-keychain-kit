public import LocalAuthentication
public import Security

public extension Keychain.Keys {
    /// Gets a key using an item reference.
    ///
    /// Retrieves the key identified by the given ``ItemReference``. The reference uniquely identifies
    /// a specific Keychain item, so this method guarantees at most one result.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `addPrivateKey()` call.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: The matching [SecKey](https://developer.apple.com/documentation/security/seckey), or `nil`
    ///   if the referenced item no longer exists (or skipped due to `skipIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` for Keychain operation failures.
    ///
    /// - Note: Security Consideration: The returned key may represent sensitive material.
    /// Minimize its lifetime and avoid unnecessary copies.
    static func get(
        itemReference: ItemReference<Self>,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> SecKey? {
        let query = Keychain.persistentReferenceQuery(
            itemReference.persistentReferenceData,
            skipIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext
        )

        let results: [SecKey] = try Keychain.queryItems(query: query, limit: .one)
        return results.first
    }
}

// MARK: - SecKeyInitializable

public extension Keychain.Keys {
    /// Gets a key using an item reference and converts it to a custom type.
    ///
    /// Retrieves the key identified by the given ``ItemReference`` and converts it to the specified type.
    /// The reference uniquely identifies a specific Keychain item, so this method guarantees at most one result.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `addPrivateKey()` call.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: The matching `Key` object, or `nil` if the referenced item no longer exists (or skipped due to
    ///   `skipIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` for Keychain operation failures, or an error from the `Key` type's initializer if
    ///   conversion fails.
    ///
    /// - Note: Security Consideration: The returned key may represent sensitive material.
    ///   Minimize its lifetime and avoid unnecessary copies.
    static func get<Key: SecKeyInitializable>(
        itemReference: ItemReference<Self>,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws -> Key? {
        try await get(
            itemReference: itemReference,
            skipIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext
        ).flatMap { secKey in
            try Key(secKey: secKey)
        }
    }
}
