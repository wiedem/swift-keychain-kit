internal import BasicContainers
public import LocalAuthentication

public extension Keychain.GenericPassword {
    /// Gets a generic password using an item reference.
    ///
    /// Retrieves the password data identified by the given ``ItemReference``. The reference uniquely identifies
    /// a specific Keychain item, so this method guarantees at most one result.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `add()` call.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: The ``SecretData`` if found, `nil` if the referenced item no longer exists (or skipped due to
    ///   `skipIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` for Keychain operation failures.
    ///
    /// - Note: Security Consideration: The returned data contains sensitive information.
    /// Minimize its lifetime and clear from memory when no longer needed.
    static func get(
        itemReference: ItemReference<Self>,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws -> SecretData? {
        let query = Keychain.persistentReferenceQuery(
            itemReference.persistentReferenceData,
            skipIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext
        )

        var results: UniqueArray<SecretData> = try Keychain.queryItems(query: query, limit: .one)
        return results.isEmpty ? nil : results.remove(at: 0)
    }
}

// MARK: - GenericPasswordInitializable

public extension Keychain.GenericPassword {
    /// Gets a generic password using an item reference and converts it to a custom type.
    ///
    /// Retrieves the password data identified by the given ``ItemReference`` and converts it to the specified type.
    /// The reference uniquely identifies a specific Keychain item, so this method guarantees at most one result.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `add()` call.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: The `Password` object if found, `nil` if the referenced item no longer exists (or skipped due to
    ///   `skipIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails, or an error from the `Password` type's initializer if
    ///   conversion fails.
    ///
    /// - Note: Security Consideration: The returned data contains sensitive information.
    /// Minimize its lifetime and clear from memory when no longer needed.
    static func get<Password: Keychain.GenericPasswordInitializable>(
        itemReference: ItemReference<Self>,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws -> Password? {
        guard let secretData = try await get(
            itemReference: itemReference,
            skipIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext
        ) else {
            return nil
        }
        return try Password(genericPasswordRepresentation: secretData)
    }
}
