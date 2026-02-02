public import LocalAuthentication

public extension Keychain.GenericPassword {
    // MARK: - Get (Single Result)

    /// Gets a single generic password matching the specified criteria.
    ///
    /// This method guarantees uniqueness because the combination of `account`, `service`, `accessGroup`, and `synchronizable`
    /// forms the complete primary key for generic passwords. At most one entry can match these parameters, so this method never
    /// throws ``KeychainError/multipleItemsFound``.
    ///
    /// - Parameters:
    ///   - account: The account name for this password.
    ///   - service: The service name for this password.
    ///   - accessGroup: The access group scope to search in.
    ///   - synchronizable: The synchronization scope to match.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: The ``SecretData`` if found, `nil` if no entry matches (or skipped due to `skipIfUIRequired`).
    ///
    /// - Throws:
    ///   * ``KeychainError/anyAppEntitlementsError`` if the app's entitlements are missing or cannot be read while
    ///     resolving the default access group.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///
    /// - Note: Security Consideration: The returned data contains sensitive information.
    /// Minimize its lifetime and clear from memory when no longer needed.
    static func get(
        account: String,
        service: String,
        accessGroup: Keychain.AccessGroup = .default,
        synchronizable: Bool = false,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws -> SecretData? {
        // The parameters uniquely identify the result, multiple results are not possible
        var results = try await query(
            account: .specific(account),
            service: .specific(service),
            accessGroup: .specific(accessGroup.valueForGet),
            synchronizable: synchronizable ? .synchronized : .notSynchronized,
            skipItemsIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext,
            limit: .one
        )
        return results.isEmpty ? nil : results.remove(at: 0)
    }
}

// MARK: - GenericPasswordInitializable

public extension Keychain.GenericPassword {
    /// Gets a single generic password and converts it to a custom type.
    ///
    /// This method guarantees uniqueness because the combination of `account`, `service`, `accessGroup`, and `synchronizable`
    /// forms the complete primary key for generic passwords. At most one entry can match these parameters, so this method never
    /// throws ``KeychainError/multipleItemsFound``.
    ///
    /// - Parameters:
    ///   - account: The account name for this password.
    ///   - service: The service name for this password.
    ///   - accessGroup: The access group scope to search in.
    ///   - synchronizable: The synchronization scope to match.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: The `Password` object if found, `nil` if no entry matches (or skipped due to `skipIfUIRequired`).
    ///
    /// - Throws:
    ///   * ``KeychainError/anyAppEntitlementsError`` if the app's entitlements are missing or cannot be read while
    ///     resolving the default access group.
    ///   * ``KeychainError`` if the Keychain operation fails, or an error from the `Password` type's initializer if
    ///     conversion fails.
    ///
    /// - Note: Security Consideration: The returned data contains sensitive information.
    /// Minimize its lifetime and clear from memory when no longer needed.
    static func get<Password: Keychain.GenericPasswordInitializable>(
        account: String,
        service: String,
        accessGroup: Keychain.AccessGroup = .default,
        synchronizable: Bool = false,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws -> Password? {
        guard let secretData = try await get(
            account: account,
            service: service,
            accessGroup: accessGroup,
            synchronizable: synchronizable,
            skipIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext
        ) else {
            return nil
        }
        return try Password(genericPasswordRepresentation: secretData)
    }
}
