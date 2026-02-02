public import BasicContainers
public import LocalAuthentication

public extension Keychain.GenericPassword {
    // MARK: - Query

    /// Queries generic passwords matching the specified criteria.
    ///
    /// Returns all entries that match the provided search parameters. Use this method when you expect multiple entries or want
    /// to iterate over results.
    ///
    /// - Parameters:
    ///   - accountScope: The account name scope. Use `.any` to match any account, or `.specific(name)` to match only that
    ///     account. Defaults to `.any`.
    ///   - serviceScope: The service name scope. Use `.any` to match any service, or `.specific(name)` to match only that
    ///     service. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///   - limit: The maximum number of results to return. Defaults to `.one`.
    ///
    /// - Returns: An array of ``SecretData`` objects matching the
    ///   criteria. May be empty if no matches found (or items skipped due to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails.
    ///
    /// - Note: Security Consideration: The returned data contains sensitive information.
    /// Minimize its lifetime and clear from memory when no longer needed.
    static func query(
        account accountScope: Keychain.AccountScope = .any,
        service serviceScope: Keychain.ServiceScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws -> UniqueArray<SecretData> {
        var query = baseQuery()

        try applyQueryParameters(
            accountScope: accountScope,
            serviceScope: serviceScope,
            accessGroupScope: accessGroupScope,
            synchronizableScope: synchronizableScope,
            skipItemsIfUIRequired: skipItemsIfUIRequired,
            authenticationContext: authenticationContext,
            to: &query
        )

        return try Keychain.queryItems(
            query: query,
            limit: limit
        )
    }
}

// MARK: - GenericPasswordInitializable

public extension Keychain.GenericPassword {
    /// Queries generic passwords and converts them to a custom type.
    ///
    /// Returns all entries that match the provided search parameters, converted to the specified type that conforms to
    /// ``Keychain/GenericPasswordInitializable``.
    ///
    /// - Parameters:
    ///   - secretType: The type to initialize from each matching generic password.
    ///   - accountScope: The account name scope. Use `.any` to match any account, or `.specific(name)` to match only that
    ///     account. Defaults to `.any`.
    ///   - serviceScope: The service name scope. Use `.any` to match any service, or `.specific(name)` to match only that
    ///     service. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///   - limit: The maximum number of results to return. Defaults to `.one`.
    ///
    /// - Returns: An array of `Secret` objects matching the criteria. May be empty if no matches found (or items skipped due
    ///   to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails, or an error from the `Secret` type's initializer if
    ///   conversion fails.
    ///
    /// - Note: Security Consideration: The returned data contains sensitive information.
    /// Minimize its lifetime and clear from memory when no longer needed.
    static func query<Secret: Keychain.GenericPasswordInitializable>(
        _ secretType: Secret.Type = Secret.self,
        account accountScope: Keychain.AccountScope = .any,
        service serviceScope: Keychain.ServiceScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws -> UniqueArray<Secret> {
        var secretDataItems = try await query(
            account: accountScope,
            service: serviceScope,
            accessGroup: accessGroupScope,
            synchronizable: synchronizableScope,
            skipItemsIfUIRequired: skipItemsIfUIRequired,
            authenticationContext: authenticationContext,
            limit: limit
        )

        return try UniqueArray(capacity: secretDataItems.count) { span in
            while let secretData = secretDataItems.popLast() {
                try span.append(
                    Secret(genericPasswordRepresentation: secretData)
                )
            }
        }
    }
}
