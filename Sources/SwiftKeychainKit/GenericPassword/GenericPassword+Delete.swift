public import LocalAuthentication

public extension Keychain.GenericPassword {
    // MARK: - Delete

    /// Deletes generic passwords matching the specified criteria.
    ///
    /// Removes all entries from the Keychain that match the provided search parameters. Returns `true` if at least one entry
    /// was deleted, `false` if no matching entries were found.
    ///
    /// Use optional parameters to narrow the deletion scope. When parameters are omitted, all entries matching the remaining
    /// criteria will be deleted.
    ///
    /// - Parameters:
    ///   - account: The account name scope. Use `.any` to match any account, or `.specific(name)` to match only that
    ///     account. Defaults to `.any`.
    ///   - service: The service name scope. Use `.any` to match any service, or `.specific(name)` to match only that
    ///     service. Defaults to `.any`.
    ///   - accessGroup: The access group scope of the entries to delete. Use `.specific(...)` to target a specific
    ///     access group or `.any` to target entries across all access groups.
    ///   - synchronizable: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: `true` if at least one entry was deleted, `false` if no matching entries were found.
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails (other than item not found).
    @discardableResult
    static func delete(
        account: Keychain.AccountScope = .any,
        service: Keychain.ServiceScope = .any,
        accessGroup: Keychain.AccessGroupScope,
        synchronizable: Keychain.SynchronizableScope = .notSynchronized,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> Bool {
        try performDelete(
            accountScope: account,
            serviceScope: service,
            accessGroupScope: accessGroup,
            synchronizableScope: synchronizable,
            authenticationContext: authenticationContext
        )
    }

    /// Synchronously deletes generic passwords matching the specified criteria.
    ///
    /// This is the synchronous variant of ``delete(account:service:accessGroup:synchronizable:authenticationContext:)-9zdmx`` and can
    /// be safely used in `deinit` implementations or other synchronous contexts.
    ///
    /// Use optional parameters to narrow the deletion scope. When parameters are omitted, all entries matching the remaining
    /// criteria will be deleted.
    ///
    /// - Parameters:
    ///   - account: The account name scope. Use `.any` to match any account, or `.specific(name)` to match only that
    ///     account. Defaults to `.any`.
    ///   - service: The service name scope. Use `.any` to match any service, or `.specific(name)` to match only that
    ///     service. Defaults to `.any`.
    ///   - accessGroup: The access group scope of the entries to delete. Use `.specific(...)` to target a specific
    ///     access group or `.any` to target entries across all access groups.
    ///   - synchronizable: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: `true` if at least one entry was deleted, `false` if no matching entries were found.
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails (other than item not found).
    @discardableResult
    static func delete(
        account: Keychain.AccountScope = .any,
        service: Keychain.ServiceScope = .any,
        accessGroup: Keychain.AccessGroupScope,
        synchronizable: Keychain.SynchronizableScope = .notSynchronized,
        authenticationContext: LAContext? = nil
    ) throws(KeychainError) -> Bool {
        try performDelete(
            accountScope: account,
            serviceScope: service,
            accessGroupScope: accessGroup,
            synchronizableScope: synchronizable,
            authenticationContext: authenticationContext
        )
    }
}

private extension Keychain.GenericPassword {
    @discardableResult
    static func performDelete(
        accountScope: Keychain.AccountScope,
        serviceScope: Keychain.ServiceScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        authenticationContext: LAContext?
    ) throws(KeychainError) -> Bool {
        var query = baseQuery()

        try applyDeleteParameters(
            accountScope: accountScope,
            serviceScope: serviceScope,
            accessGroupScope: accessGroupScope,
            synchronizableScope: synchronizableScope,
            authenticationContext: authenticationContext,
            to: &query
        )

        return try Keychain.deleteItems(query: query)
    }
}
