public import LocalAuthentication

public extension Keychain.InternetPassword {
    // MARK: - Delete

    /// Deletes internet passwords matching the specified criteria.
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
    ///   - server: The server name scope. Use `.any` to match any server, or `.specific(name)` to match only that
    ///     server. Defaults to `.any`.
    ///   - protocol: The network protocol to match. Defaults to `nil`.
    ///   - authenticationType: The authentication type to match. Defaults to `nil`.
    ///   - port: The port number to match. Defaults to `nil`.
    ///   - path: The path on the server to match. Defaults to `nil`.
    ///   - securityDomain: The security domain to match. Defaults to `nil`.
    ///   - accessGroup: The access group scope of the entries to delete. Use `.specific(...)` to target a specific
    ///     access group or `.any` to target entries across all access groups. Defaults to `.any`.
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
        server: Keychain.ServerScope = .any,
        protocol: Keychain.ProtocolScope = .any,
        authenticationType: Keychain.AuthenticationTypeScope = .any,
        port: Keychain.PortScope = .any,
        path: Keychain.PathScope = .any,
        securityDomain: Keychain.SecurityDomainScope = .any,
        accessGroup: Keychain.AccessGroupScope,
        synchronizable: Keychain.SynchronizableScope = .notSynchronized,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> Bool {
        try performDelete(
            account: account,
            server: server,
            protocol: `protocol`,
            authenticationType: authenticationType,
            port: port,
            path: path,
            securityDomain: securityDomain,
            accessGroupScope: accessGroup,
            synchronizableScope: synchronizable,
            authenticationContext: authenticationContext
        )
    }

    /// Synchronously deletes internet passwords matching the specified criteria.
    ///
    /// This is the synchronous variant of
    /// ``Keychain/InternetPassword/delete(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:authenticationContext:)-9sxri``
    /// and can be safely used in `deinit` implementations or other synchronous contexts.
    ///
    /// Use optional parameters to narrow the deletion scope. When parameters are omitted, all entries matching the remaining
    /// criteria will be deleted.
    ///
    /// - Parameters:
    ///   - account: The account name scope. Use `.any` to match any account, or `.specific(name)` to match only that
    ///     account. Defaults to `.any`.
    ///   - server: The server name scope. Use `.any` to match any server, or `.specific(name)` to match only that
    ///     server. Defaults to `.any`.
    ///   - protocol: The network protocol to match. Defaults to `nil`.
    ///   - authenticationType: The authentication type to match. Defaults to `nil`.
    ///   - port: The port number to match. Defaults to `nil`.
    ///   - path: The path on the server to match. Defaults to `nil`.
    ///   - securityDomain: The security domain to match. Defaults to `nil`.
    ///   - accessGroup: The access group scope of the entries to delete. Use `.specific(...)` to target a specific
    ///     access group or `.any` to target entries across all access groups. Defaults to `.any`.
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
        server: Keychain.ServerScope = .any,
        protocol: Keychain.ProtocolScope = .any,
        authenticationType: Keychain.AuthenticationTypeScope = .any,
        port: Keychain.PortScope = .any,
        path: Keychain.PathScope = .any,
        securityDomain: Keychain.SecurityDomainScope = .any,
        accessGroup: Keychain.AccessGroupScope,
        synchronizable: Keychain.SynchronizableScope = .notSynchronized,
        authenticationContext: LAContext? = nil
    ) throws(KeychainError) -> Bool {
        try performDelete(
            account: account,
            server: server,
            protocol: `protocol`,
            authenticationType: authenticationType,
            port: port,
            path: path,
            securityDomain: securityDomain,
            accessGroupScope: accessGroup,
            synchronizableScope: synchronizable,
            authenticationContext: authenticationContext
        )
    }
}

private extension Keychain.InternetPassword {
    @discardableResult
    static func performDelete(
        account: Keychain.AccountScope,
        server: Keychain.ServerScope,
        protocol: Keychain.ProtocolScope,
        authenticationType: Keychain.AuthenticationTypeScope,
        port: Keychain.PortScope,
        path: Keychain.PathScope,
        securityDomain: Keychain.SecurityDomainScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        authenticationContext: LAContext?
    ) throws(KeychainError) -> Bool {
        var query = baseQuery()

        try applyDeleteParameters(
            accountScope: account,
            serverScope: server,
            protocolScope: `protocol`,
            authenticationTypeScope: authenticationType,
            portScope: port,
            pathScope: path,
            securityDomainScope: securityDomain,
            accessGroupScope: accessGroupScope,
            synchronizableScope: synchronizableScope,
            authenticationContext: authenticationContext,
            to: &query
        )

        return try Keychain.deleteItems(query: query)
    }
}
