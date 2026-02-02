public import BasicContainers
public import LocalAuthentication
private import Security

public extension Keychain.InternetPassword {
    // MARK: - Query

    /// Queries internet passwords matching the specified criteria.
    ///
    /// Returns all entries that match the provided search parameters.
    ///
    /// - Parameters:
    ///   - accountScope: The account name scope. Use `.any` to match any account, or `.specific(name)` to match only that
    ///     account. Defaults to `.any`.
    ///   - serverScope: The server name scope. Use `.any` to match any server, or `.specific(name)` to match only that
    ///     server. Defaults to `.any`.
    ///   - protocolScope: The network protocol scope. Use `.any` to match any protocol, or `.specific(protocol)` to match
    ///     only that protocol. Defaults to `.any`.
    ///   - authenticationTypeScope: The authentication type scope. Use `.any` to match any type, or `.specific(type)` to
    ///     match only that type. Defaults to `.any`.
    ///   - portScope: The port number scope. Use `.any` to match any port, or `.specific(number)` to match only that port.
    ///     Defaults to `.any`.
    ///   - pathScope: The path scope. Use `.any` to match any path, or `.specific(path)` to match only that path. Defaults
    ///     to `.any`.
    ///   - securityDomainScope: The security domain scope. Use `.any` to match any domain, or `.specific(domain)` to match
    ///     only that domain. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///   - limit: The maximum number of results to return. Defaults to `.one`.
    ///
    /// - Returns: An array of ``SecretData`` objects matching the criteria. May be empty if no matches found (or items
    ///   skipped due to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails.
    ///
    /// - Note: Security Consideration: The returned data contains sensitive information.
    /// Minimize its lifetime and clear from memory when no longer needed.
    static func query(
        account accountScope: Keychain.AccountScope = .any,
        server serverScope: Keychain.ServerScope = .any,
        protocol protocolScope: Keychain.ProtocolScope = .any,
        authenticationType authenticationTypeScope: Keychain.AuthenticationTypeScope = .any,
        port portScope: Keychain.PortScope = .any,
        path pathScope: Keychain.PathScope = .any,
        securityDomain securityDomainScope: Keychain.SecurityDomainScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws -> UniqueArray<SecretData> {
        var query = baseQuery()

        try applyQueryParameters(
            accountScope: accountScope,
            serverScope: serverScope,
            protocolScope: protocolScope,
            authenticationTypeScope: authenticationTypeScope,
            portScope: portScope,
            pathScope: pathScope,
            securityDomainScope: securityDomainScope,
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
