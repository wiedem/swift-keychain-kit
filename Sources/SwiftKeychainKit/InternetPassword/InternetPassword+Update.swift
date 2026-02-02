public import LocalAuthentication
private import Security

public extension Keychain.InternetPassword {
    // MARK: - Update

    /// Updates internet password entries matching the specified criteria.
    ///
    /// This method can update one or multiple entries depending on the scope parameters provided. Use ``Keychain/QueryScope/any`` for scope
    /// parameters to match entries regardless of that attribute's value, or use ``Keychain/QueryScope/specific(_:)`` to match only entries with
    /// that exact value.
    ///
    /// - Important: Unlike ``add(_:account:server:protocol:authenticationType:port:path:securityDomain:label:accessGroup:synchronizable:accessControl:authenticationContext:)``, this method can update multiple entries if the criteria
    /// match more than one entry. To update a single specific entry, provide ``Keychain/QueryScope/specific(_:)`` for all optional attributes.
    ///
    /// - Parameters:
    ///   - account: The account name for the password(s).
    ///   - server: The server name.
    ///   - protocolScope: The network protocol scope. Use `.any` to match any protocol, or `.specific(protocol)` to match
    ///     only that protocol. Defaults to `.any`.
    ///   - authenticationTypeScope: The authentication type scope. Defaults to `.any`.
    ///   - portScope: The port number scope. Defaults to `.any`.
    ///   - pathScope: The path scope. Defaults to `.any`.
    ///   - securityDomainScope: The security domain scope. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - data: The new password data to store.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access.
    ///
    /// - Throws: ``KeychainError/itemNotFound`` if no matching entries exist. ``KeychainError`` for other Keychain
    ///   operation failures.
    ///
    /// - Note: Security Consideration: The new secret data is stored securely in the Keychain.
    /// The provided data is consumed after storage.
    static func updateMatching(
        account: String,
        server: String,
        protocol protocolScope: Keychain.ProtocolScope = .any,
        authenticationType authenticationTypeScope: Keychain.AuthenticationTypeScope = .any,
        port portScope: Keychain.PortScope = .any,
        path pathScope: Keychain.PathScope = .any,
        securityDomain securityDomainScope: Keychain.SecurityDomainScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        to data: consuming some SecretDataProtocol & ~Copyable,
        authenticationContext: LAContext? = nil
    ) async throws {
        var query = baseQuery()

        try applyUpdateParameters(
            account: account,
            server: server,
            protocol: protocolScope.value,
            authenticationType: authenticationTypeScope.value,
            port: portScope.value,
            path: pathScope.value,
            securityDomain: securityDomainScope.value,
            accessGroupScope: accessGroupScope,
            synchronizableScope: synchronizableScope,
            authenticationContext: authenticationContext,
            to: &query
        )

        let attributesToUpdate: [String: Any] = try [
            kSecValueData as String: data.makeUnownedCFData(),
        ]

        try Keychain.updateItems(
            query: query,
            attributesToUpdate: attributesToUpdate
        )
    }
}
