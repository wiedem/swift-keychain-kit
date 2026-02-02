public import LocalAuthentication
private import Security

public extension Keychain.InternetPassword {
    /// Attributes of an internet password stored in the Keychain.
    ///
    /// Contains metadata about an internet password entry.
    struct Attributes: Sendable {
        /// The account name (username) for this password.
        public let account: String

        /// The server name or domain.
        public let server: String

        /// The network protocol used.
        public let networkProtocol: NetworkProtocol?

        /// The authentication type used.
        public let authenticationType: AuthenticationType?

        /// The port number.
        public let port: Int

        /// The path on the server.
        public let path: String

        /// The security domain (HTTP realm).
        public let securityDomain: String

        /// A user-visible label for the item.
        public let label: String?

        /// The accessibility level of the item.
        public let itemAccessibility: Keychain.ItemAccessibility

        /// The access group of the item.
        public let accessGroup: String

        /// Whether the item is synchronized via iCloud Keychain.
        public let synchronizable: Bool

        /// The date the item was created.
        public let creationDate: Date

        /// The date the item was last modified.
        public let modificationDate: Date
    }

    // MARK: - Attributes Query

    /// Queries attributes of internet passwords.
    ///
    /// Fetches metadata for entries identified by the specified criteria.
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
    /// - Returns: An array of `Attributes` matching the criteria. May be empty if no matches found (or items skipped
    ///   due to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` for Keychain operation failures.
    static func queryAttributes(
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
    ) async throws(KeychainError) -> [Attributes] {
        var query = baseQuery()

        try applyAttributesParameters(
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

        return try Keychain.queryAttributes(
            query: query,
            limit: limit
        ) { items throws(KeychainError) in
            try items.map { attributes throws(KeychainError) -> Attributes in
                try parseAttributes(from: attributes)
            }
        }
    }
}

// MARK: - Attributes parsing

extension Keychain.InternetPassword {
    static func parseAttributes(from dict: [String: Any]) throws(KeychainError) -> Attributes {
        guard let account = Keychain.ItemAttributes.Account.get(from: dict),
              let server = Keychain.ItemAttributes.Server.get(from: dict),
              let itemAccessibility: Keychain.ItemAccessibility = Keychain.ItemAttributes.ItemAccessibility.get(from: dict),
              let accessGroup = Keychain.ItemAttributes.AccessGroup.get(from: dict),
              let creationDate = Keychain.ItemAttributes.CreationDate.get(from: dict),
              let modificationDate = Keychain.ItemAttributes.ModificationDate.get(from: dict)
        else {
            throw .attributeParsingFailed
        }

        let networkProtocol: NetworkProtocol? = Keychain.ItemAttributes.NetworkProtocol.get(
            from: dict
        )
        let authenticationType: AuthenticationType? = Keychain.ItemAttributes.AuthenticationType.get(
            from: dict
        )

        return Attributes(
            account: account,
            server: server,
            networkProtocol: networkProtocol,
            authenticationType: authenticationType,
            port: Keychain.ItemAttributes.Port.get(from: dict) ?? 0,
            path: Keychain.ItemAttributes.Path.get(from: dict) ?? "",
            securityDomain: Keychain.ItemAttributes.SecurityDomain.get(from: dict) ?? "",
            label: Keychain.ItemAttributes.Label.get(from: dict),
            itemAccessibility: itemAccessibility,
            accessGroup: accessGroup,
            synchronizable: Keychain.ItemAttributes.Synchronizable.get(from: dict) ?? false,
            creationDate: creationDate,
            modificationDate: modificationDate
        )
    }
}
