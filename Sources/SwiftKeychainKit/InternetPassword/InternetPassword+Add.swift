public import LocalAuthentication
private import Security

public extension Keychain.InternetPassword {
    /// Adds an internet password to the Keychain.
    ///
    /// Stores network credentials in the Keychain with the specified attributes. The entry must not already exist with the same
    /// primary key attributes.
    ///
    /// - Parameters:
    ///   - data: The password data to store.
    ///   - account: The account name (username) for this password.
    ///   - server: The server name or domain.
    ///   - protocol: The network protocol used.
    ///   - authenticationType: The authentication type used.
    ///   - port: The port number. Defaults to `0`.
    ///   - path: The path on the server. Defaults to an empty string.
    ///   - securityDomain: The security domain (HTTP realm). Defaults to an empty string.
    ///   - label: An optional, user-visible label for the item.
    ///   - accessGroup: The access group identifier for Keychain sharing. Use `.default` to apply the default group.
    ///   - synchronizable: Whether to synchronize the item via iCloud Keychain.
    ///   - accessControl: The access control settings for the item.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access.
    ///
    /// - Throws:
    ///   * ``KeychainError/duplicateItem`` if an entry with the same primary attributes exists.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///
    /// - SeeAlso:
    ///   * [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
    ///   * [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
    ///
    /// - Note: Security Consideration: The password data is stored securely in the Keychain.
    /// The provided data is consumed after storage.
    static func add(
        _ data: consuming some SecretDataProtocol & ~Copyable,
        account: String,
        server: String,
        protocol: NetworkProtocol? = nil,
        authenticationType: AuthenticationType? = nil,
        port: Int = 0,
        path: String = "",
        securityDomain: String = "",
        label: String? = nil,
        accessGroup: Keychain.AccessGroup = .default,
        synchronizable: Bool = false,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) async throws {
        var query = baseQuery()

        let cfData = try data.makeUnownedCFData()

        try applyAddParameters(
            data: cfData,
            account: account,
            server: server,
            protocol: `protocol`,
            authenticationType: authenticationType,
            port: port,
            path: path,
            securityDomain: securityDomain,
            label: label,
            accessGroup: accessGroup.valueForAdd,
            synchronizable: synchronizable,
            to: &query
        )

        try accessControl.apply(to: &query)

        authenticationContext.apply(to: &query)

        try Keychain.addItem(query: query)
    }
}
