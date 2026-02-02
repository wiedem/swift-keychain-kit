public import LocalAuthentication
private import Security

public extension Keychain.GenericPassword {
    // MARK: - Update

    /// Updates an existing generic password in the Keychain.
    ///
    /// Updates the data for an entry identified by the specified primary key attributes. The combination of account, service,
    /// access group, and synchronizable flag must uniquely identify exactly one entry.
    ///
    /// - Parameters:
    ///   - account: The account name for this password.
    ///   - service: The service name for this password.
    ///   - accessGroup: The access group to use. Defaults to `.default`.
    ///   - synchronizable: Whether the entry is synchronized via iCloud Keychain. Defaults to `false`.
    ///   - data: The new password data to store.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Throws:
    ///   * ``KeychainError/itemNotFound`` if no matching entry exists.
    ///   * ``KeychainError/anyAppEntitlementsError`` if the app's entitlements are missing or cannot be read while
    ///     resolving the default access group.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///
    /// - Note: Security Consideration: The new secret data is stored securely in the Keychain.
    /// The provided data is consumed after storage.
    static func update(
        account: String,
        service: String,
        accessGroup: Keychain.AccessGroup = .default,
        synchronizable: Bool = false,
        to data: consuming some SecretDataProtocol & ~Copyable,
        authenticationContext: LAContext? = nil
    ) async throws {
        var query = baseQuery()

        try applyUpdateParameters(
            account: account,
            service: service,
            accessGroup: accessGroup.valueForGet,
            synchronizable: synchronizable,
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
