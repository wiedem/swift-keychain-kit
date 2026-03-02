public import LocalAuthentication

public extension Keychain.GenericPassword {
    /// Adds a generic password to the Keychain and returns an item reference.
    ///
    /// Stores data in the Keychain with the specified attributes. The entry must not already exist with the same primary key
    /// attributes (account, service, accessGroup, and synchronizable).
    ///
    /// The returned ``ItemReference`` uniquely identifies the stored item and can be persisted for later retrieval
    /// via ``get(itemReference:skipIfUIRequired:authenticationContext:)-1f1np``.
    ///
    /// - Parameters:
    ///   - data: The data to store in the Keychain.
    ///   - account: The account name for this password.
    ///   - service: The service name for this password.
    ///   - label: A user-visible label for the item. Defaults to `nil`.
    ///   - accessGroup: The access group identifier for Keychain sharing. Defaults to `.default`.
    ///   - synchronizable: Whether to synchronize the item via iCloud Keychain. Defaults to `false`.
    ///   - accessControl: The access control settings for the item. Defaults to `.afterFirstUnlockThisDeviceOnly`.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: An ``ItemReference`` that uniquely identifies the stored item.
    ///
    /// - Throws:
    ///   * ``KeychainError/duplicateItem`` if an entry with the same primary attributes exists.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///
    /// - SeeAlso:
    ///   * [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
    ///   * [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
    ///
    /// - Note: Security Consideration: The secret data is stored securely in the Keychain.
    /// The provided data is consumed after storage.
    @discardableResult
    static func add(
        _ data: consuming some SecretDataProtocol & ~Copyable,
        account: String,
        service: String,
        label: String? = nil,
        accessGroup: Keychain.AccessGroup = .default,
        synchronizable: Bool = false,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) async throws -> ItemReference<Self> {
        var query = baseQuery()

        let cfData = try data.makeUnownedCFData()

        applyAddParameters(
            data: cfData,
            account: account,
            service: service,
            label: label,
            accessGroup: accessGroup.valueForAdd,
            synchronizable: synchronizable,
            authenticationContext: authenticationContext,
            to: &query
        )

        try accessControl.apply(to: &query)

        let persistentRef = try Keychain.addItemReturningPersistentReference(query: query)
        return ItemReference(persistentReferenceData: persistentRef)
    }
}

// MARK: - GenericPasswordRepresentable

public extension Keychain.GenericPassword {
    /// Adds a generic password from a custom type to the Keychain and returns an item reference.
    ///
    /// Stores data in the Keychain by first converting the secret to its generic password representation. The entry must not
    /// already exist with the same primary key attributes (account, service, accessGroup, and synchronizable).
    ///
    /// The returned ``ItemReference`` uniquely identifies the stored item and can be persisted for later retrieval
    /// via ``get(itemReference:skipIfUIRequired:authenticationContext:)-1f1np``.
    ///
    /// - Parameters:
    ///   - secret: The secret conforming to ``Keychain/GenericPasswordRepresentable`` to store.
    ///   - account: The account name for this password.
    ///   - service: The service name for this password.
    ///   - label: A user-visible label for the item. Defaults to `nil`.
    ///   - accessGroup: The access group identifier for Keychain sharing. Defaults to `.default`.
    ///   - synchronizable: Whether to synchronize the item via iCloud Keychain. Defaults to `false`.
    ///   - accessControl: The access control settings for the item. Defaults to `.afterFirstUnlockThisDeviceOnly`.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: An ``ItemReference`` that uniquely identifies the stored item.
    ///
    /// - Throws:
    ///   * ``KeychainError/duplicateItem`` if an entry with the same primary attributes exists.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///   * An error from the secret's `genericPasswordRepresentation()` method if conversion fails.
    ///
    /// - SeeAlso:
    ///   * [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
    ///   * [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
    ///
    /// - Note: Security Consideration: The secret data is stored securely in the Keychain.
    /// The provided data is consumed after storage.
    @discardableResult
    static func add(
        _ secret: some Keychain.GenericPasswordRepresentable,
        account: String,
        service: String,
        label: String? = nil,
        accessGroup: Keychain.AccessGroup = .default,
        synchronizable: Bool = false,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) async throws -> ItemReference<Self> {
        try await add(
            secret.genericPasswordRepresentation(),
            account: account,
            service: service,
            label: label,
            accessGroup: accessGroup,
            synchronizable: synchronizable,
            accessControl: accessControl,
            authenticationContext: authenticationContext
        )
    }
}
