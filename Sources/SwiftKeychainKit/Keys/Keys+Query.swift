public import BasicContainers
public import LocalAuthentication
public import Security

public extension Keychain.Keys {
    // MARK: - Query Keys

    /// Queries cryptographic keys matching the specified criteria.
    ///
    /// Returns all keys that match the provided search parameters. Use this method when you expect multiple keys or want to
    /// iterate over results.
    ///
    /// - Parameters:
    ///   - keyTypeScope: The type and class of key to search for.
    ///   - applicationTagScope: The application tag scope. Use `.any` to match any tag, or `.specific(data)` to match only
    ///     that tag. Defaults to `.any`.
    ///   - applicationLabelScope: The application label scope. Use `.any` to match any label, or `.specific(data)` to match
    ///     only that label. Defaults to `.any`.
    ///   - keySizeInBitsScope: The key size scope. Use `.any` to match any size, or `.specific(bits)` to match only that
    ///     size. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///   - limit: The maximum number of results to return. Defaults to `.one`.
    ///
    /// - Returns: An array of [SecKey](https://developer.apple.com/documentation/security/seckey) objects matching the
    ///   criteria. May be empty if no matches found (or items skipped due to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails.
    static func query(
        keyType keyTypeScope: Keychain.AsymmetricKeyTypeScope,
        applicationTag applicationTagScope: Keychain.ApplicationTagScope = .any,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        keySizeInBits keySizeInBitsScope: Keychain.KeySizeInBitsScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws(KeychainError) -> [SecKey] {
        var query = baseQuery()

        try applyQueryParameters(
            keyTypeScope: keyTypeScope,
            applicationTagScope: applicationTagScope,
            applicationLabelScope: applicationLabelScope,
            keySizeInBitsScope: keySizeInBitsScope,
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

// MARK: - SecKeyInitializable

public extension Keychain.Keys {
    /// Queries cryptographic keys and converts them to a custom type.
    ///
    /// Returns all keys that match the provided search parameters, converted to the specified type that conforms to
    /// `SecKeyInitializable`. This overload is for non-copyable types.
    ///
    /// - Parameters:
    ///   - keyType: The concrete key type to return. Defaults to `Key.self`.
    ///   - keyTypeScope: The type and class of key to search for.
    ///   - applicationTagScope: The application tag scope. Use `.any` to match any tag, or `.specific(data)` to match only
    ///     that tag. Defaults to `.any`.
    ///   - applicationLabelScope: The application label scope. Use `.any` to match any label, or `.specific(data)` to match
    ///     only that label. Defaults to `.any`.
    ///   - keySizeInBitsScope: The key size scope. Use `.any` to match any size, or `.specific(bits)` to match only that
    ///     size. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///   - limit: The maximum number of results to return. Defaults to `.one`.
    ///
    /// - Returns: An array of `Key` objects matching the criteria. May be empty if no matches found (or items skipped due
    ///   to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails, or an error from the `Key` type's initializer if
    ///   conversion fails.
    static func query<Key: SecKeyInitializable> (
        _ keyType: Key.Type = Key.self,
        keyType keyTypeScope: Keychain.AsymmetricKeyTypeScope,
        applicationTag applicationTagScope: Keychain.ApplicationTagScope = .any,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        keySizeInBits keySizeInBitsScope: Keychain.KeySizeInBitsScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws -> UniqueArray<Key> {
        let secKeys = try await query(
            keyType: keyTypeScope,
            applicationTag: applicationTagScope,
            applicationLabel: applicationLabelScope,
            keySizeInBits: keySizeInBitsScope,
            accessGroup: accessGroupScope,
            synchronizable: synchronizableScope,
            skipItemsIfUIRequired: skipItemsIfUIRequired,
            authenticationContext: authenticationContext,
            limit: limit
        )

        guard secKeys.isEmpty == false else {
            return .init()
        }

        return try UniqueArray<Key>(capacity: secKeys.count) {
            for secKey in secKeys {
                try $0.append(Key(secKey: secKey))
            }
        }
    }

    /// Queries cryptographic keys and converts them to a custom copyable type.
    ///
    /// Returns all keys that match the provided search parameters, converted to the specified type that conforms to
    /// `SecKeyInitializable` and `Copyable`. This overload is for copyable types and returns a standard array.
    ///
    /// - Parameters:
    ///   - keyTypeScope: The type and class of key to search for.
    ///   - applicationTagScope: The application tag scope. Use `.any` to match any tag, or `.specific(data)` to match only
    ///     that tag. Defaults to `.any`.
    ///   - applicationLabelScope: The application label scope. Use `.any` to match any label, or `.specific(data)` to match
    ///     only that label. Defaults to `.any`.
    ///   - keySizeInBitsScope: The key size scope. Use `.any` to match any size, or `.specific(bits)` to match only that
    ///     size. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///   - limit: The maximum number of results to return. Defaults to `.one`.
    ///
    /// - Returns: An array of `Key` objects matching the criteria. May be empty if no matches found (or items skipped due
    ///   to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails, or an error from the `Key` type's initializer if
    ///   conversion fails.
    static func query<Key: SecKeyInitializable & Copyable> (
        keyType keyTypeScope: Keychain.AsymmetricKeyTypeScope,
        applicationTag applicationTagScope: Keychain.ApplicationTagScope = .any,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        keySizeInBits keySizeInBitsScope: Keychain.KeySizeInBitsScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws -> [Key] {
        try await query(
            keyType: keyTypeScope,
            applicationTag: applicationTagScope,
            applicationLabel: applicationLabelScope,
            keySizeInBits: keySizeInBitsScope,
            accessGroup: accessGroupScope,
            synchronizable: synchronizableScope,
            skipItemsIfUIRequired: skipItemsIfUIRequired,
            authenticationContext: authenticationContext,
            limit: limit
        ).map { secKey in
            try Key(secKey: secKey)
        }
    }
}

// MARK: - AsymmetricKeyTypeProviding

public extension Keychain.Keys {
    /// Queries cryptographic keys of a specific type determined by the Key type itself.
    ///
    /// Returns all keys that match the provided search parameters, converted to the specified type that conforms to
    /// `SecKeyInitializable` and `AsymmetricKeyTypeProviding`. The key type is automatically determined from the `Key`
    /// type's `asymmetricKeyType` property. This overload is for non-copyable types.
    ///
    /// - Parameters:
    ///   - keyType: The concrete key type to return.
    ///   - applicationTagScope: The application tag scope. Use `.any` to match any tag, or `.specific(data)` to match only
    ///     that tag. Defaults to `.any`.
    ///   - applicationLabelScope: The application label scope. Use `.any` to match any label, or `.specific(data)` to match
    ///     only that label. Defaults to `.any`.
    ///   - keySizeInBitsScope: The key size scope. Use `.any` to match any size, or `.specific(bits)` to match only that
    ///     size. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///   - limit: The maximum number of results to return. Defaults to `.one`.
    ///
    /// - Returns: An array of `Key` objects matching the criteria. May be empty if no matches found (or items skipped due
    ///   to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails, or an error from the `Key` type's initializer if
    ///   conversion fails.
    static func query<Key: SecKeyInitializable & AsymmetricKeyTypeProviding> (
        _ keyType: Key.Type = Key.self,
        applicationTag applicationTagScope: Keychain.ApplicationTagScope = .any,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        keySizeInBits keySizeInBitsScope: Keychain.KeySizeInBitsScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws -> UniqueArray<Key> {
        try await query(
            keyType: Key.asymmetricKeyType.keychainQueryScope,
            applicationTag: applicationTagScope,
            applicationLabel: applicationLabelScope,
            keySizeInBits: keySizeInBitsScope,
            accessGroup: accessGroupScope,
            synchronizable: synchronizableScope,
            skipItemsIfUIRequired: skipItemsIfUIRequired,
            authenticationContext: authenticationContext,
            limit: limit
        )
    }

    /// Queries cryptographic keys of a specific copyable type determined by the Key type itself.
    ///
    /// Returns all keys that match the provided search parameters, converted to the specified type that conforms to
    /// `SecKeyInitializable` and `AsymmetricKeyTypeProviding`. The key type is automatically determined from the `Key`
    /// type's `asymmetricKeyType` property. This overload is for copyable types and returns a standard array.
    ///
    /// - Parameters:
    ///   - applicationTagScope: The application tag scope. Use `.any` to match any tag, or `.specific(data)` to match only
    ///     that tag. Defaults to `.any`.
    ///   - applicationLabelScope: The application label scope. Use `.any` to match any label, or `.specific(data)` to match
    ///     only that label. Defaults to `.any`.
    ///   - keySizeInBitsScope: The key size scope. Use `.any` to match any size, or `.specific(bits)` to match only that
    ///     size. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///   - limit: The maximum number of results to return. Defaults to `.one`.
    ///
    /// - Returns: An array of `Key` objects matching the criteria. May be empty if no matches found (or items skipped due
    ///   to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails, or an error from the `Key` type's initializer if
    ///   conversion fails.
    static func query<Key: SecKeyInitializable & AsymmetricKeyTypeProviding> (
        applicationTag applicationTagScope: Keychain.ApplicationTagScope = .any,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        keySizeInBits keySizeInBitsScope: Keychain.KeySizeInBitsScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws -> [Key] {
        try await query(
            keyType: Key.asymmetricKeyType.keychainQueryScope,
            applicationTag: applicationTagScope,
            applicationLabel: applicationLabelScope,
            keySizeInBits: keySizeInBitsScope,
            accessGroup: accessGroupScope,
            synchronizable: synchronizableScope,
            skipItemsIfUIRequired: skipItemsIfUIRequired,
            authenticationContext: authenticationContext,
            limit: limit
        )
    }
}
