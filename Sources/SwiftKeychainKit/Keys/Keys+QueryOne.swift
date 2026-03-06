public import LocalAuthentication
public import Security

public extension Keychain.Keys {
    /// Queries for a single key matching the specified criteria.
    ///
    /// This is a convenience method that returns a single matching key or `nil` if none found. If multiple keys match the
    /// criteria, a ``KeychainError/multipleItemsFound`` error is thrown to indicate that the query parameters are not specific
    /// enough.
    ///
    /// - Parameters:
    ///   - keyType: The type and class of key to search for.
    ///   - applicationTag: The application tag scope. Use `.any` to match any tag, or `.specific(data)` to match only
    ///     that tag. Defaults to `.any`.
    ///   - applicationLabelScope: The application label scope. Use `.any` to match any label, or `.specific(data)` to match
    ///     only that label. Defaults to `.any`.
    ///   - keySizeInBitsScope: The key size scope. Use `.any` to match any size, or `.specific(bits)` to match only that
    ///     size. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.default`.
    ///   - synchronizable: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///
    /// - Returns: The matching [SecKey](https://developer.apple.com/documentation/security/seckey), or `nil`
    ///   if not found (or skipped due to `skipIfUIRequired`).
    ///
    /// - Throws:
    ///   * ``KeychainError/multipleItemsFound`` if more than one key matches the criteria.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///
    /// - Note: Security Consideration: The returned key may represent sensitive material.
    /// Minimize its lifetime and avoid unnecessary copies.
    static func queryOne(
        keyType: AsymmetricKeyType,
        applicationTag: Data,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        keySizeInBits keySizeInBitsScope: Keychain.KeySizeInBitsScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .default,
        synchronizable: Bool = false,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws -> SecKey? {
        let results = try await query(
            keyType: keyType.scope,
            applicationTag: .specific(applicationTag),
            applicationLabel: applicationLabelScope,
            keySizeInBits: keySizeInBitsScope,
            accessGroup: accessGroupScope,
            synchronizable: synchronizable ? .synchronized : .notSynchronized,
            skipItemsIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext,
            limit: .count(2)
        )

        guard results.count <= 1 else {
            throw KeychainError.multipleItemsFound
        }

        return results.first
    }
}

// MARK: - SecKeyInitializable

public extension Keychain.Keys {
    /// Queries for a single key and converts it to a custom type.
    ///
    /// This is a convenience method that returns a single matching key converted to the specified type, or `nil` if none found.
    /// If multiple keys match the criteria, a ``KeychainError/multipleItemsFound`` error is thrown to indicate that the query
    /// parameters are not specific enough.
    ///
    /// - Parameters:
    ///   - keyType: The type and class of key to search for.
    ///   - applicationTag: The application tag for this key.
    ///   - applicationLabelScope: The application label scope. Use `.any` to match any label, or `.specific(data)` to match only
    ///     that label. Defaults to `.any`.
    ///   - keySizeInBitsScope: The key size scope. Use `.any` to match any size, or `.specific(bits)` to match only that
    ///     size. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.default`.
    ///   - synchronizable: The synchronization scope to match. Defaults to `false`.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///
    /// - Returns: The matching `Key` object, or `nil` if not found (or skipped due to `skipIfUIRequired`).
    ///
    /// - Throws:
    ///   * ``KeychainError/multipleItemsFound`` if more than one key matches the criteria.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///   * An error from the `Key` type's initializer if conversion fails.
    ///
    /// - Note: Security Consideration: The returned key may represent sensitive material.
    ///   Minimize its lifetime and avoid unnecessary copies.
    static func queryOne<Key: SecKeyInitializable>(
        keyType: AsymmetricKeyType,
        applicationTag: Data,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        keySizeInBits keySizeInBitsScope: Keychain.KeySizeInBitsScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .default,
        synchronizable: Bool = false,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws -> Key? {
        try await queryOne(
            keyType: keyType,
            applicationTag: applicationTag,
            applicationLabel: applicationLabelScope,
            keySizeInBits: keySizeInBitsScope,
            accessGroup: accessGroupScope,
            synchronizable: synchronizable,
            skipIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext
        ).flatMap { secKey in
            try Key(secKey: secKey)
        }
    }
}

// MARK: - AsymmetricKeyTypeProviding

public extension Keychain.Keys {
    /// Queries for a single key of a specific type determined by the Key type itself.
    ///
    /// This is a convenience method that returns a single matching key converted to the specified type, or `nil` if none found.
    /// The key type is automatically determined from the `Key` type's `asymmetricKeyType` property. If multiple keys match the
    /// criteria, a ``KeychainError/multipleItemsFound`` error is thrown to indicate that the query parameters are not specific
    /// enough.
    ///
    /// - Parameters:
    ///   - applicationTag: The application tag for this key.
    ///   - applicationLabelScope: The application label scope. Use `.any` to match any label, or `.specific(data)` to match only
    ///     that label. Defaults to `.any`.
    ///   - keySizeInBitsScope: The key size scope. Use `.any` to match any size, or `.specific(bits)` to match only that
    ///     size. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.default`.
    ///   - synchronizable: The synchronization scope to match. Defaults to `false`.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///
    /// - Returns: The matching `Key` object, or `nil` if not found (or skipped due to `skipIfUIRequired`).
    ///
    /// - Throws:
    ///   * ``KeychainError/multipleItemsFound`` if more than one key matches the criteria.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///   * An error from the `Key` type's initializer if conversion fails.
    ///
    /// - Note: Security Consideration: The returned key may represent sensitive material.
    ///   Minimize its lifetime and avoid unnecessary copies.
    static func queryOne<Key: SecKeyInitializable & AsymmetricKeyTypeProviding>(
        applicationTag: Data,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        keySizeInBits keySizeInBitsScope: Keychain.KeySizeInBitsScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .default,
        synchronizable: Bool = false,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws -> Key? {
        try await queryOne(
            keyType: Key.asymmetricKeyType,
            applicationTag: applicationTag,
            applicationLabel: applicationLabelScope,
            keySizeInBits: keySizeInBitsScope,
            accessGroup: accessGroupScope,
            synchronizable: synchronizable,
            skipIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext
        ).flatMap { secKey in
            try Key(secKey: secKey)
        }
    }
}
