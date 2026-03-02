internal import Foundation
public import LocalAuthentication

public extension Keychain.Keys {
    // MARK: - Delete Keys

    /// Deletes cryptographic keys matching the specified criteria.
    ///
    /// Removes all keys from the Keychain that match the provided search parameters. Returns `true` if at least one key was
    /// deleted, `false` if no matching keys were found.
    ///
    /// - Parameters:
    ///   - keyType: The type and class of key to delete.
    ///   - applicationTag: An application-specific tag to identify the key to delete.
    ///   - applicationLabel: A label used to identify the key to delete.
    ///   - keySizeInBits: The size of the key in bits.
    ///   - accessGroup: The access group scope of the keys to delete. Use `.specific(...)` to target a specific access
    ///     group or `.any` to target entries across all access groups.
    ///   - synchronizable: The synchronization scope to match.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access.
    ///
    /// - Returns: `true` if at least one key was deleted, `false` if no matching keys were found.
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails (other than item not found).
    @discardableResult
    static func delete(
        keyType: Keychain.AsymmetricKeyTypeScope,
        applicationTag: Keychain.ApplicationTagScope = .any,
        applicationLabel: Keychain.ApplicationLabelScope = .any,
        keySizeInBits: Keychain.KeySizeInBitsScope = .any,
        accessGroup: Keychain.AccessGroupScope = .any,
        synchronizable: Keychain.SynchronizableScope = .notSynchronized,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> Bool {
        try performDelete(
            keyType: keyType,
            applicationTag: applicationTag.value,
            applicationLabel: applicationLabel.value,
            keySizeInBits: keySizeInBits.value,
            accessGroupScope: accessGroup,
            synchronizableScope: synchronizable,
            authenticationContext: authenticationContext
        )
    }

    /// Synchronously deletes cryptographic keys matching the specified criteria.
    ///
    /// This is the synchronous variant of
    /// ``delete(keyType:applicationTag:applicationLabel:keySizeInBits:accessGroup:synchronizable:authenticationContext:)-5qero`` and
    /// can be safely used in `deinit` implementations or other synchronous contexts.
    ///
    /// - Parameters:
    ///   - keyType: The type and class of key to delete.
    ///   - applicationTag: An application-specific tag to identify the key to delete.
    ///   - applicationLabel: A label used to identify the key to delete.
    ///   - keySizeInBits: The size of the key in bits.
    ///   - accessGroup: The access group scope of the keys to delete. Use `.specific(...)` to target a specific access
    ///     group or `.any` to target entries across all access groups.
    ///   - synchronizable: The synchronization scope to match.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access.
    ///
    /// - Returns: `true` if at least one key was deleted, `false` if no matching keys were found.
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails (other than item not found).
    @discardableResult
    static func delete(
        keyType: Keychain.AsymmetricKeyTypeScope,
        applicationTag: Keychain.ApplicationTagScope = .any,
        applicationLabel: Keychain.ApplicationLabelScope = .any,
        keySizeInBits: Keychain.KeySizeInBitsScope = .any,
        accessGroup: Keychain.AccessGroupScope = .any,
        synchronizable: Keychain.SynchronizableScope = .notSynchronized,
        authenticationContext: LAContext? = nil
    ) throws(KeychainError) -> Bool {
        try performDelete(
            keyType: keyType,
            applicationTag: applicationTag.value,
            applicationLabel: applicationLabel.value,
            keySizeInBits: keySizeInBits.value,
            accessGroupScope: accessGroup,
            synchronizableScope: synchronizable,
            authenticationContext: authenticationContext
        )
    }
}

private extension Keychain.Keys {
    @discardableResult
    static func performDelete(
        keyType: Keychain.AsymmetricKeyTypeScope,
        applicationTag: Data?,
        applicationLabel: Data?,
        keySizeInBits: Int?,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        authenticationContext: LAContext? = nil
    ) throws(KeychainError) -> Bool {
        var query = baseQuery()

        try applyDeleteParameters(
            keyTypeScope: keyType,
            applicationTag: applicationTag,
            applicationLabel: applicationLabel,
            keySizeInBits: keySizeInBits,
            accessGroupScope: accessGroupScope,
            synchronizableScope: synchronizableScope,
            to: &query
        )

        authenticationContext.apply(to: &query)

        return try Keychain.deleteItems(query: query)
    }
}
