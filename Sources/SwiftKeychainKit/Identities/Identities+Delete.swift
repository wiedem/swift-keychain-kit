public import LocalAuthentication

public extension Keychain.Identities {
    // MARK: - Delete

    /// Deletes identities matching the specified criteria.
    ///
    /// Removes all identities from the Keychain that match the provided search parameters.
    ///
    /// - Parameters:
    ///   - issuer: Filter by certificate issuer (normalized issuer sequence).
    ///   - serialNumber: Filter by certificate serial number.
    ///   - label: Filter by label.
    ///   - accessGroup: The access group scope of the identities to delete. Use `.specific(...)` to target a specific
    ///     access group or `.any` to target entries across all access groups.
    ///   - synchronizable: The synchronization scope to match.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access.
    ///
    /// - Returns: `true` if at least one identity was deleted, `false` if no matching identities were found.
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails (other than item not found).
    @discardableResult
    static func delete(
        issuer: Keychain.IssuerScope = .any,
        serialNumber: Keychain.SerialNumberScope = .any,
        label: Keychain.LabelScope = .any,
        accessGroup: Keychain.AccessGroupScope = .any,
        synchronizable: Keychain.SynchronizableScope = .notSynchronized,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> Bool {
        try performDelete(
            issuer: issuer.value,
            serialNumber: serialNumber.value,
            label: label.value,
            accessGroupScope: accessGroup,
            synchronizableScope: synchronizable,
            authenticationContext: authenticationContext
        )
    }

    /// Synchronously deletes identities matching the specified criteria.
    ///
    /// This is the synchronous variant of
    /// ``delete(issuer:serialNumber:label:accessGroup:synchronizable:authenticationContext:)-63i1r`` and can be safely used in
    /// `deinit` implementations or other synchronous contexts.
    ///
    /// - Parameters:
    ///   - issuer: Filter by certificate issuer (normalized issuer sequence).
    ///   - serialNumber: Filter by certificate serial number.
    ///   - label: Filter by label.
    ///   - accessGroup: The access group scope of the identities to delete. Use `.specific(...)` to target a specific
    ///     access group or `.any` to target entries across all access groups.
    ///   - synchronizable: The synchronization scope to match.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access.
    ///
    /// - Returns: `true` if at least one identity was deleted, `false` if no matching identities were found.
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails (other than item not found).
    @discardableResult
    static func delete(
        issuer: Keychain.IssuerScope = .any,
        serialNumber: Keychain.SerialNumberScope = .any,
        label: Keychain.LabelScope = .any,
        accessGroup: Keychain.AccessGroupScope = .any,
        synchronizable: Keychain.SynchronizableScope = .notSynchronized,
        authenticationContext: LAContext? = nil
    ) throws(KeychainError) -> Bool {
        try performDelete(
            issuer: issuer.value,
            serialNumber: serialNumber.value,
            label: label.value,
            accessGroupScope: accessGroup,
            synchronizableScope: synchronizable,
            authenticationContext: authenticationContext
        )
    }
}

private extension Keychain.Identities {
    @discardableResult
    static func performDelete(
        issuer: Data?,
        serialNumber: Data?,
        label: String?,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        authenticationContext: LAContext?
    ) throws(KeychainError) -> Bool {
        var query = baseQuery()

        try applyDeleteParameters(
            issuer: issuer,
            serialNumber: serialNumber,
            label: label,
            accessGroupScope: accessGroupScope,
            synchronizableScope: synchronizableScope,
            authenticationContext: authenticationContext,
            to: &query
        )

        return try Keychain.deleteItems(query: query)
    }
}
