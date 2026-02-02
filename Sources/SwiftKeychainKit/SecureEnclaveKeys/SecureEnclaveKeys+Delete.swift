public import LocalAuthentication

public extension Keychain.SecureEnclaveKeys {
    /// Deletes private keys stored in the Secure Enclave.
    ///
    /// - Parameters:
    ///   - applicationTag: The application tag to match. Defaults to matching any tag.
    ///   - applicationLabel: The application label to match. Defaults to matching any label.
    ///   - accessGroup: The access group to search in. Defaults to searching in all access groups.
    ///   - authenticationContext: An optional authentication context for the operation.
    ///
    /// - Returns: `true` if at least one key was deleted, `false` if no matching keys were found.
    ///
    /// - Throws: A ``KeychainError`` if the deletion fails.
    ///
    /// - SeeAlso: [Storing Keys in the Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave)
    @discardableResult
    static func delete(
        applicationTag: Keychain.ApplicationTagScope = .any,
        applicationLabel: Keychain.ApplicationLabelScope = .any,
        accessGroup: Keychain.AccessGroupScope = .any,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> Bool {
        try performDelete(
            applicationTagScope: applicationTag,
            applicationLabelScope: applicationLabel,
            accessGroupScope: accessGroup,
            authenticationContext: authenticationContext
        )
    }

    /// Synchronously deletes private keys stored in the Secure Enclave.
    ///
    /// This synchronous variant is provided for use in scenarios where asynchronous operations are not possible, such as in
    /// `deinit` methods.
    ///
    /// - Parameters:
    ///   - applicationTag: The application tag to match. Defaults to matching any tag.
    ///   - applicationLabel: The application label to match. Defaults to matching any label.
    ///   - accessGroup: The access group to search in. Defaults to searching in all access groups.
    ///   - authenticationContext: An optional authentication context for the operation.
    ///
    /// - Returns: `true` if at least one key was deleted, `false` if no matching keys were found.
    ///
    /// - Throws: A ``KeychainError`` if the deletion fails.
    ///
    /// - SeeAlso: [Storing Keys in the Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave)
    @discardableResult
    static func delete(
        applicationTag: Keychain.ApplicationTagScope = .any,
        applicationLabel: Keychain.ApplicationLabelScope = .any,
        accessGroup: Keychain.AccessGroupScope = .any,
        authenticationContext: LAContext? = nil
    ) throws(KeychainError) -> Bool {
        try performDelete(
            applicationTagScope: applicationTag,
            applicationLabelScope: applicationLabel,
            accessGroupScope: accessGroup,
            authenticationContext: authenticationContext
        )
    }
}

private extension Keychain.SecureEnclaveKeys {
    static func performDelete(
        applicationTagScope: Keychain.ApplicationTagScope,
        applicationLabelScope: Keychain.ApplicationLabelScope,
        accessGroupScope: Keychain.AccessGroupScope,
        authenticationContext: LAContext?
    ) throws(KeychainError) -> Bool {
        var query = baseQuery()

        try applyDeleteParameters(
            applicationTagScope: applicationTagScope,
            applicationLabelScope: applicationLabelScope,
            accessGroupScope: accessGroupScope,
            authenticationContext: authenticationContext,
            to: &query
        )

        return try Keychain.deleteItems(query: query)
    }
}
