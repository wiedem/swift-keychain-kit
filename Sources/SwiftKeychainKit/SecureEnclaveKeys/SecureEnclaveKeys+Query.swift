public import LocalAuthentication
public import Security

public extension Keychain.SecureEnclaveKeys {
    /// Queries for private keys stored in the Secure Enclave.
    ///
    /// - Parameters:
    ///   - applicationTagScope: The application tag to match. Defaults to matching any tag.
    ///   - applicationLabelScope: The application label to match. Defaults to matching any label.
    ///   - accessGroupScope: The access group to search in. Defaults to searching in all access groups.
    ///   - authenticationContext: An optional authentication context for the operation.
    ///   - limit: The maximum number of keys to return.
    ///
    /// - Returns: An array of matching private keys. May be empty if no matches found.
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails.
    static func query(
        applicationTag applicationTagScope: Keychain.ApplicationTagScope = .any,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws(KeychainError) -> [SecKey] {
        var query = baseQuery()

        try applyQueryParameters(
            applicationTagScope: applicationTagScope,
            applicationLabelScope: applicationLabelScope,
            accessGroupScope: accessGroupScope,
            authenticationContext: authenticationContext,
            to: &query
        )

        return try Keychain.queryItems(
            query: query,
            limit: limit
        )
    }
}
