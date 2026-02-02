public import LocalAuthentication

public extension Keychain.InternetPassword {
    /// Queries for a single internet password matching the specified criteria.
    ///
    /// This is a convenience method that returns the matching password, or `nil` if none found. If multiple passwords match the
    /// criteria, a ``KeychainError/multipleItemsFound`` error is thrown to indicate that the query parameters are not specific
    /// enough.
    ///
    /// - Important: This method does not guarantee uniqueness. Multiple entries can exist with the same account
    /// and server but different ports, protocols, or paths. Use the optional parameters to narrow your query, or handle the
    /// ``KeychainError/multipleItemsFound`` error to detect ambiguous queries.
    ///
    /// - Parameters:
    ///   - account: The account name to match.
    ///   - server: The server name to match.
    ///   - protocolScope: The protocol to match. Defaults to matching any protocol.
    ///   - authenticationTypeScope: The authentication type to match. Defaults to matching any type.
    ///   - portScope: The port number to match. Defaults to matching any port.
    ///   - pathScope: The path to match. Defaults to matching any path.
    ///   - securityDomainScope: The security domain to match. Defaults to matching any domain.
    ///   - accessGroupScope: The access group scope to search in. Defaults to searching in all access groups.
    ///   - synchronizable: Whether to query for a synchronized password. Defaults to `false`.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///
    /// - Returns: The matching password data, or `nil` if not found (or skipped due to `skipIfUIRequired`).
    ///
    /// - Throws:
    ///   * ``KeychainError/multipleItemsFound`` if more than one password matches the criteria.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///
    /// - Note: Security Consideration: The returned data contains sensitive information.
    /// Minimize its lifetime and clear from memory when no longer needed.
    static func queryOne(
        account: String,
        server: String,
        protocol protocolScope: Keychain.ProtocolScope = .any,
        authenticationType authenticationTypeScope: Keychain.AuthenticationTypeScope = .any,
        port portScope: Keychain.PortScope = .any,
        path pathScope: Keychain.PathScope = .any,
        securityDomain securityDomainScope: Keychain.SecurityDomainScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .default,
        synchronizable: Bool = false,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws -> SecretData? {
        var results = try await query(
            account: .specific(account),
            server: .specific(server),
            protocol: protocolScope,
            authenticationType: authenticationTypeScope,
            port: portScope,
            path: pathScope,
            securityDomain: securityDomainScope,
            accessGroup: accessGroupScope,
            synchronizable: synchronizable ? .synchronized : .notSynchronized,
            skipItemsIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext,
            limit: .count(2)
        )

        guard results.count <= 1 else {
            throw KeychainError.multipleItemsFound
        }

        return results.isEmpty ? nil : results.remove(at: 0)
    }
}
