public import LocalAuthentication
public import Security

public extension Keychain.Certificates {
    /// Gets a certificate using an item reference.
    ///
    /// Retrieves the certificate identified by the given ``ItemReference``. The reference uniquely identifies
    /// a specific Keychain item, so this method guarantees at most one result.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `add()` call.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Returns: The matching [SecCertificate](https://developer.apple.com/documentation/security/seccertificate), or
    ///   `nil` if the referenced item no longer exists (or skipped due to `skipIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` for Keychain operation failures.
    ///
    /// - Note: Security Consideration: The returned certificate may contain sensitive information.
    /// Minimize its lifetime and avoid unnecessary copies.
    static func get(
        itemReference: ItemReference<Self>,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> SecCertificate? {
        let query = Keychain.persistentReferenceQuery(
            itemReference.persistentReferenceData,
            skipIfUIRequired: skipIfUIRequired,
            authenticationContext: authenticationContext
        )

        let results: [SecCertificate] = try Keychain.queryItems(query: query, limit: .one)
        return results.first
    }
}
