public import LocalAuthentication
public import Security

public extension Keychain.Identities {
    // MARK: - Query

    /// Queries identities matching the specified criteria.
    ///
    /// Returns all identities that match the provided search parameters.
    ///
    /// - Parameters:
    ///   - certificateTypeScope: The certificate type scope. Use `.any` to match any type, or `.specific(type)` to match
    ///     only that certificate type. Defaults to `.any`.
    ///   - subjectScope: The certificate subject scope. Use `.any` to match any subject, or `.specific(data)` to match only
    ///     that subject (DER-encoded X.500 name). Defaults to `.any`.
    ///   - issuerScope: The certificate issuer scope. Use `.any` to match any issuer, or `.specific(data)` to match only
    ///     that issuer (DER-encoded X.500 name). Defaults to `.any`.
    ///   - serialNumberScope: The certificate serial number scope. Use `.any` to match any serial number, or
    ///     `.specific(data)` to match only that serial number. Defaults to `.any`.
    ///   - subjectKeyIDScope: The subject key identifier scope. Use `.any` to match any subject key ID, or `.specific(data)`
    ///     to match only that subject key ID. Defaults to `.any`.
    ///   - publicKeyHashScope: The public key hash scope. Use `.any` to match any public key hash, or `.specific(data)` to
    ///     match only that public key hash. Defaults to `.any`.
    ///   - labelScope: The label scope. Use `.any` to match any label, or `.specific(string)` to match only that label.
    ///     Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///   - limit: The maximum number of results to return. Defaults to `.one`.
    ///
    /// - Returns: An array of [SecIdentity](https://developer.apple.com/documentation/security/secidentity) objects
    ///   matching the criteria. May be empty if no matches found (or items skipped due to
    ///   `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` if the Keychain operation fails.
    static func query(
        certificateType certificateTypeScope: Keychain.CertificateTypeScope = .any,
        subject subjectScope: Keychain.SubjectScope = .any,
        issuer issuerScope: Keychain.IssuerScope = .any,
        serialNumber serialNumberScope: Keychain.SerialNumberScope = .any,
        subjectKeyID subjectKeyIDScope: Keychain.SubjectKeyIDScope = .any,
        publicKeyHash publicKeyHashScope: Keychain.PublicKeyHashScope = .any,
        label labelScope: Keychain.LabelScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws(KeychainError) -> [SecIdentity] {
        var query = baseQuery()

        try applyQueryParameters(
            certificateType: certificateTypeScope.value,
            subject: subjectScope.value,
            issuer: issuerScope.value,
            serialNumber: serialNumberScope.value,
            subjectKeyID: subjectKeyIDScope.value,
            publicKeyHash: publicKeyHashScope.value,
            label: labelScope.value,
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
