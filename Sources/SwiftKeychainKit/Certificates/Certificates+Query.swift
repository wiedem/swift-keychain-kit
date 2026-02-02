public import LocalAuthentication
public import Security

public extension Keychain.Certificates {
    // MARK: - Query

    /// Queries certificates matching the specified criteria.
    ///
    /// Returns all certificates that match the provided search parameters.
    ///
    /// - Parameters:
    ///   - certificateTypeScope: The certificate type scope. Use `.any` to match any type, or `.specific(type)` to match
    ///     only that certificate type.
    ///   - subjectScope: The certificate subject scope. Use `.any` to match any subject, or `.specific(data)` to match only
    ///     that subject (DER-encoded X.500 name).
    ///   - issuerScope: The certificate issuer scope. Use `.any` to match any issuer, or `.specific(data)` to match only
    ///     that issuer (DER-encoded X.500 name).
    ///   - serialNumberScope: The serial number scope. Use `.any` to match any serial number, or `.specific(data)` to match
    ///     only that serial number.
    ///   - subjectKeyIDScope: The subject key identifier scope. Use `.any` to match any subject key ID, or `.specific(data)`
    ///     to match only that subject key ID.
    ///   - publicKeyHashScope: The public key hash scope. Use `.any` to match any public key hash, or `.specific(data)` to
    ///     match only that public key hash.
    ///   - labelScope: The label scope. Use `.any` to match any label, or `.specific(string)` to match only that label.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access group or
    ///     `.any` to search across all access groups.
    ///   - synchronizableScope: The synchronization scope to match.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access.
    ///   - limit: The maximum number of results to return.
    ///
    /// - Returns: An array of [SecCertificate](https://developer.apple.com/documentation/security/seccertificate)
    ///   objects matching the criteria. May be empty if no matches found (or items skipped due to
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
    ) async throws(KeychainError) -> [SecCertificate] {
        var query = baseQuery()

        try applyQueryParameters(
            certificateTypeScope: certificateTypeScope,
            subjectScope: subjectScope,
            issuerScope: issuerScope,
            serialNumberScope: serialNumberScope,
            subjectKeyIDScope: subjectKeyIDScope,
            publicKeyHashScope: publicKeyHashScope,
            labelScope: labelScope,
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
