public import LocalAuthentication
public import Security

public extension Keychain.Certificates {
    /// Queries for a single certificate matching the specified label.
    ///
    /// This is a convenience method that returns a single matching certificate or `nil` if none found. If multiple certificates
    /// match the criteria, a ``KeychainError/multipleItemsFound`` error is thrown to indicate that the query parameters are not
    /// specific enough.
    ///
    /// - Parameters:
    ///   - label: The certificate label to match.
    ///   - certificateTypeScope: The certificate type scope. Use `.any` to match any type, or `.specific(type)` to match
    ///     only that certificate type. Defaults to `.any`.
    ///   - subjectScope: The certificate subject scope. Use `.any` to match any subject, or `.specific(data)` to match only
    ///     that subject (DER-encoded X.500 name). Defaults to `.any`.
    ///   - issuerScope: The certificate issuer scope. Use `.any` to match any issuer, or `.specific(data)` to match only
    ///     that issuer (DER-encoded X.500 name). Defaults to `.any`.
    ///   - serialNumberScope: The serial number scope. Use `.any` to match any serial number, or `.specific(data)` to match
    ///     only that serial number. Defaults to `.any`.
    ///   - subjectKeyIDScope: The subject key identifier scope. Use `.any` to match any subject key ID, or `.specific(data)`
    ///     to match only that subject key ID. Defaults to `.any`.
    ///   - publicKeyHashScope: The public key hash scope. Use `.any` to match any public key hash, or `.specific(data)` to
    ///     match only that public key hash. Defaults to `.any`.
    ///   - accessGroupScope: The access group scope to search in. Defaults to `.default`.
    ///   - synchronizable: Whether to query for a synchronized certificate. Defaults to `false`.
    ///   - skipIfUIRequired: If `true`, the item is skipped (returns `nil`) if authentication UI would be required. If
    ///     `false` (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access. Defaults to `nil`.
    ///
    /// - Returns: The matching [SecCertificate](https://developer.apple.com/documentation/security/seccertificate), or
    ///   `nil` if not found (or skipped due to `skipIfUIRequired`).
    ///
    /// - Throws:
    ///   * ``KeychainError/multipleItemsFound`` if more than one certificate matches the criteria.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///
    static func queryOne(
        label: String,
        certificateType certificateTypeScope: Keychain.CertificateTypeScope = .any,
        subject subjectScope: Keychain.SubjectScope = .any,
        issuer issuerScope: Keychain.IssuerScope = .any,
        serialNumber serialNumberScope: Keychain.SerialNumberScope = .any,
        subjectKeyID subjectKeyIDScope: Keychain.SubjectKeyIDScope = .any,
        publicKeyHash publicKeyHashScope: Keychain.PublicKeyHashScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .default,
        synchronizable: Bool = false,
        skipIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil
    ) async throws -> SecCertificate? {
        var results = try await query(
            certificateType: certificateTypeScope,
            subject: subjectScope,
            issuer: issuerScope,
            serialNumber: serialNumberScope,
            subjectKeyID: subjectKeyIDScope,
            publicKeyHash: publicKeyHashScope,
            label: .specific(label),
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
