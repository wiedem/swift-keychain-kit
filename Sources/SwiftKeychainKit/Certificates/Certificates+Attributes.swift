public import Foundation
public import LocalAuthentication

public extension Keychain.Certificates {
    /// Attributes of a certificate stored in the Keychain.
    ///
    /// Contains metadata about a certificate entry.
    struct Attributes: Sendable {
        /// The certificate type.
        ///
        /// Part of the certificate's primary key. The value corresponds to `CSSM_CERT_TYPE` in `cssmtype.h` (macOS only).
        ///
        /// - SeeAlso: [kSecAttrCertificateType](https://developer.apple.com/documentation/security/ksecattrcertificatetype)
        public let certificateType: Int

        /// The certificate issuer (normalized issuer sequence).
        ///
        /// Part of the certificate's primary key.
        public let issuer: Data

        /// The certificate serial number.
        ///
        /// Part of the certificate's primary key.
        public let serialNumber: Data

        /// The certificate encoding.
        ///
        /// The value corresponds to `CSSM_CERT_ENCODING` in `cssmtype.h` (macOS only).
        ///
        /// - SeeAlso: [kSecAttrCertificateEncoding](https://developer.apple.com/documentation/security/ksecattrcertificateencoding)
        public let certificateEncoding: Int?

        /// The subject name.
        ///
        /// Always present, extracted from the certificate by the system.
        public let subject: Data

        /// The subject key ID.
        public let subjectKeyID: Data?

        /// The public key hash.
        ///
        /// Always present, computed from the certificate's public key by the system.
        public let publicKeyHash: Data

        /// A user-visible label for the certificate.
        public let label: String?

        /// The accessibility level of the certificate.
        public let itemAccessibility: Keychain.ItemAccessibility

        /// The access group of the certificate.
        public let accessGroup: String

        /// Whether the certificate is synchronized via iCloud Keychain.
        public let synchronizable: Bool

        /// The date the certificate was created.
        public let creationDate: Date

        /// The date the certificate was last modified.
        public let modificationDate: Date
    }

    // MARK: - Attributes Query

    /// Queries attributes of certificates.
    ///
    /// Fetches metadata for certificates identified by the specified criteria.
    ///
    /// - Parameters:
    ///   - certificateTypeScope: Filter by certificate type.
    ///   - subjectScope: Filter by certificate subject (DER-encoded X.500 name).
    ///   - issuerScope: The certificate issuer scope. Use `.any` to match any issuer, or `.specific(data)` to match only
    ///     that issuer.
    ///   - serialNumberScope: The serial number scope. Use `.any` to match any serial number, or `.specific(data)` to match
    ///     only that serial number.
    ///   - subjectKeyIDScope: Filter by subject key identifier.
    ///   - publicKeyHashScope: Filter by public key hash.
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
    /// - Returns: An array of `Attributes` matching the criteria. May be empty if no matches found (or items skipped
    ///   due to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` for Keychain operation failures.
    static func queryAttributes(
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
    ) async throws(KeychainError) -> [Attributes] {
        var query = baseQuery()

        try applyAttributesParameters(
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

        return try Keychain.queryAttributes(
            query: query,
            limit: limit
        ) { items throws(KeychainError) -> [Attributes] in
            try items.map { attributes throws(KeychainError) -> Attributes in
                try parseAttributes(from: attributes)
            }
        }
    }
}

extension Keychain.Certificates {
    static func parseAttributes(from dict: [String: Any]) throws(KeychainError) -> Attributes {
        guard let certificateType = Keychain.ItemAttributes.CertificateType.get(from: dict),
              let issuer = Keychain.ItemAttributes.Issuer.get(from: dict),
              let serialNumber = Keychain.ItemAttributes.SerialNumber.get(from: dict),
              let subject = Keychain.ItemAttributes.Subject.get(from: dict),
              let publicKeyHash = Keychain.ItemAttributes.PublicKeyHash.get(from: dict),
              let itemAccessibility: Keychain.ItemAccessibility = Keychain.ItemAttributes.ItemAccessibility.get(from: dict),
              let accessGroup = Keychain.ItemAttributes.AccessGroup.get(from: dict),
              let creationDate = Keychain.ItemAttributes.CreationDate.get(from: dict),
              let modificationDate = Keychain.ItemAttributes.ModificationDate.get(from: dict)
        else {
            throw .attributeParsingFailed
        }

        return Attributes(
            certificateType: certificateType,
            issuer: issuer,
            serialNumber: serialNumber,
            certificateEncoding: Keychain.ItemAttributes.CertificateEncoding.get(from: dict),
            subject: subject,
            subjectKeyID: Keychain.ItemAttributes.SubjectKeyID.get(from: dict),
            publicKeyHash: publicKeyHash,
            label: Keychain.ItemAttributes.Label.get(from: dict),
            itemAccessibility: itemAccessibility,
            accessGroup: accessGroup,
            synchronizable: Keychain.ItemAttributes.Synchronizable.get(from: dict) ?? false,
            creationDate: creationDate,
            modificationDate: modificationDate
        )
    }
}
