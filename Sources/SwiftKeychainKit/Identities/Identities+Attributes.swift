public import Foundation
public import LocalAuthentication

public extension Keychain.Identities {
    /// Attributes of an identity stored in the Keychain.
    ///
    /// Contains metadata about an identity entry. Since an identity is the combination of a private key and a certificate, this
    /// struct includes attributes from both the private key and the certificate.
    struct Attributes: Hashable, Sendable {
        /// A reference to this item in the Keychain.
        public let itemReference: ItemReference<Keychain.Identities>

        // MARK: - Certificate Attributes

        /// The certificate type.
        ///
        /// Part of the identity's primary key (from the certificate). The value corresponds to `CSSM_CERT_TYPE` in `cssmtype.h`
        /// (macOS only).
        ///
        /// - SeeAlso: [kSecAttrCertificateType](https://developer.apple.com/documentation/security/ksecattrcertificatetype)
        public let certificateType: Int

        /// The certificate issuer (normalized issuer sequence).
        ///
        /// Part of the identity's primary key (from the certificate).
        public let issuer: Data

        /// The certificate serial number.
        ///
        /// Part of the identity's primary key (from the certificate).
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

        // MARK: - Key Attributes

        /// The class of the key (public, private, or symmetric).
        public let keyClass: Keychain.Keys.KeyClass

        /// The cryptographic algorithm of the key.
        public let algorithm: Keychain.Keys.KeyAlgorithm

        /// The size of the key in bits.
        public let keySizeInBits: Int

        /// A label used to identify the key.
        public let applicationLabel: Data?

        /// An application-specific tag to identify the key.
        public let applicationTag: Data?

        // MARK: - Common Attributes

        /// A user-visible label for the identity.
        public let label: String?

        /// The accessibility level of the identity.
        public let itemAccessibility: Keychain.ItemAccessibility

        /// The access group of the identity.
        public let accessGroup: String

        /// Whether the identity is synchronized via iCloud Keychain.
        public let synchronizable: Bool

        /// The date the identity was created.
        public let creationDate: Date

        /// The date the identity was last modified.
        public let modificationDate: Date
    }
}

public extension Keychain.Identities {
    // MARK: - Attributes Query

    /// Queries attributes of identities.
    ///
    /// Fetches metadata for identities identified by the specified criteria.
    ///
    /// - Parameters:
    ///   - certificateTypeScope: Filter by certificate type.
    ///   - subjectScope: Filter by certificate subject (DER-encoded X.500 name).
    ///   - issuerScope: Filter by certificate issuer (DER-encoded X.500 name).
    ///   - serialNumberScope: Filter by certificate serial number.
    ///   - subjectKeyIDScope: Filter by subject key identifier.
    ///   - publicKeyHashScope: Filter by public key hash.
    ///   - labelScope: Filter by label.
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
        ) { items throws(KeychainError) in
            try items.map { attributes throws(KeychainError) -> Attributes in
                try parseAttributes(from: attributes)
            }
        }
    }
}

// MARK: - Attributes parsing

extension Keychain.Identities {
    static func parseAttributes(from dict: [String: Any]) throws(KeychainError) -> Attributes {
        guard let persistentReferenceData = Keychain.ItemAttributes.PersistentReference.get(from: dict) else {
            throw .attributeParsingFailed
        }

        // Certificate Attributes
        guard let certificateType = Keychain.ItemAttributes.CertificateType.get(from: dict),
              let issuer = Keychain.ItemAttributes.Issuer.get(from: dict),
              let serialNumber = Keychain.ItemAttributes.SerialNumber.get(from: dict),
              let subject = Keychain.ItemAttributes.Subject.get(from: dict),
              let publicKeyHash = Keychain.ItemAttributes.PublicKeyHash.get(from: dict)
        else {
            throw .attributeParsingFailed
        }

        // Key attributes
        guard let algorithm = Keychain.Keys.KeyAlgorithm.get(from: dict),
              let keyClass = Keychain.Keys.KeyClass.get(from: dict),
              let keySizeInBits = Keychain.ItemAttributes.KeySizeInBits.get(from: dict)
        else {
            throw .attributeParsingFailed
        }

        // Common Attributes
        guard let itemAccessibility: Keychain.ItemAccessibility = Keychain.ItemAttributes.ItemAccessibility.get(from: dict),
              let accessGroup = Keychain.ItemAttributes.AccessGroup.get(from: dict),
              let creationDate = Keychain.ItemAttributes.CreationDate.get(from: dict),
              let modificationDate = Keychain.ItemAttributes.ModificationDate.get(from: dict)
        else {
            throw .attributeParsingFailed
        }

        return Attributes(
            itemReference: ItemReference(persistentReferenceData: persistentReferenceData),
            certificateType: certificateType,
            issuer: issuer,
            serialNumber: serialNumber,
            certificateEncoding: Keychain.ItemAttributes.CertificateEncoding.get(from: dict),
            subject: subject,
            subjectKeyID: Keychain.ItemAttributes.SubjectKeyID.get(from: dict),
            publicKeyHash: publicKeyHash,
            keyClass: keyClass,
            algorithm: algorithm,
            keySizeInBits: keySizeInBits,
            applicationLabel: Keychain.ItemAttributes.ApplicationLabel.get(from: dict),
            applicationTag: Keychain.ItemAttributes.ApplicationTag.get(from: dict),
            label: Keychain.ItemAttributes.Label.get(from: dict),
            itemAccessibility: itemAccessibility,
            accessGroup: accessGroup,
            synchronizable: Keychain.ItemAttributes.Synchronizable.get(from: dict) ?? false,
            creationDate: creationDate,
            modificationDate: modificationDate
        )
    }
}
