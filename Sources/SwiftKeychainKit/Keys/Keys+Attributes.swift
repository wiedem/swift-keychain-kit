public import Foundation
public import LocalAuthentication

public extension Keychain.Keys {
    /// Attributes of a cryptographic key stored in the Keychain.
    ///
    /// Contains metadata about a key, such as its type, size, and labels.
    struct Attributes: Hashable, Sendable {
        /// A reference to this item in the Keychain.
        public let itemReference: ItemReference<Keychain.Keys>

        /// The class of the key (public, private, or symmetric).
        public let keyClass: KeyClass

        /// The cryptographic algorithm of the key.
        public let algorithm: KeyAlgorithm

        /// The size of the key in bits.
        public let keySizeInBits: Int

        /// A label used to identify the key.
        public let applicationLabel: Data?

        /// An application-specific tag to identify the key.
        public let applicationTag: Data?

        /// A user-visible label for the key.
        public let label: String?

        /// The date the key was created.
        public let creationDate: Date

        /// The access group of the key.
        public let accessGroup: String?

        /// Whether the key is synchronized via iCloud Keychain.
        public let synchronizable: Bool
    }

    // MARK: - Attributes Query

    /// Queries attributes of cryptographic keys.
    ///
    /// Fetches metadata for keys identified by the specified criteria.
    ///
    /// - Parameters:
    ///   - keyTypeScope: The type and class of key to search for.
    ///   - applicationTagScope: An application-specific tag to identify the key.
    ///   - applicationLabelScope: A label used to identify the key.
    ///   - keySizeInBitsScope: The size of the key in bits.
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
        keyType keyTypeScope: Keychain.AsymmetricKeyTypeScope,
        applicationTag applicationTagScope: Keychain.ApplicationTagScope = .any,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        keySizeInBits keySizeInBitsScope: Keychain.KeySizeInBitsScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws(KeychainError) -> [Attributes] {
        var query = baseQuery()

        try applyAttributesParameters(
            keyTypeScope: keyTypeScope,
            applicationTagScope: applicationTagScope,
            applicationLabelScope: applicationLabelScope,
            keySizeInBitsScope: keySizeInBitsScope,
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

extension Keychain.Keys {
    static func parseAttributes(from dict: [String: Any]) throws(KeychainError) -> Attributes {
        guard let persistentReferenceData = Keychain.ItemAttributes.PersistentReference.get(from: dict),
              let algorithm = KeyAlgorithm.get(from: dict),
              let keyClass = KeyClass.get(from: dict),
              let keySizeInBits = Keychain.ItemAttributes.KeySizeInBits.get(from: dict),
              let creationDate = Keychain.ItemAttributes.CreationDate.get(from: dict)
        else {
            throw .attributeParsingFailed
        }

        return Attributes(
            itemReference: ItemReference(persistentReferenceData: persistentReferenceData),
            keyClass: keyClass,
            algorithm: algorithm,
            keySizeInBits: keySizeInBits,
            applicationLabel: Keychain.ItemAttributes.ApplicationLabel.get(from: dict),
            applicationTag: Keychain.ItemAttributes.ApplicationTag.get(from: dict),
            label: Keychain.ItemAttributes.Label.get(from: dict),
            creationDate: creationDate,
            accessGroup: Keychain.ItemAttributes.AccessGroup.get(from: dict),
            synchronizable: Keychain.ItemAttributes.Synchronizable.get(from: dict) ?? false
        )
    }
}
