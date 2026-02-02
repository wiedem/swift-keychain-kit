public import Foundation
public import LocalAuthentication
private import Security

public extension Keychain.GenericPassword {
    /// Attributes of a generic password stored in the Keychain.
    ///
    /// Contains metadata about a generic password entry.
    struct Attributes: Hashable, Sendable {
        /// The account name for this password.
        public let account: String

        /// The service name for this password.
        public let service: String

        /// A user-visible label for the item.
        public let label: String?

        /// A user-visible description of the item.
        public let itemDescription: String?

        /// The accessibility level of the item.
        public let itemAccessibility: Keychain.ItemAccessibility

        /// The access group of the item.
        public let accessGroup: String

        /// Whether the item is synchronized via iCloud Keychain.
        public let synchronizable: Bool

        /// The date the item was created.
        public let creationDate: Date

        /// The date the item was last modified.
        public let modificationDate: Date
    }
}

public extension Keychain.GenericPassword {
    // MARK: - Attributes Query

    /// Queries attributes of generic passwords.
    ///
    /// Fetches metadata for entries identified by the specified criteria.
    ///
    /// - Parameters:
    ///   - accountScope: The account name for this password.
    ///   - serviceScope: The service name for this password.
    ///   - accessGroupScope: The access group scope to search in. Use `.specific(...)` to target a specific access
    ///     group or `.any` to search across all access groups. Defaults to `.any`.
    ///   - synchronizableScope: The synchronization scope to match. Defaults to `.notSynchronized`.
    ///   - skipItemsIfUIRequired: If `true`, items requiring authentication UI are skipped from results. If `false`
    ///     (default), authentication UI may be presented to the user.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///   - limit: The maximum number of results to return. Defaults to `.one`.
    ///
    /// - Returns: An array of `Attributes` matching the criteria. May be empty if no matches found (or items skipped
    ///   due to `skipItemsIfUIRequired`).
    ///
    /// - Throws: ``KeychainError`` for Keychain operation failures.
    static func queryAttributes(
        account accountScope: Keychain.AccountScope = .any,
        service serviceScope: Keychain.ServiceScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        synchronizable synchronizableScope: Keychain.SynchronizableScope = .notSynchronized,
        skipItemsIfUIRequired: Bool = false,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws(KeychainError) -> [Attributes] {
        var query = baseQuery()

        try applyAttributesParameters(
            accountScope: accountScope,
            serviceScope: serviceScope,
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

extension Keychain.GenericPassword {
    static func parseAttributes(from dict: [String: Any]) throws(KeychainError) -> Attributes {
        guard let account = Keychain.ItemAttributes.Account.get(from: dict),
              let service = Keychain.ItemAttributes.Service.get(from: dict),
              let itemAccessibility: Keychain.ItemAccessibility = Keychain.ItemAttributes.ItemAccessibility.get(from: dict),
              let accessGroup = Keychain.ItemAttributes.AccessGroup.get(from: dict),
              let creationDate = Keychain.ItemAttributes.CreationDate.get(from: dict),
              let modificationDate = Keychain.ItemAttributes.ModificationDate.get(from: dict)
        else {
            throw .attributeParsingFailed
        }

        return Attributes(
            account: account,
            service: service,
            label: Keychain.ItemAttributes.Label.get(from: dict),
            itemDescription: Keychain.ItemAttributes.ItemDescription.get(from: dict),
            itemAccessibility: itemAccessibility,
            accessGroup: accessGroup,
            synchronizable: Keychain.ItemAttributes.Synchronizable.get(from: dict) ?? false,
            creationDate: creationDate,
            modificationDate: modificationDate
        )
    }
}
