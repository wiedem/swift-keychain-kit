public import Foundation
public import LocalAuthentication

public extension Keychain.SecureEnclaveKeys {
    /// Attributes of a private key stored in the Secure Enclave.
    struct Attributes: Sendable {
        /// The application tag identifying the key.
        public let applicationTag: Data

        /// The application label for the key.
        public let applicationLabel: Data

        /// The user-visible label for the key, if set.
        public let label: String?

        /// The access group for the key.
        public let accessGroup: String?
    }

    /// Queries for the attributes of private keys stored in the Secure Enclave.
    ///
    /// - Parameters:
    ///   - applicationTagScope: The application tag to match. Defaults to matching any tag.
    ///   - applicationLabelScope: The application label to match. Defaults to matching any label.
    ///   - accessGroupScope: The access group to search in. Defaults to searching in all access groups.
    ///   - authenticationContext: An optional authentication context for the operation.
    ///   - limit: The maximum number of key attributes to return.
    ///
    /// - Returns: An array of key attributes for matching keys. May be empty if no matches found.
    ///
    /// - Throws: A ``KeychainError`` if the query fails.
    ///
    /// - SeeAlso: [Storing Keys in the Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave)
    static func queryAttributes(
        applicationTag applicationTagScope: Keychain.ApplicationTagScope = .any,
        applicationLabel applicationLabelScope: Keychain.ApplicationLabelScope = .any,
        accessGroup accessGroupScope: Keychain.AccessGroupScope = .any,
        authenticationContext: LAContext? = nil,
        limit: Keychain.QueryLimit = .one
    ) async throws(KeychainError) -> [Attributes] {
        var query = baseQuery()

        try applyAttributesParameters(
            applicationTagScope: applicationTagScope,
            applicationLabelScope: applicationLabelScope,
            accessGroupScope: accessGroupScope,
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

extension Keychain.SecureEnclaveKeys {
    static func parseAttributes(from dict: [String: Any]) throws(KeychainError) -> Attributes {
        guard let applicationTag = Keychain.ItemAttributes.ApplicationTag.get(from: dict) else {
            throw .attributeParsingFailed
        }

        return Attributes(
            applicationTag: applicationTag,
            applicationLabel: Keychain.ItemAttributes.ApplicationLabel.get(from: dict) ?? Data(),
            label: Keychain.ItemAttributes.Label.get(from: dict),
            accessGroup: Keychain.ItemAttributes.AccessGroup.get(from: dict)
        )
    }
}
