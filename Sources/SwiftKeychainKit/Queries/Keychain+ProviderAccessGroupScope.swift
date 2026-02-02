public extension Keychain {
    /// The access group scope for Keychain query, update, and delete operations.
    ///
    /// Access groups control which apps can access Keychain items. ``AccessGroupScope`` is used to specify which access
    /// groups are searched when querying, updating, or deleting items.
    ///
    /// ## Overview
    ///
    /// By default, query, update, and delete operations search all of the app's access groups. ``AccessGroupScope`` is
    /// used to limit the search to a specific group:
    ///
    /// - ``ProviderAccessGroupScope/any``: Search across all the app's access groups (default behavior)
    /// - ``ProviderAccessGroupScope/specific(_:)``: Limit the search to a particular access group
    /// - ``ProviderAccessGroupScope/default``: Limit the search to the app's default access group
    ///
    /// An app's access groups consist of:
    /// 1. The strings in the app's Keychain Access Groups Entitlement
    /// 2. The app ID string
    /// 3. The strings in the App Groups Entitlement
    ///
    /// - SeeAlso: [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
    typealias AccessGroupScope = ProviderAccessGroupScope<AppEntitlementsAccessGroupProvider>

    /// Parameterized variant of access group scope for Keychain query, update, and delete operations.
    ///
    /// Most code uses ``AccessGroupScope`` instead. This variant is provided primarily for testing purposes, allowing tests
    /// to inject custom access group providers.
    ///
    /// - SeeAlso: ``AccessGroupScope``
    enum ProviderAccessGroupScope<AccessGroupProvider: AccessGroupProviding>: Equatable, Sendable {
        /// Search across all the app's access groups.
        ///
        /// This is the default behavior when no access group is specified in a query. The search matches items in any of the app's
        /// access groups.
        case any

        /// Limit the search to a specific access group.
        ///
        /// Use this to search only items in a particular access group. If the app doesn't belong to the specified group, the search
        /// returns no items.
        ///
        /// - Parameter identifier: The access group identifier (e.g., `"ABCDE12345.com.example.MyApp"`).
        case specific(String)

        /// Limit the search to the app's default access group.
        ///
        /// The default access group is the first group in the concatenated list of the app's access groups (keychain groups, app
        /// ID, app groups).
        ///
        /// - Throws: ``KeychainError/anyAppEntitlementsError`` if the default access group cannot be determined.
        case `default`
    }
}
