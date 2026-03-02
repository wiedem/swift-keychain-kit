public extension Keychain {
    /// The access group for Keychain operations that must target a single, explicit access group.
    ///
    /// ``AccessGroup`` is used for add operations and other APIs that must create or match items in exactly one access
    /// group. For query, update, and delete operations that can span multiple access groups, ``AccessGroupScope`` is
    /// used instead.
    ///
    /// Most code uses this type alias. For testing purposes, ``ProviderAccessGroup`` is used directly with a custom access
    /// group provider.
    typealias AccessGroup = ProviderAccessGroup<AppEntitlementsAccessGroupProvider>

    /// Parameterized variant of access group for Keychain query and add operations.
    ///
    /// This type specifies which access group to use for Keychain operations that require a specific access group. Unlike
    /// ``ProviderAccessGroupScope``, this type does not include an `.any` case, ensuring operations using it can only match or
    /// create items in a single, well-defined access group.
    ///
    /// Most code uses ``AccessGroup`` instead. This variant is provided primarily for testing purposes, allowing tests to
    /// inject custom access group providers.
    ///
    /// ## Use Cases
    ///
    /// This type is used for operations that must ensure uniqueness:
    /// - ``GenericPassword/get(account:service:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)-1w6be``
    /// requires a specific access group to guarantee at most one result
    /// - Add operations where you want to explicitly specify which access group to use
    ///
    /// For query, update, and delete operations that can span multiple access groups, ``ProviderAccessGroupScope`` is used
    /// instead.
    ///
    /// - SeeAlso: ``ProviderAccessGroupScope``
    enum ProviderAccessGroup<AccessGroupProvider: AccessGroupProviding>: Equatable, Sendable {
        /// The app's default access group is used.
        ///
        /// The default access group is determined by the `AccessGroupProvider`. For operations that resolve this value at
        /// runtime (such as get and update), the resolution can fail with
        /// ``KeychainError/anyAppEntitlementsError`` if the app's entitlements are missing or cannot be read.
        case `default`

        /// An explicit access group identifier is used.
        ///
        /// The exact access group identifier is provided. The identifier must match one of the app's keychain access groups,
        /// typically in the format `$(AppIdentifierPrefix)com.example.MyApp` or a shared group like
        /// `$(AppIdentifierPrefix)com.example.SharedGroup`.
        ///
        /// - Parameter identifier: The access group identifier.
        case identifier(String)
    }
}
