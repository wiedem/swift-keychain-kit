public extension Keychain {
    /// A type that provides access group information for Keychain operations.
    ///
    /// Conforming types supply the access groups that determine which Keychain items the app can read and write.
    /// The library ships with ``AppEntitlementsAccessGroupProvider`` as the default implementation, which reads
    /// access groups from the app's entitlements at runtime.
    ///
    /// Custom conformances can be used for testing or when access group information is obtained through
    /// other means.
    protocol AccessGroupProviding: Sendable, ~Copyable {
        /// The app's default Keychain access group.
        ///
        /// The default access group is used when no explicit access group is specified in an add operation.
        /// It is typically derived from ``keychainAccessGroups`` or ``Keychain/ApplicationIdentifierProviding/applicationIdentifier``.
        static var defaultKeychainAccessGroup: String { get throws(KeychainError) }

        /// The app's Keychain access groups.
        ///
        /// Returns the list of Keychain access group identifiers the app is entitled to use.
        /// An empty array indicates that no explicit Keychain access groups are configured.
        static var keychainAccessGroups: [String] { get throws(KeychainError) }

        /// The app's application groups.
        ///
        /// Returns the list of application group identifiers the app is entitled to use.
        /// Application groups can be used as Keychain access groups for sharing items between apps
        /// in the same group.
        static var applicationGroups: [String] { get throws(KeychainError) }
    }
}

public extension Keychain {
    /// A type that provides the app's application identifier.
    ///
    /// The application identifier is used as a fallback default access group when no explicit
    /// Keychain access groups are configured.
    protocol ApplicationIdentifierProviding: Sendable, ~Copyable {
        /// The app's application identifier, or `nil` if not available.
        static var applicationIdentifier: String? { get throws(KeychainError) }
    }
}

public extension Keychain.AccessGroupProviding {
    /// A Boolean value that indicates whether a default Keychain access group is available.
    ///
    /// Returns `true` if ``defaultKeychainAccessGroup`` can be resolved without throwing an error,
    /// `false` otherwise.
    static var isDefaultAccessGroupAvailable: Bool {
        (try? defaultKeychainAccessGroup) != nil
    }
}

public extension Keychain.AccessGroupProviding where Self: Keychain.ApplicationIdentifierProviding {
    /// The app's default Keychain access group.
    ///
    /// Returns the first entry of ``keychainAccessGroups`` if available, otherwise falls back to
    /// ``Keychain/ApplicationIdentifierProviding/applicationIdentifier``.
    ///
    /// - Throws: ``KeychainError/anyAppEntitlementsError`` if neither a Keychain access group
    ///   nor an application identifier is available.
    static var defaultKeychainAccessGroup: String {
        get throws(KeychainError) {
            if let firstGroup = try keychainAccessGroups.first {
                return firstGroup
            }

            guard let applicationIdentifier = try Self.applicationIdentifier else {
                throw KeychainError.appEntitlementsError(underlyingError: EntitlementError.noDefaultAccessGroup)
            }
            return applicationIdentifier
        }
    }
}
