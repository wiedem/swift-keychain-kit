private import AppEntitlements

/// Reads access group information from the app's entitlements at runtime.
///
/// Use this provider to discover which Keychain access groups, application groups, and application identifier
/// are available to your app. This is the default provider used by ``Keychain/AccessGroup`` and
/// ``Keychain/AccessGroupScope``.
public enum AppEntitlementsAccessGroupProvider: Keychain.AccessGroupProviding & Keychain.ApplicationIdentifierProviding {
    /// The app's application identifier from its entitlements.
    ///
    /// Returns the value of the
    /// [application-identifier](https://developer.apple.com/documentation/bundleresources/entitlements/application-identifier)
    /// entitlement, or `nil` if the entitlement is not present.
    ///
    /// - Throws: ``KeychainError/anyAppEntitlementsError`` if the entitlements could not be read.
    public static var applicationIdentifier: String? {
        get throws(KeychainError) {
            do {
                return try AppEntitlements.applicationIdentifier
            } catch {
                throw KeychainError.appEntitlementsError(underlyingError: error)
            }
        }
    }

    /// The app's keychain access groups from its entitlements.
    ///
    /// Returns the values of the
    /// [keychain-access-groups](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
    /// entitlement, or an empty array if the entitlement is not present.
    ///
    /// - Throws: ``KeychainError/anyAppEntitlementsError`` if the entitlements could not be read.
    public static var keychainAccessGroups: [String] {
        get throws(KeychainError) {
            do {
                return try AppEntitlements.keychainAccessGroups ?? []
            } catch {
                throw KeychainError.appEntitlementsError(underlyingError: error)
            }
        }
    }

    /// The app's application groups from its entitlements.
    ///
    /// Returns the values of the
    /// [com.apple.security.application-groups](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
    /// entitlement, or an empty array if the entitlement is not present.
    ///
    /// - Throws: ``KeychainError/anyAppEntitlementsError`` if the entitlements could not be read.
    public static var applicationGroups: [String] {
        get throws(KeychainError) {
            do {
                return try AppEntitlements.applicationGroups ?? []
            } catch {
                throw KeychainError.appEntitlementsError(underlyingError: error)
            }
        }
    }
}
