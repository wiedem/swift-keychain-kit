/// Errors related to the app's entitlements that are detected by SwiftKeychainKit.
public enum EntitlementError: Error, Sendable {
    /// The app has no default access group configured.
    ///
    /// This occurs when resolving the ``Keychain/ProviderAccessGroup/default`` access group, but no keychain access group
    /// or application identifier entitlement is present. This error is wrapped as the underlying error of
    /// ``KeychainError/Code/appEntitlementsError(underlyingError:)``.
    case noDefaultAccessGroup
}

extension EntitlementError: CustomDebugStringConvertible {
    /// A human-readable description of the error for debugging purposes.
    public var debugDescription: String {
        switch self {
        case .noDefaultAccessGroup:
            return "No default keychain access group found in app entitlements"
        }
    }
}
