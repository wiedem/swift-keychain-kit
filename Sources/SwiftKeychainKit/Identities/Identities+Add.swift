private import Foundation
public import LocalAuthentication
public import Security

public extension Keychain.Identities {
    /// Adds an identity to the Keychain.
    ///
    /// Stores a [SecIdentity](https://developer.apple.com/documentation/security/secidentity) (private key +
    /// certificate pair) in the Keychain. The identity must not already exist with the same primary key
    /// attributes.
    ///
    /// - Parameters:
    ///   - identity: The [SecIdentity](https://developer.apple.com/documentation/security/secidentity)
    ///     to store in the Keychain.
    ///   - label: A user-visible label for the identity. Use `.automatic` to let the Keychain apply a label.
    ///   - accessGroup: The access group identifier for Keychain sharing. Use `.default` to apply the default group.
    ///   - synchronizable: Whether to synchronize the identity via iCloud Keychain.
    ///   - accessControl: The access control settings for the identity.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access.
    ///
    /// - Throws:
    ///   * ``KeychainError/duplicateItem`` if an entry with the same primary attributes exists.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///   
    /// - SeeAlso:
    ///   * [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
    ///   * [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
    static func add(
        _ identity: SecIdentity,
        label: Keychain.DefaultableLabel = .default,
        accessGroup: Keychain.AccessGroup = .default,
        synchronizable: Bool = false,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) {
        var query = baseQuery()
        try applyAddParameters(
            identity: identity,
            label: label.value,
            accessGroup: accessGroup.valueForAdd,
            synchronizable: synchronizable,
            accessControl: accessControl,
            authenticationContext: authenticationContext,
            to: &query
        )

        try Keychain.addItem(query: query)
    }
}
