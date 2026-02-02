public import Foundation
public import LocalAuthentication
public import Security

public extension Keychain.Keys {
    // MARK: - Add Private Key

    /// Adds a private key to the Keychain.
    ///
    /// Stores a private [SecKey](https://developer.apple.com/documentation/security/seckey) in the Keychain with the specified
    /// attributes. The key must not already exist with the same primary key attributes. Public keys are not supported.
    ///
    /// - Parameters:
    ///   - key: The private [SecKey](https://developer.apple.com/documentation/security/seckey) to store in the
    ///     Keychain.
    ///   - applicationTag: An application-specific tag to identify the key.
    ///   - applicationLabel: The application label value for the key. Use `.publicKeyHash` for private keys.
    ///   - label: An optional, user-visible label for the key.
    ///   - accessGroup: The access group identifier for Keychain sharing. Use `.default` to apply the default group.
    ///   - synchronizable: Whether to synchronize the key via iCloud Keychain.
    ///   - accessControl: The access control settings for the key.
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
    ///
    /// - Note: Security Consideration: The private key represents sensitive cryptographic material.
    /// The key is stored securely in the Keychain.
    static func addPrivateKey(
        _ key: SecKey,
        applicationTag: Data? = nil,
        applicationLabel: ApplicationLabel = .publicKeyHash,
        label: String? = nil,
        accessGroup: Keychain.AccessGroup = .default,
        synchronizable: Bool = false,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) {
        try requirePrivateKey(key)

        var query = baseQuery()

        applyAddParameters(
            key: key,
            applicationTag: applicationTag,
            applicationLabel: applicationLabel,
            label: label,
            accessGroup: accessGroup,
            synchronizable: synchronizable,
            to: &query
        )

        try accessControl.apply(to: &query)

        authenticationContext.apply(to: &query)

        try Keychain.addItem(query: query)
    }
}

// MARK: - Generic Extensions

public extension Keychain.Keys {
    /// Adds a private key from a custom type to the Keychain.
    ///
    /// Generic overload that accepts any ``SecKeyRepresentable`` type. Public keys are not supported.
    ///
    /// - Parameters:
    ///   - key: A private key conforming to ``SecKeyRepresentable`` to store in the Keychain.
    ///   - applicationTag: An application-specific tag to identify the key.
    ///   - applicationLabel: The application label value for the key. Use `.publicKeyHash` for private keys.
    ///   - label: An optional, user-visible label for the key.
    ///   - accessGroup: The access group for Keychain sharing. Use `.default` to apply the default group.
    ///   - synchronizable: Whether to synchronize the key via iCloud Keychain.
    ///   - accessControl: The access control settings for the key.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access.
    ///
    /// - Throws:
    ///   * ``SecKeyConversionError`` if the key cannot be converted into a
    ///     [SecKey](https://developer.apple.com/documentation/security/seckey) representation.
    ///   * ``KeychainError/duplicateItem`` if a key with the same primary attributes exists.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///
    /// - SeeAlso:
    ///   * [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
    ///   * [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
    ///
    /// - Note: Security Consideration: The private key represents sensitive cryptographic material.
    /// The key is stored securely in the Keychain.
    static func addPrivateKey(
        _ key: some SecKeyRepresentable,
        applicationTag: Data? = nil,
        applicationLabel: ApplicationLabel = .publicKeyHash,
        label: String? = nil,
        accessGroup: Keychain.AccessGroup = .default,
        synchronizable: Bool = false,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) async throws {
        try await addPrivateKey(
            key.makeSecKey(),
            applicationTag: applicationTag,
            applicationLabel: applicationLabel,
            label: label,
            accessGroup: accessGroup,
            synchronizable: synchronizable,
            accessControl: accessControl,
            authenticationContext: authenticationContext
        )
    }
}
