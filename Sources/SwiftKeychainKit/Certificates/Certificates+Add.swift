public import LocalAuthentication
public import Security

public extension Keychain.Certificates {
    /// Adds a certificate to the Keychain and returns an item reference.
    ///
    /// Stores a [SecCertificate](https://developer.apple.com/documentation/security/seccertificate) in the
    /// Keychain with the specified attributes. The certificate must not already exist with the same
    /// primary key attributes.
    ///
    /// The returned ``ItemReference`` uniquely identifies the stored certificate and can be persisted for later retrieval
    /// via ``get(itemReference:skipIfUIRequired:authenticationContext:)-1noyy``.
    ///
    /// - Parameters:
    ///   - certificate: The [SecCertificate](https://developer.apple.com/documentation/security/seccertificate)
    ///     to store in the Keychain.
    ///   - label: The label to apply to the certificate. Use `.default` to let the Keychain apply a label.
    ///   - accessGroup: The access group identifier for Keychain sharing. Use `.default` to apply the default group.
    ///   - synchronizable: Whether to synchronize the certificate via iCloud Keychain.
    ///   - accessControl: The access control settings for the certificate.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access.
    ///
    /// - Returns: An ``ItemReference`` that uniquely identifies the stored certificate.
    ///
    /// - Throws:
    ///   * ``KeychainError/duplicateItem`` if an entry with the same primary attributes exists.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///
    /// - SeeAlso:
    ///   * [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
    ///   * [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
    ///
    /// - Note: Security Consideration: The certificate is stored securely in the Keychain.
    @discardableResult
    static func add(
        _ certificate: SecCertificate,
        label: Keychain.DefaultableLabel = .default,
        accessGroup: Keychain.AccessGroup = .default,
        synchronizable: Bool = false,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> ItemReference<Self> {
        var query = baseQuery()

        applyAddParameters(
            certificate: certificate,
            label: label,
            accessGroup: accessGroup,
            synchronizable: synchronizable,
            to: &query
        )

        try accessControl.apply(to: &query)

        authenticationContext.apply(to: &query)

        let persistentRef = try Keychain.addItemReturningPersistentReference(query: query)
        return ItemReference(persistentReferenceData: persistentRef)
    }
}
