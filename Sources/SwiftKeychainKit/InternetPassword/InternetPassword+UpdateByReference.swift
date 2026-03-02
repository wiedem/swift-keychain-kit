public import LocalAuthentication
private import Security

public extension Keychain.InternetPassword {
    /// Updates an internet password using an item reference.
    ///
    /// Replaces the password data for the entry identified by the given ``ItemReference``.
    ///
    /// - Parameters:
    ///   - itemReference: The item reference obtained from a previous `add()` call.
    ///   - data: The new password data to store.
    ///   - authenticationContext: An [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
    ///     for pre-authenticated access to protected items. Defaults to `nil`.
    ///
    /// - Throws:
    ///   * ``KeychainError/itemNotFound`` if the referenced item no longer exists.
    ///   * ``KeychainError`` for other Keychain operation failures.
    ///
    /// - Note: Security Consideration: The new secret data is stored securely in the Keychain.
    /// The provided data is consumed after storage.
    static func update(
        itemReference: ItemReference<Self>,
        to data: consuming some SecretDataProtocol & ~Copyable,
        authenticationContext: LAContext? = nil
    ) async throws {
        let query = Keychain.persistentReferenceQuery(
            itemReference.persistentReferenceData,
            skipIfUIRequired: false,
            authenticationContext: authenticationContext
        )

        let attributesToUpdate: [String: Any] = try [
            kSecValueData as String: data.makeUnownedCFData(),
        ]

        try Keychain.updateItems(
            query: query,
            attributesToUpdate: attributesToUpdate
        )
    }
}
