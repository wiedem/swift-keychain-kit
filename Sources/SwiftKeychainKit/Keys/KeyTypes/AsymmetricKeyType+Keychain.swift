public extension AsymmetricKeyType {
    /// The corresponding scope for query and delete operations.
    ///
    /// Converts this key type into a ``Keychain/AsymmetricKeyTypeScope`` that matches the same algorithm and key class.
    ///
    /// ```swift
    /// let keyType = AsymmetricKeyType.rsa(.privateKey)
    ///
    /// try await Keychain.Keys.delete(keyType: keyType.scope, ...)
    /// ```
    var scope: Keychain.AsymmetricKeyTypeScope {
        switch self {
        case let .rsa(keyClass):
            .rsa(keyClass.scope)
        case let .ellipticCurve(keyClass):
            .ellipticCurve(keyClass.scope)
        }
    }
}
