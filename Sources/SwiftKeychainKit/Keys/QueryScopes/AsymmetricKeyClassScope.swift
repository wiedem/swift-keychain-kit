public extension Keychain {
    /// Defines the scope for filtering asymmetric keys by their class (public or private) in queries.
    ///
    /// Use this type to specify whether to search for public keys, private keys, or both when querying the Keychain.
    enum AsymmetricKeyClassScope: Equatable, Sendable {
        /// Search only for public keys.
        case publicKey

        /// Search only for private keys.
        case privateKey

        /// Search for both public and private keys.
        case any
    }
}
