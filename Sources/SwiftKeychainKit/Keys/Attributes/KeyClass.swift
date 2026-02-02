public extension Keychain.Keys {
    /// The class of a cryptographic key.
    ///
    /// Indicates whether the key is a public key, private key, or symmetric key.
    ///
    /// - SeeAlso: [kSecAttrKeyClass](https://developer.apple.com/documentation/security/ksecattrkeyclass)
    enum KeyClass: Sendable, Equatable, CaseIterable {
        /// A public key of a public-private key pair.
        ///
        /// Public keys can be freely shared and are used to verify signatures or encrypt data that only the private key holder can
        /// decrypt.
        case publicKey

        /// A private key of a public-private key pair.
        ///
        /// Private keys must be kept secret and are used to create signatures or decrypt data encrypted with the corresponding
        /// public key.
        case privateKey

        /// A symmetric key used for both encryption and decryption.
        ///
        /// Symmetric keys must be kept secret and are used with algorithms like symmetric keys where the same key encrypts and
        /// decrypts data.
        case symmetric
    }
}
