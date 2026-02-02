/// Represents the class of an asymmetric cryptographic key in a public-private key pair.
///
/// Asymmetric cryptography uses pairs of keys where each key performs a different function. This enum distinguishes between
/// the public and private components of such key pairs.
public enum AsymmetricKeyClass: Sendable, Equatable, CaseIterable {
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
}
