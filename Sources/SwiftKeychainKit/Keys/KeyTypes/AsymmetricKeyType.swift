/// Represents the algorithm and class of an asymmetric cryptographic key.
///
/// This enum combines a key algorithm (RSA or Elliptic Curve) with a key class (public or private) to fully specify
/// the type of an asymmetric key.
///
/// - SeeAlso: ``AsymmetricKeyTypeProviding``
public enum AsymmetricKeyType: Sendable, Equatable {
    /// An RSA key with the specified class (public or private).
    ///
    /// RSA is a widely-used asymmetric encryption algorithm suitable for encryption, decryption, and digital signatures.
    case rsa(AsymmetricKeyClass)

    /// An Elliptic Curve key with the specified class (public or private).
    ///
    /// Elliptic Curve cryptography provides strong security with smaller key sizes compared to RSA, making it efficient
    /// for resource-constrained environments.
    case ellipticCurve(AsymmetricKeyClass)
}
