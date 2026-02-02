public extension Keychain.Keys {
    /// The cryptographic algorithm of a key.
    ///
    /// - SeeAlso: [kSecAttrKeyType](https://developer.apple.com/documentation/security/ksecattrkeytype)
    enum KeyAlgorithm: Sendable, Equatable, CaseIterable {
        /// RSA algorithm.
        ///
        /// RSA keys are widely supported and can be used for both signing and encryption operations.
        case rsa

        /// Elliptic Curve algorithm using SECG curves (P-192, P-256, P-384, P-521).
        ///
        /// The specific curve is determined by the key size in bits. This is the modern EC key type and the only one supported by
        /// the Secure Enclave.
        case ellipticCurve

        #if os(macOS)
        /// DES symmetric encryption algorithm.
        ///
        /// - Note: DES is considered insecure and should not be used for new applications.
        case des

        /// Triple DES (3DES) symmetric encryption algorithm.
        case tripleDES

        /// RC4 stream cipher algorithm.
        ///
        /// - Note: RC4 is considered insecure and should not be used for new applications.
        case rc4

        /// RC2 block cipher algorithm.
        ///
        /// - Note: RC2 is considered insecure and should not be used for new applications.
        case rc2

        /// CAST block cipher algorithm.
        case cast

        /// DSA (Digital Signature Algorithm).
        case dsa
        #endif
    }
}
