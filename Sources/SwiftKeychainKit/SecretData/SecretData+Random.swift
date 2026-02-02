internal import Security

public extension SecretData {
    /// Creates a new ``SecretData`` instance filled with cryptographically secure random bytes.
    ///
    /// This factory method uses the system's cryptographically secure random number generator
    /// ([SecRandomCopyBytes](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes)) to generate random
    /// data directly into the secure buffer, avoiding intermediate copies.
    ///
    /// Use this method for generating random secrets such as encryption keys, authentication tokens, or other cryptographic
    /// material that requires high-entropy random data.
    ///
    /// - Parameter count: The number of random bytes to generate. Must be greater than 0.
    ///
    /// - Returns: A new ``SecretData`` instance containing cryptographically secure random bytes.
    ///
    /// - Throws:
    ///   - ``SecretDataError/emptyBuffer`` if `count` is 0 or negative.
    ///   - ``SecretDataError/memoryLockFailed(errno:)`` if secure memory protection
    /// cannot be established.
    ///   - ``SecretDataError/randomGenerationFailed(status:)`` if the system's random
    /// number generator fails.
    ///
    /// - Note: Security Consideration: This is the most secure way to create random ``SecretData``
    /// as it generates the random bytes directly into the locked memory buffer without any intermediate copies or allocations.
    static func makeRandom(count: Int) throws -> SecretData {
        try SecretData(count: count) { buffer in
            let status = SecRandomCopyBytes(
                kSecRandomDefault,
                buffer.count,
                buffer.baseAddress!
            )

            guard status == errSecSuccess else {
                throw SecretDataError.randomGenerationFailed(status: status)
            }
        }
    }
}
