public import CryptoKit

public extension SecretData {
    /// Creates a CryptoKit symmetric key by consuming this secret data.
    ///
    /// This method transfers ownership of the secret data to the new
    /// [SymmetricKey](https://developer.apple.com/documentation/cryptokit/symmetrickey). After this call,
    /// this ``SecretData`` instance is consumed and its memory zeroized.
    ///
    /// - Returns: A [SymmetricKey](https://developer.apple.com/documentation/cryptokit/symmetrickey) containing the
    ///   secret bytes.
    ///
    /// - Note: Security Consideration: This operation copies the secret bytes into
    /// CryptoKit-managed memory. Minimize additional copies and handle the returned key carefully.
    consuming func moveToSymmetricKey() -> SymmetricKey {
        withUnsafeBytes { buffer in
            SymmetricKey(data: buffer)
        }
    }
}
