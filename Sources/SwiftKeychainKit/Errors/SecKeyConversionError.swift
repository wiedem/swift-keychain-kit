/// Errors that can occur when converting key representations to
/// [SecKey](https://developer.apple.com/documentation/security/seckey).
public enum SecKeyConversionError: Error {
    /// The [SecKey](https://developer.apple.com/documentation/security/seckey) could not be created from the provided
    /// key representation.
    ///
    /// This occurs when the key data does not match the expected format, for example when converting a CryptoKit key
    /// that uses a different curve than expected, or when the raw key data is malformed. The underlying error from the
    /// Security framework provides additional details.
    ///
    /// - Parameter underlyingError: The error reported by the Security framework.
    case secKeyCreationFailed(underlyingError: any Error & Sendable)
}
