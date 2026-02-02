private import Security

public extension SecretDataError {
    /// Returns the Security framework's error message for `randomGenerationFailed` errors.
    ///
    /// This property provides the detailed error message from the Security framework when the error is caused by a failure in
    /// [SecRandomCopyBytes](https://developer.apple.com/documentation/security/secrandomcopybytes(_:_:_:)). The message is
    /// obtained from the Security framework. For other error types, this returns `nil`.
    ///
    /// Example error messages include:
    /// - \"Function or operation not implemented.\"
    /// - \"One or more parameters passed to a function were not valid.\"
    ///
    /// The error message string, or `nil` if not a random generation error or no message is available.
    var securityErrorMessage: String? {
        if case let .randomGenerationFailed(status) = self {
            return SecCopyErrorMessageString(status, nil) as String?
        }
        return nil
    }
}
