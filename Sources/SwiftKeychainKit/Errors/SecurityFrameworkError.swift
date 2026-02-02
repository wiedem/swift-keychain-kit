public import Darwin
private import Security

/// An error from the Security framework represented by an OSStatus code.
///
/// This type wraps the raw `OSStatus` error codes returned by Security framework functions like
/// [SecItemAdd](https://developer.apple.com/documentation/security/secitemadd(_:_:)),
/// [SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)), and others.
public struct SecurityFrameworkError: Error, Sendable, Equatable {
    /// The OSStatus error code from the Security framework.
    public let status: OSStatus

    /// The Security framework's error message for this status code.
    ///
    /// Returns the message provided by
    /// [SecCopyErrorMessageString](https://developer.apple.com/documentation/security/seccopyerrormessagestring(_:_:)),
    /// or `nil` if the status code is not recognized.
    public var message: String? {
        SecCopyErrorMessageString(status, nil) as String?
    }
}

extension SecurityFrameworkError {
    static func status(_ status: OSStatus) -> Self {
        .init(status: status)
    }
}

extension SecurityFrameworkError: CustomDebugStringConvertible {
    /// A human-readable description of the error for debugging purposes.
    public var debugDescription: String {
        if let message {
            return "SecurityFrameworkError(\(status)): \(message)"
        }
        return "SecurityFrameworkError(\(status))"
    }
}
