private import Security

// MARK: - Convenience Pattern Properties

public extension KeychainError {
    /// Duplicate item error.
    ///
    /// Thrown when attempting to add an item that already exists in the Keychain.
    /// Wraps [errSecDuplicateItem](https://developer.apple.com/documentation/security/errsecduplicateitem).
    static var duplicateItem: KeychainError {
        .securityError(errSecDuplicateItem)
    }

    /// Item not found error.
    ///
    /// Thrown when attempting to update an item that doesn't exist in the Keychain.
    /// Wraps [errSecItemNotFound](https://developer.apple.com/documentation/security/errsecitemnotfound).
    static var itemNotFound: KeychainError {
        .securityError(errSecItemNotFound)
    }

    /// Interaction not allowed error.
    ///
    /// Thrown when an operation requires user interaction but the authentication context has `interactionNotAllowed` set to
    /// `true`, or when UI prompts are not possible in the current execution context.
    /// Wraps [errSecInteractionNotAllowed](https://developer.apple.com/documentation/security/errsecinteractionnotallowed).
    static var interactionNotAllowed: KeychainError {
        .securityError(errSecInteractionNotAllowed)
    }

    /// Authentication cancelled error.
    ///
    /// Thrown when the user cancels an authentication prompt (Touch ID, Face ID, or application password prompt).
    /// Wraps [errSecUserCanceled](https://developer.apple.com/documentation/security/errsecusercanceled).
    static var authenticationCancelled: KeychainError {
        .securityError(errSecUserCanceled)
    }

    /// Authentication failed error.
    ///
    /// Thrown when authentication fails, for example when an incorrect application password is provided or biometric
    /// authentication does not match.
    /// Wraps [errSecAuthFailed](https://developer.apple.com/documentation/security/errsecauthfailed).
    static var authenticationFailed: KeychainError {
        .securityError(errSecAuthFailed)
    }

    /// An error related to the app's entitlements.
    ///
    /// Matches any ``KeychainError/Code/appEntitlementsError(underlyingError:)`` error, regardless of the underlying error.
    ///
    /// This includes:
    /// - Missing entitlements required for Keychain operations
    /// - Failures when reading entitlement values at runtime
    static var anyAppEntitlementsError: KeychainError {
        .appEntitlementsError()
    }
}

// MARK: - Pattern Matching

/// Custom pattern matching for KeychainError.
///
/// This operator enables pattern matching in catch clauses using specific error instances.
///
/// - Parameters:
///   - pattern: The KeychainError pattern to match against.
///   - error: The error to match.
/// - Returns: `true` when the error matches the pattern's code.
public func ~= (pattern: KeychainError, error: any Error) -> Bool {
    guard let keychainError = error as? KeychainError else {
        return false
    }
    return keychainError.code == pattern.code
}
