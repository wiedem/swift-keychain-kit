public import Foundation
private import Security

/// Errors thrown by SwiftKeychainKit operations.
///
/// ``KeychainError`` wraps various error conditions that can occur when working with the Keychain, including Security
/// framework errors, data conversion failures, and invalid parameters.
///
/// Use the ``code`` property to determine the specific error type.
public struct KeychainError: Error, Sendable, Equatable {
    /// The specific error code indicating what went wrong.
    public let code: Code

    /// Creates a KeychainError with the specified code.
    private init(code: Code) {
        self.code = code
    }
}

// MARK: - Error Code

public extension KeychainError {
    /// The different error codes that can occur during Keychain operations.
    ///
    /// Each case represents a specific failure mode, from low-level Security framework errors to high-level data conversion or
    /// validation failures.
    enum Code: Sendable {
        /// A Security framework error.
        ///
        /// These are low-level errors from the Keychain Services API. Common examples include:
        /// - [errSecDuplicateItem](https://developer.apple.com/documentation/security/errsecduplicateitem) (-25299): Item already exists
        /// - [errSecItemNotFound](https://developer.apple.com/documentation/security/errsecitemnotfound) (-25300): Item not found
        /// - [errSecAuthFailed](https://developer.apple.com/documentation/security/errsecauthfailed) (-25293): Authentication failed
        ///
        /// For a complete list, see [Security Framework Result
        /// Codes](https://developer.apple.com/documentation/security/security-framework-result-codes).
        ///
        /// > Tip: Instead of checking `OSStatus` values directly, use the convenience properties
        /// like ``duplicateItem`` and ``itemNotFound`` for pattern matching with common errors. See ``KeychainError`` for usage
        /// examples.
        ///
        /// - Parameter error: The Security framework error.
        case securityError(_ error: SecurityFrameworkError)

        /// An error occurred while creating or validating an access control object.
        ///
        /// This occurs when
        /// [SecAccessControlCreateWithFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:))
        /// fails. Common causes include unsupported combinations of accessibility level and access control flags, such as
        /// requesting biometric protection with an accessibility level that doesn't restrict to the current device.
        ///
        /// Check that the ``Keychain/ItemAccessibility`` and ``Keychain/AccessConstraint`` values are compatible.
        ///
        /// - Parameter nsError: The underlying error from the Security framework.
        case accessControlError(_ nsError: NSError)

        /// Invalid parameters were provided to a Keychain operation.
        ///
        /// This occurs when parameters are logically invalid, for example when a required value like account or service is
        /// empty, or when mutually exclusive options are combined. Verify that all required parameters are non-empty and that
        /// the parameter combination is valid.
        case invalidParameters

        /// The retrieved data could not be decoded as a UTF-8 string.
        ///
        /// This occurs when retrieving a password as a string, but the stored data is not valid UTF-8. If the password was
        /// originally stored as raw bytes, retrieve it as `Data` instead.
        case stringDecodingFailed

        /// The data could not be converted to the requested type.
        ///
        /// This occurs when the Keychain item's data does not match the expected format, for example when the stored data
        /// cannot be interpreted as a [SecKey](https://developer.apple.com/documentation/security/seckey). Verify that the
        /// item was stored with the expected format and that the query targets the correct item class.
        case dataConversionFailed

        /// Public keys are not supported for Keychain key storage.
        ///
        /// The Keychain only stores private keys and symmetric keys. Public keys should be stored separately or derived from their
        /// corresponding private keys.
        case publicKeyNotSupported

        /// Multiple items were found when exactly one was expected.
        ///
        /// This error is thrown when a query unexpectedly returns more than one matching item, indicating that the query parameters
        /// are not specific enough.
        case multipleItemsFound

        /// The Secure Enclave is not available on this device.
        ///
        /// Secure Enclave operations require hardware support that is not available on all devices, such as simulators or
        /// older Mac models without a T1/T2 chip or Apple Silicon. Check for Secure Enclave availability before attempting
        /// to create or access Secure Enclave keys.
        case secureEnclaveNotAvailable

        /// The attributes returned by the Keychain could not be parsed.
        ///
        /// The data structure returned by the Security framework does not match the expected format. This typically indicates a
        /// bug in SwiftKeychainKit or an incompatible change in the Security framework. If you encounter this error, please
        /// file a bug report with the OS version and the Keychain operation that triggered it.
        case attributeParsingFailed

        /// An error related to the app's entitlements.
        ///
        /// This error covers entitlement-related failures, including:
        /// - Missing entitlements required for Keychain operations
        /// - Failures when reading entitlement values at runtime
        ///
        /// The optional associated error contains the underlying failure, which can be used for diagnostic logging.
        ///
        /// - Parameter underlyingError: The underlying error, if available.
        case appEntitlementsError(underlyingError: (any Error & Sendable)? = nil)
    }
}

// MARK: - Equatable

extension KeychainError.Code: Equatable {
    public static func == (lhs: KeychainError.Code, rhs: KeychainError.Code) -> Bool {
        switch (lhs, rhs) {
        case let (.securityError(lhsError), .securityError(rhsError)):
            return lhsError == rhsError
        case let (.accessControlError(lhsError), .accessControlError(rhsError)):
            return lhsError == rhsError
        case (.invalidParameters, .invalidParameters),
             (.stringDecodingFailed, .stringDecodingFailed),
             (.dataConversionFailed, .dataConversionFailed),
             (.publicKeyNotSupported, .publicKeyNotSupported),
             (.multipleItemsFound, .multipleItemsFound),
             (.secureEnclaveNotAvailable, .secureEnclaveNotAvailable),
             (.attributeParsingFailed, .attributeParsingFailed),
             (.appEntitlementsError, .appEntitlementsError):
            return true
        default:
            return false
        }
    }
}

// MARK: - Static Factory Methods

public extension KeychainError {
    /// Creates a Security framework error.
    ///
    /// - Parameter resultCode: The OSStatus error code from the Security framework.
    /// - Returns: A KeychainError wrapping the security error.
    static func securityError(_ resultCode: OSStatus) -> KeychainError {
        // Special handling for the errSecMissingEntitlement error since we don't want appEntitlementsError and
        // securityError basically reflecting the same error domain.
        guard resultCode != errSecMissingEntitlement else {
            return KeychainError(
                code: .appEntitlementsError(underlyingError: SecurityFrameworkError(status: resultCode))
            )
        }
        return KeychainError(code: .securityError(.status(resultCode)))
    }

    /// Creates an app entitlements error.
    ///
    /// - Parameter underlyingError: The underlying error, if available.
    /// - Returns: A KeychainError wrapping the entitlements error.
    static func appEntitlementsError(underlyingError: (any Error & Sendable)? = nil) -> KeychainError {
        KeychainError(
            code: .appEntitlementsError(underlyingError: underlyingError)
        )
    }

    /// Creates an access control error.
    ///
    /// - Parameter nsError: The underlying error from the Security framework.
    /// - Returns: A KeychainError wrapping the access control error.
    static func accessControlError(_ nsError: NSError) -> KeychainError {
        KeychainError(code: .accessControlError(nsError))
    }

    /// Invalid parameters were provided to a Keychain operation.
    ///
    /// This occurs when parameters are logically invalid, for example when a required value like account or service is
    /// empty, or when mutually exclusive options are combined. Verify that all required parameters are non-empty and that
    /// the parameter combination is valid.
    static var invalidParameters: KeychainError {
        KeychainError(code: .invalidParameters)
    }

    /// The retrieved data could not be decoded as a UTF-8 string.
    ///
    /// This occurs when retrieving a password as a string, but the stored data is not valid UTF-8. If the password was
    /// originally stored as raw bytes, retrieve it as `Data` instead.
    static var stringDecodingFailed: KeychainError {
        KeychainError(code: .stringDecodingFailed)
    }

    /// The data could not be converted to the requested type.
    ///
    /// This occurs when the Keychain item's data does not match the expected format, for example when the stored data
    /// cannot be interpreted as a [SecKey](https://developer.apple.com/documentation/security/seckey). Verify that the
    /// item was stored with the expected format and that the query targets the correct item class.
    static var dataConversionFailed: KeychainError {
        KeychainError(code: .dataConversionFailed)
    }

    /// Public keys are not supported for Keychain key storage.
    ///
    /// The Keychain only stores private keys and symmetric keys. Public keys should be stored separately or derived from
    /// their corresponding private keys.
    static var publicKeyNotSupported: KeychainError {
        KeychainError(code: .publicKeyNotSupported)
    }

    /// Multiple items were found when exactly one was expected.
    ///
    /// This occurs when a query unexpectedly returns more than one matching item, indicating that the query parameters
    /// are not specific enough.
    static var multipleItemsFound: KeychainError {
        KeychainError(code: .multipleItemsFound)
    }

    /// The Secure Enclave is not available on this device.
    ///
    /// Secure Enclave operations require hardware support that is not available on all devices, such as simulators or
    /// older Mac models without a T1/T2 chip or Apple Silicon. Check for Secure Enclave availability before attempting
    /// to create or access Secure Enclave keys.
    static var secureEnclaveNotAvailable: KeychainError {
        KeychainError(code: .secureEnclaveNotAvailable)
    }

    /// The attributes returned by the Keychain could not be parsed.
    ///
    /// The data structure returned by the Security framework does not match the expected format. This typically indicates
    /// a bug in SwiftKeychainKit or an incompatible change in the Security framework. If you encounter this error, please
    /// file a bug report with the OS version and the Keychain operation that triggered it.
    static var attributeParsingFailed: KeychainError {
        KeychainError(code: .attributeParsingFailed)
    }
}

extension KeychainError: CustomDebugStringConvertible {
    /// A human-readable description of the error for debugging purposes.
    public var debugDescription: String {
        switch code {
        case let .securityError(error):
            if let message = error.message {
                return "Security error \(error.status): \(message)"
            }
            return "Security error \(error.status)"
        case let .accessControlError(error):
            return "Access control error: \(error.debugDescription)"
        case .invalidParameters:
            return "Invalid parameters for Keychain operation"
        case .stringDecodingFailed:
            return "Failed to decode Keychain data as UTF-8 string"
        case .dataConversionFailed:
            return "Failed to convert Keychain data to the requested type"
        case .publicKeyNotSupported:
            return "Public keys are not supported for Keychain key storage"
        case .multipleItemsFound:
            return "Multiple items found when at most one was expected"
        case .secureEnclaveNotAvailable:
            return "Secure Enclave is not available on this device"
        case .attributeParsingFailed:
            return "Failed to parse Keychain item attributes"
        case let .appEntitlementsError(underlyingError):
            if let underlyingError {
                return "App entitlements error: \(String(reflecting: underlyingError))"
            }
            return "App entitlements error"
        }
    }
}
