public import Foundation
public import LocalAuthentication
private import Security

public extension Keychain.SecureEnclaveKeys {
    /// Generates a new private key in the Secure Enclave.
    ///
    /// Keys generated in the Secure Enclave cannot be exported or migrated to other devices. Only 256-bit elliptic curve (ECC)
    /// keys are supported.
    ///
    /// - Parameters:
    ///   - applicationTag: A unique tag to identify the key.
    ///   - applicationLabel: The application label for the key. Defaults to using the public key hash.
    ///   - label: An optional user-visible label for the key.
    ///   - accessGroup: The access group for the key. Defaults to the app's default keychain access group.
    ///   - accessControl: The access control constraints for the key. Must use a `ThisDeviceOnly` accessibility. The
    ///     `.privateKeyUsage` flag is automatically added if not present.
    ///   - authenticationContext: An optional authentication context for the operation.
    ///
    /// - Returns: The generated private key.
    ///
    /// - Throws: A ``KeychainError`` if the key generation fails.
    ///   * ``KeychainError/secureEnclaveNotAvailable`` if the Secure Enclave is not available on the device.
    ///   * ``KeychainError/duplicateItem`` if a key with the same application tag and label already exists.
    ///
    /// - SeeAlso:
    ///   * [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
    ///   * [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
    ///   * [Storing Keys in the Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave)
    static func generate(
        applicationTag: Data,
        applicationLabel: Keychain.Keys.ApplicationLabel = .publicKeyHash,
        label: String? = nil,
        accessGroup: Keychain.AccessGroup = .default,
        accessControl: AccessControl = .whenUnlockedThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) async throws(KeychainError) -> SecKey {
        guard isAvailable else {
            throw .secureEnclaveNotAvailable
        }

        var attributes: [String: Any] = [:]

        try applyGenerateParameters(
            applicationTag: applicationTag,
            applicationLabel: applicationLabel.dataValue,
            label: label,
            accessGroup: accessGroup.valueForAdd,
            accessControl: accessControl,
            authenticationContext: authenticationContext,
            to: &attributes
        )

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            guard let cfError = error?.takeRetainedValue() else {
                throw .invalidParameters
            }
            // According to the documentation, SecKeyCreateRandomKey populates errors with "Security Error Codes" defined in "SecBase.h"
            let errorCode = OSStatus(CFErrorGetCode(cfError))
            throw .securityError(errorCode)
        }

        return privateKey
    }
}
