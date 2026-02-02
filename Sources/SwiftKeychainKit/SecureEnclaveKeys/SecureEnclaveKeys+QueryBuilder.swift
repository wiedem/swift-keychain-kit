internal import Foundation
internal import LocalAuthentication
private import Security

extension Keychain.SecureEnclaveKeys {
    static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
    }

    static func applyDeleteParameters(
        applicationTagScope: Keychain.ApplicationTagScope,
        applicationLabelScope: Keychain.ApplicationLabelScope,
        accessGroupScope: Keychain.AccessGroupScope,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        applicationTagScope.apply(to: &query)
        applicationLabelScope.apply(to: &query)
        try accessGroupScope.apply(to: &query)
        authenticationContext.apply(to: &query)
    }

    static func applyQueryParameters(
        applicationTagScope: Keychain.ApplicationTagScope,
        applicationLabelScope: Keychain.ApplicationLabelScope,
        accessGroupScope: Keychain.AccessGroupScope,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        applicationTagScope.apply(to: &query)
        applicationLabelScope.apply(to: &query)
        try accessGroupScope.apply(to: &query)
        authenticationContext.apply(to: &query)
    }

    static func applyAttributesParameters(
        applicationTagScope: Keychain.ApplicationTagScope,
        applicationLabelScope: Keychain.ApplicationLabelScope,
        accessGroupScope: Keychain.AccessGroupScope,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        applicationTagScope.apply(to: &query)
        applicationLabelScope.apply(to: &query)
        try accessGroupScope.apply(to: &query)

        authenticationContext.apply(to: &query)
    }
}

extension Keychain.SecureEnclaveKeys {
    static func applyGenerateParameters(
        applicationTag: Data,
        applicationLabel: Data?,
        label: String?,
        accessGroup: String?,
        accessControl: AccessControl,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        // Set the common attributes
        query[kSecUseDataProtectionKeychain as String] = true
        query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        query[kSecAttrKeyType as String] = kSecAttrKeyTypeECSECPrimeRandom
        Keychain.ItemAttributes.KeySizeInBits.apply(256, to: &query)

        authenticationContext.apply(to: &query)

        // Create the private key attributes
        var privateKeyAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
        ]
        Keychain.ItemAttributes.ApplicationTag.apply(applicationTag, to: &privateKeyAttributes)
        try accessControl.apply(to: &privateKeyAttributes)

        Keychain.ItemAttributes.AccessGroup.apply(accessGroup, to: &privateKeyAttributes)
        Keychain.ItemAttributes.Label.apply(label, to: &privateKeyAttributes)
        Keychain.ItemAttributes.ApplicationLabel.apply(applicationLabel, to: &privateKeyAttributes)

        query[kSecPrivateKeyAttrs as String] = privateKeyAttributes
    }
}
