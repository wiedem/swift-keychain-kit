internal import Foundation
internal import LocalAuthentication
private import Security

extension Keychain.Keys {
    static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    static func applyQueryParameters(
        keyTypeScope: Keychain.AsymmetricKeyTypeScope,
        applicationTagScope: Keychain.ApplicationTagScope,
        applicationLabelScope: Keychain.ApplicationLabelScope,
        keySizeInBitsScope: Keychain.KeySizeInBitsScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        skipItemsIfUIRequired: Bool,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        keyTypeScope.apply(to: &query)
        applicationTagScope.apply(to: &query)
        applicationLabelScope.apply(to: &query)
        keySizeInBitsScope.apply(to: &query)
        try accessGroupScope.apply(to: &query)

        synchronizableScope.apply(to: &query)

        if skipItemsIfUIRequired {
            Keychain.ItemAttributes.AuthenticationUI.applySkipUI(to: &query)
        }

        authenticationContext.apply(to: &query)
    }

    static func applyAddParameters(
        key: SecKey,
        applicationTag: Data?,
        applicationLabel: ApplicationLabel,
        label: String?,
        accessGroup: Keychain.AccessGroup,
        synchronizable: Bool,
        to query: inout [String: Any]
    ) {
        query[kSecValueRef as String] = key

        Keychain.ItemAttributes.ApplicationTag.apply(applicationTag, to: &query)
        Keychain.ItemAttributes.ApplicationLabel.apply(applicationLabel.dataValue, to: &query)
        Keychain.ItemAttributes.Label.apply(label, to: &query)
        Keychain.ItemAttributes.AccessGroup.apply(accessGroup.valueForAdd, to: &query)
        Keychain.ItemAttributes.Synchronizable.apply(synchronizable, to: &query)
    }

    static func applyDeleteParameters(
        keyTypeScope: Keychain.AsymmetricKeyTypeScope,
        applicationTag: Data?,
        applicationLabel: Data?,
        keySizeInBits: Int?,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        keyTypeScope.apply(to: &query)
        Keychain.ItemAttributes.ApplicationTag.apply(applicationTag, to: &query)
        Keychain.ItemAttributes.ApplicationLabel.apply(applicationLabel, to: &query)
        Keychain.ItemAttributes.KeySizeInBits.apply(keySizeInBits, to: &query)

        try accessGroupScope.apply(to: &query)
        synchronizableScope.apply(to: &query)
    }

    static func applyAttributesParameters(
        keyTypeScope: Keychain.AsymmetricKeyTypeScope,
        applicationTagScope: Keychain.ApplicationTagScope,
        applicationLabelScope: Keychain.ApplicationLabelScope,
        keySizeInBitsScope: Keychain.KeySizeInBitsScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        skipItemsIfUIRequired: Bool,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        keyTypeScope.apply(to: &query)
        applicationTagScope.apply(to: &query)
        applicationLabelScope.apply(to: &query)
        keySizeInBitsScope.apply(to: &query)
        try accessGroupScope.apply(to: &query)

        synchronizableScope.apply(to: &query)

        if skipItemsIfUIRequired {
            Keychain.ItemAttributes.AuthenticationUI.applySkipUI(to: &query)
        }

        authenticationContext.apply(to: &query)
    }
}

extension Keychain.Keys {
    static func requirePrivateKey(_ key: SecKey) throws(KeychainError) {
        guard let keyClass = AsymmetricKeyClass(from: key) else {
            throw KeychainError.invalidParameters
        }
        guard keyClass == .privateKey else {
            throw KeychainError.publicKeyNotSupported
        }
    }
}
