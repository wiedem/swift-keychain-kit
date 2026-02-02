internal import Foundation
internal import LocalAuthentication
private import Security

extension Keychain.GenericPassword {
    static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    static func applyQueryParameters(
        accountScope: Keychain.AccountScope,
        serviceScope: Keychain.ServiceScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        skipItemsIfUIRequired: Bool,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws {
        accountScope.apply(to: &query)
        serviceScope.apply(to: &query)
        try accessGroupScope.apply(to: &query)

        synchronizableScope.apply(to: &query)

        if skipItemsIfUIRequired {
            Keychain.ItemAttributes.AuthenticationUI.applySkipUI(to: &query)
        }

        authenticationContext.apply(to: &query)
    }

    static func applyAddParameters(
        data: CFData,
        account: String,
        service: String,
        label: String?,
        accessGroup: String?,
        synchronizable: Bool,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) {
        query[kSecValueData as String] = data

        Keychain.ItemAttributes.Account.apply(account, to: &query)
        Keychain.ItemAttributes.Service.apply(service, to: &query)

        Keychain.ItemAttributes.Label.apply(label, to: &query)
        Keychain.ItemAttributes.AccessGroup.apply(accessGroup, to: &query)
        Keychain.ItemAttributes.Synchronizable.apply(synchronizable, to: &query)

        authenticationContext.apply(to: &query)
    }

    static func applyUpdateParameters(
        account: String,
        service: String,
        accessGroup: String,
        synchronizable: Bool,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) {
        Keychain.ItemAttributes.Account.apply(account, to: &query)
        Keychain.ItemAttributes.Service.apply(service, to: &query)
        Keychain.ItemAttributes.AccessGroup.apply(accessGroup, to: &query)
        Keychain.ItemAttributes.Synchronizable.apply(synchronizable, to: &query)

        authenticationContext.apply(to: &query)
    }

    static func applyDeleteParameters(
        accountScope: Keychain.AccountScope,
        serviceScope: Keychain.ServiceScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        accountScope.apply(to: &query)
        serviceScope.apply(to: &query)
        try accessGroupScope.apply(to: &query)
        synchronizableScope.apply(to: &query)
        authenticationContext.apply(to: &query)
    }

    static func applyAttributesParameters(
        accountScope: Keychain.AccountScope,
        serviceScope: Keychain.ServiceScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        skipItemsIfUIRequired: Bool,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        accountScope.apply(to: &query)
        serviceScope.apply(to: &query)
        try accessGroupScope.apply(to: &query)

        synchronizableScope.apply(to: &query)

        if skipItemsIfUIRequired {
            Keychain.ItemAttributes.AuthenticationUI.applySkipUI(to: &query)
        }

        authenticationContext.apply(to: &query)
    }
}
