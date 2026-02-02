internal import Foundation
internal import LocalAuthentication
private import Security

extension Keychain.InternetPassword {
    static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassInternetPassword,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    static func applyQueryParameters(
        accountScope: Keychain.AccountScope,
        serverScope: Keychain.ServerScope,
        protocolScope: Keychain.ProtocolScope,
        authenticationTypeScope: Keychain.AuthenticationTypeScope,
        portScope: Keychain.PortScope,
        pathScope: Keychain.PathScope,
        securityDomainScope: Keychain.SecurityDomainScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        skipItemsIfUIRequired: Bool,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        accountScope.apply(to: &query)
        serverScope.apply(to: &query)
        try protocolScope.apply(to: &query)
        try authenticationTypeScope.apply(to: &query)

        portScope.apply(to: &query)
        pathScope.apply(to: &query)
        securityDomainScope.apply(to: &query)
        try accessGroupScope.apply(to: &query)

        synchronizableScope.apply(to: &query)

        if skipItemsIfUIRequired {
            Keychain.ItemAttributes.AuthenticationUI.applySkipUI(to: &query)
        }

        authenticationContext.apply(to: &query)
    }

    static func applyAddParameters(
        data: NSData,
        account: String,
        server: String,
        protocol networkProtocol: NetworkProtocol?,
        authenticationType: AuthenticationType?,
        port: Int,
        path: String,
        securityDomain: String,
        label: String?,
        accessGroup: String?,
        synchronizable: Bool,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        query[kSecValueData as String] = data

        Keychain.ItemAttributes.Account.apply(account, to: &query)
        Keychain.ItemAttributes.Server.apply(server, to: &query)

        try Keychain.ItemAttributes.NetworkProtocol.apply(networkProtocol, to: &query)
        try Keychain.ItemAttributes.AuthenticationType.apply(authenticationType, to: &query)

        Keychain.ItemAttributes.Port.apply(port, to: &query)
        Keychain.ItemAttributes.Path.apply(path, to: &query)
        Keychain.ItemAttributes.SecurityDomain.apply(securityDomain, to: &query)
        Keychain.ItemAttributes.Label.apply(label, to: &query)
        Keychain.ItemAttributes.AccessGroup.apply(accessGroup, to: &query)
        Keychain.ItemAttributes.Synchronizable.apply(synchronizable, to: &query)
    }

    static func applyUpdateParameters(
        account: String,
        server: String,
        protocol networkProtocol: NetworkProtocol?,
        authenticationType: AuthenticationType?,
        port: Int?,
        path: String?,
        securityDomain: String?,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        Keychain.ItemAttributes.Account.apply(account, to: &query)
        Keychain.ItemAttributes.Server.apply(server, to: &query)

        try Keychain.ItemAttributes.NetworkProtocol.apply(networkProtocol, to: &query)
        try Keychain.ItemAttributes.AuthenticationType.apply(authenticationType, to: &query)
        Keychain.ItemAttributes.Port.apply(port, to: &query)
        Keychain.ItemAttributes.Path.apply(path, to: &query)
        Keychain.ItemAttributes.SecurityDomain.apply(securityDomain, to: &query)

        try accessGroupScope.apply(to: &query)

        synchronizableScope.apply(to: &query)

        authenticationContext.apply(to: &query)
    }

    static func applyDeleteParameters(
        accountScope: Keychain.AccountScope,
        serverScope: Keychain.ServerScope,
        protocolScope: Keychain.ProtocolScope,
        authenticationTypeScope: Keychain.AuthenticationTypeScope,
        portScope: Keychain.PortScope,
        pathScope: Keychain.PathScope,
        securityDomainScope: Keychain.SecurityDomainScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        accountScope.apply(to: &query)
        serverScope.apply(to: &query)

        try protocolScope.apply(to: &query)
        try authenticationTypeScope.apply(to: &query)
        portScope.apply(to: &query)
        pathScope.apply(to: &query)
        securityDomainScope.apply(to: &query)

        try accessGroupScope.apply(to: &query)

        synchronizableScope.apply(to: &query)

        authenticationContext.apply(to: &query)
    }

    static func applyAttributesParameters(
        accountScope: Keychain.AccountScope,
        serverScope: Keychain.ServerScope,
        protocolScope: Keychain.ProtocolScope,
        authenticationTypeScope: Keychain.AuthenticationTypeScope,
        portScope: Keychain.PortScope,
        pathScope: Keychain.PathScope,
        securityDomainScope: Keychain.SecurityDomainScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        skipItemsIfUIRequired: Bool,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        accountScope.apply(to: &query)
        serverScope.apply(to: &query)
        try protocolScope.apply(to: &query)
        try authenticationTypeScope.apply(to: &query)

        portScope.apply(to: &query)
        pathScope.apply(to: &query)
        securityDomainScope.apply(to: &query)
        try accessGroupScope.apply(to: &query)

        synchronizableScope.apply(to: &query)

        if skipItemsIfUIRequired {
            Keychain.ItemAttributes.AuthenticationUI.applySkipUI(to: &query)
        }

        authenticationContext.apply(to: &query)
    }
}
