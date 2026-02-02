internal import Foundation

extension Keychain.ProviderAccessGroupScope: Keychain.KeychainValueProviding {
    var keychainValue: String? {
        get throws(KeychainError) {
            switch self {
            case .any:
                return nil

            case let .specific(groupIdentifier):
                return groupIdentifier

            case .default:
                return try AccessGroupProvider.defaultKeychainAccessGroup
            }
        }
    }
}

extension Keychain.ProviderAccessGroupScope {
    func apply(to query: inout [String: Any]) throws(KeychainError) {
        try Keychain.ItemAttributes.AccessGroup.apply(keychainValue, to: &query)
    }
}
