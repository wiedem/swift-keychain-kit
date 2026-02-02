extension Keychain.ProviderAccessGroup {
    var valueForGet: String {
        get throws(KeychainError) {
            switch self {
            case .default:
                try AccessGroupProvider.defaultKeychainAccessGroup
            case let .identifier(identifier):
                identifier
            }
        }
    }
}
