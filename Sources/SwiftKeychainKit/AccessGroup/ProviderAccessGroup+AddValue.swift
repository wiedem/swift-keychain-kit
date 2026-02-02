extension Keychain.ProviderAccessGroup {
    // Note: Access group values set via kSecAttrAccessGroup for SecItemAdd behave differently than for
    // SecItemUpdate / SecItemDelete and SecItemCopyMatching.
    // See the documentation of kSecAttrAccessGroup for details about it:
    // https://developer.apple.com/documentation/security/ksecattraccessgroup
    var valueForAdd: String? {
        switch self {
        case .default:
            nil
        case let .identifier(identifier):
            identifier
        }
    }
}
