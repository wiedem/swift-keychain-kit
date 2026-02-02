extension AsymmetricKeyType {
    var keychainQueryScope: Keychain.AsymmetricKeyTypeScope {
        switch self {
        case let .rsa(keyClass):
            .rsa(keyClass.keychainQueryScope)
        case let .ellipticCurve(keyClass):
            .ellipticCurve(keyClass.keychainQueryScope)
        }
    }
}
