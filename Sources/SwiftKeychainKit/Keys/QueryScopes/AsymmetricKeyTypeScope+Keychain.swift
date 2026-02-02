import Foundation
private import Security

extension Keychain.AsymmetricKeyTypeScope {
    func apply(to query: inout [String: Any]) {
        query[kSecAttrKeyType as String] = keyTypeKeychainValue
        keyClassScope.apply(to: &query)
    }
}

extension Keychain.AsymmetricKeyTypeScope {
    var keyTypeKeychainValue: CFString {
        switch self {
        case .rsa:
            kSecAttrKeyTypeRSA
        case .ellipticCurve:
            kSecAttrKeyTypeECSECPrimeRandom
        }
    }

    var keyClassKeychainValue: CFString? {
        switch self {
        case let .rsa(keyClass), let .ellipticCurve(keyClass):
            keyClass.keychainValue
        }
    }
}
