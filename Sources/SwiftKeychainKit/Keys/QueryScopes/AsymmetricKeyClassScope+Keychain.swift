internal import Foundation

extension Keychain.AsymmetricKeyClassScope{
    func apply(to query: inout [String: Any]) {
        if let keychainValue {
            query[kSecAttrKeyClass as String] = keychainValue
        } else {
            query.removeValue(forKey: kSecAttrKeyClass as String)
        }
    }
}

extension Keychain.AsymmetricKeyClassScope {
    var keychainValue: CFString? {
        switch self {
        case .publicKey:
            kSecAttrKeyClassPublic
        case .privateKey:
            kSecAttrKeyClassPrivate
        case .any:
            nil
        }
    }
}
