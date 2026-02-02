internal import Foundation
private import Security

extension Keychain.SynchronizableScope: Keychain.KeychainValueProviding {
    var keychainValue: Any {
        switch self {
        case .synchronized:
            true
        case .notSynchronized:
            false
        case .any:
            kSecAttrSynchronizableAny
        }
    }
}

extension Keychain.SynchronizableScope {
    func apply(to query: inout [String: Any]) {
        query[Keychain.ItemAttributes.Synchronizable.keychainAttributeKey as String] = keychainValue
    }
}
