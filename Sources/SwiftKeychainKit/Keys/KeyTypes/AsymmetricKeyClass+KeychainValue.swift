internal import Foundation
private import Security

extension AsymmetricKeyClass {
    var keychainValue: CFString {
        switch self {
        case .publicKey:
            kSecAttrKeyClassPublic
        case .privateKey:
            kSecAttrKeyClassPrivate
        }
    }

    static func make(for keychainValue: CFString) -> Self? {
        switch keychainValue {
        case kSecAttrKeyClassPublic:
            .publicKey
        case kSecAttrKeyClassPrivate:
            .privateKey
        default:
            nil
        }
    }

    static func make(for keychainValue: String) -> Self? {
        make(for: keychainValue as CFString)
    }

    static func make(for keychainValue: NSNumber) -> Self? {
        let stringValue = keychainValue.stringValue as CFString
        return .allCases.first(where: {
            $0.keychainValue == stringValue
        })
    }
}

public extension AsymmetricKeyClass {
    /// The corresponding scope for query and delete operations.
    ///
    /// Converts this key class into a ``Keychain/AsymmetricKeyClassScope`` that matches the same class.
    var scope: Keychain.AsymmetricKeyClassScope {
        switch self {
        case .publicKey:
            .publicKey
        case .privateKey:
            .privateKey
        }
    }
}
