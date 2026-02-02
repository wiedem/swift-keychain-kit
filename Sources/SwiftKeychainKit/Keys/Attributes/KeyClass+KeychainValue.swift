internal import Foundation
private import Security

extension Keychain.Keys.KeyClass {
    var keychainValue: CFString {
        switch self {
        case .publicKey:
            kSecAttrKeyClassPublic
        case .privateKey:
            kSecAttrKeyClassPrivate
        case .symmetric:
            kSecAttrKeyClassSymmetric
        }
    }

    static func make(for keychainValue: CFString) -> Self? {
        switch keychainValue {
        case kSecAttrKeyClassPublic:
            .publicKey
        case kSecAttrKeyClassPrivate:
            .privateKey
        case kSecAttrKeyClassSymmetric:
            .symmetric
        default:
            nil
        }
    }

    static func make(for keychainValue: NSNumber) -> Self? {
        let stringValue = keychainValue.stringValue as CFString
        return .allCases.first(where: { $0.keychainValue == stringValue })
    }

    static func make(for keychainValue: String) -> Self? {
        make(for: keychainValue as CFString)
    }

    static func get(from dictionary: [String: Any]) -> Self? {
        switch dictionary[kSecAttrKeyClass as String] {
        case let numericValue as NSNumber:
            make(for: numericValue)
        case let stringValue as String:
            make(for: stringValue)
        default:
            nil
        }
    }
}
