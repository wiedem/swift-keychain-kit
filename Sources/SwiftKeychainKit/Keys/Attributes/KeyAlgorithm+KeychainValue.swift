internal import Foundation
private import Security

extension Keychain.Keys.KeyAlgorithm {
    var keychainValue: CFString {
        switch self {
        case .rsa:
            kSecAttrKeyTypeRSA
        case .ellipticCurve:
            kSecAttrKeyTypeECSECPrimeRandom
        #if os(macOS)
        case .des:
            kSecAttrKeyTypeDES
        case .tripleDES:
            kSecAttrKeyType3DES
        case .rc4:
            kSecAttrKeyTypeRC4
        case .rc2:
            kSecAttrKeyTypeRC2
        case .cast:
            kSecAttrKeyTypeCAST
        case .dsa:
            kSecAttrKeyTypeDSA
        #endif
        }
    }

    static func make(for keychainValue: CFString) -> Self? {
        switch keychainValue {
        case kSecAttrKeyTypeRSA:
            .rsa
        case kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyTypeEC:
            .ellipticCurve
        #if os(macOS)
        case kSecAttrKeyTypeDES:
            .des
        case kSecAttrKeyType3DES:
            .tripleDES
        case kSecAttrKeyTypeRC4:
            .rc4
        case kSecAttrKeyTypeRC2:
            .rc2
        case kSecAttrKeyTypeCAST:
            .cast
        case kSecAttrKeyTypeDSA:
            .dsa
        #endif
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
        switch dictionary[kSecAttrKeyType as String] {
        case let numericValue as NSNumber:
            make(for: numericValue)
        case let stringValue as String:
            make(for: stringValue)
        default:
            nil
        }
    }
}
