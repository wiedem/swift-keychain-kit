private import Foundation
internal import Security

extension AsymmetricKeyClass {
    init?(from key: SecKey) {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any] else {
            return nil
        }

        guard let keyClass = switch attributes[kSecAttrKeyClass as String] {
        case let value as CFString:
            Self.make(for: value)
        case let value as String:
            Self.make(for: value)
        case let value as NSNumber:
            Self.make(for: value)
        default:
            nil
        } else {
            return nil
        }

        self = keyClass
    }
}
