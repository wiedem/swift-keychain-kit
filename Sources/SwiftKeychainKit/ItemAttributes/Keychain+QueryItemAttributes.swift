internal import Foundation
internal import LocalAuthentication
private import Security

public extension Keychain.ItemAttributes {
    enum QueryLimit: Attribute {
        typealias ValueType = Any

        static var keychainAttributeKey: CFString {
            kSecMatchLimit
        }
    }

    enum AuthenticationUI: Attribute {
        typealias ValueType = CFString

        static var keychainAttributeKey: CFString {
            kSecUseAuthenticationUI
        }

        static func applySkipUI(to query: inout [String: Any]) {
            apply(kSecUseAuthenticationUISkip, to: &query)
        }
    }

    enum AuthenticationContext: Attribute {
        typealias ValueType = LAContext

        static var keychainAttributeKey: CFString {
            kSecUseAuthenticationContext
        }
    }
}
