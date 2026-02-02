internal import Foundation
private import Security

public extension Keychain.ItemAttributes {
    enum AuthenticationType: Keychain.ItemAttributes.Attribute, Sendable {
        typealias ValueType = CFString

        static var keychainAttributeKey: CFString {
            kSecAttrAuthenticationType
        }
    }

    enum NetworkProtocol: Keychain.ItemAttributes.Attribute, Sendable {
        typealias ValueType = CFString

        static var keychainAttributeKey: CFString {
            kSecAttrProtocol
        }
    }
}
