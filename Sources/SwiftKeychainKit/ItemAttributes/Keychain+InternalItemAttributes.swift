internal import Foundation
private import Security

public extension Keychain.ItemAttributes {
    enum CreationDate: Attribute, Sendable {
        typealias ValueType = Date

        static var keychainAttributeKey: CFString {
            kSecAttrCreationDate
        }
    }

    enum ModificationDate: Attribute, Sendable {
        typealias ValueType = Date

        static var keychainAttributeKey: CFString {
            kSecAttrModificationDate
        }
    }

    enum PersistentReference: Attribute, Sendable {
        typealias ValueType = Data

        static var keychainAttributeKey: CFString {
            kSecValuePersistentRef
        }
    }
}
