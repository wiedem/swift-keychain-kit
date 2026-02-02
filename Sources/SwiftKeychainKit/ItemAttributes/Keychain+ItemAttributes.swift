internal import Foundation
private import Security

public extension Keychain {
    /// Namespace for Keychain item attribute types.
    ///
    /// This type serves as a namespace for the various attribute types used in Keychain operations. You typically don't use
    /// this type directly; instead, you use the type aliases like ``AccountScope``, ``ServiceScope``, etc., which provide
    /// convenient access to query scopes for specific attributes.
    ///
    /// - SeeAlso: ``QueryScope``
    enum ItemAttributes {}
}

extension Keychain.ItemAttributes {
    protocol Attribute: Sendable {
        associatedtype ValueType

        static var keychainAttributeKey: CFString { get }
    }
}

extension Keychain.ItemAttributes.Attribute {
    static func apply(_ value: ValueType, to dictionary: inout [String: Any]) {
        dictionary[keychainAttributeKey as String] = value
    }

    static func apply(_ value: ValueType?, to dictionary: inout [String: Any]) {
        if let value {
            apply(value, to: &dictionary)
        } else {
            dictionary.removeValue(forKey: Self.keychainAttributeKey as String)
        }
    }

    static func get(from dictionary: [String: Any]) -> ValueType? {
        dictionary[keychainAttributeKey as String] as? ValueType
    }
}

extension Keychain.ItemAttributes.Attribute {
    static func apply<Value: Keychain.KeychainValueProviding>(
        _ value: Value,
        to dictionary: inout [String: Any]
    ) throws(KeychainError) where ValueType == Value.KeychainValue {
        try dictionary[keychainAttributeKey as String] = value.keychainValue
    }

    static func apply<Value: Keychain.KeychainValueProviding>(
        _ value: Value?,
        to dictionary: inout [String: Any]
    ) throws(KeychainError) where ValueType == Value.KeychainValue {
        if let value {
            try apply(value, to: &dictionary)
        } else {
            dictionary.removeValue(forKey: Self.keychainAttributeKey as String)
        }
    }

    static func get<Value: Keychain.KeychainValueInitializable>(
        from dictionary: [String: Any]
    ) -> Value? where ValueType == Value.KeychainValue {
        guard let keychainValue = dictionary[keychainAttributeKey as String] as? ValueType else {
            return nil
        }
        return Value(keychainValue: keychainValue)
    }
}
