@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("Item Attributes Tests")
struct ItemAttributesTests {
    @Test("All attribute keys return correct Security constants")
    func allAttributeKeysReturnCorrectSecurityConstants() {
        #expect(Keychain.ItemAttributes.Account.keychainAttributeKey == kSecAttrAccount)
        #expect(Keychain.ItemAttributes.AccessGroup.keychainAttributeKey == kSecAttrAccessGroup)
        #expect(Keychain.ItemAttributes.ApplicationLabel.keychainAttributeKey == kSecAttrApplicationLabel)
        #expect(Keychain.ItemAttributes.ApplicationTag.keychainAttributeKey == kSecAttrApplicationTag)
        #expect(Keychain.ItemAttributes.Issuer.keychainAttributeKey == kSecAttrIssuer)
        #expect(Keychain.ItemAttributes.KeySizeInBits.keychainAttributeKey == kSecAttrKeySizeInBits)
        #expect(Keychain.ItemAttributes.Label.keychainAttributeKey == kSecAttrLabel)
        #expect(Keychain.ItemAttributes.Path.keychainAttributeKey == kSecAttrPath)
        #expect(Keychain.ItemAttributes.Port.keychainAttributeKey == kSecAttrPort)
        #expect(Keychain.ItemAttributes.SecurityDomain.keychainAttributeKey == kSecAttrSecurityDomain)
        #expect(Keychain.ItemAttributes.SerialNumber.keychainAttributeKey == kSecAttrSerialNumber)
        #expect(Keychain.ItemAttributes.Server.keychainAttributeKey == kSecAttrServer)
        #expect(Keychain.ItemAttributes.Service.keychainAttributeKey == kSecAttrService)
        #expect(Keychain.ItemAttributes.Synchronizable.keychainAttributeKey == kSecAttrSynchronizable)
        #expect(Keychain.ItemAttributes.ItemDescription.keychainAttributeKey == kSecAttrDescription)
        #expect(Keychain.ItemAttributes.ItemAccessibility.keychainAttributeKey == kSecAttrAccessible)
        #expect(Keychain.ItemAttributes.QueryLimit.keychainAttributeKey == kSecMatchLimit)
        #expect(Keychain.ItemAttributes.AuthenticationContext.keychainAttributeKey == kSecUseAuthenticationContext)
        #expect(Keychain.ItemAttributes.AuthenticationUI.keychainAttributeKey == kSecUseAuthenticationUI)
    }

    @Test("All internal attribute keys return correct Security constants")
    func allInternalAttributeKeysReturnCorrectSecurityConstants() {
        #expect(Keychain.ItemAttributes.CreationDate.keychainAttributeKey == kSecAttrCreationDate)
        #expect(Keychain.ItemAttributes.ModificationDate.keychainAttributeKey == kSecAttrModificationDate)
    }

    @Test("Apply method adds attribute with value to dictionary")
    func applyMethodAddsAttributeWithValueToDictionary() {
        var dictionary: [String: Any] = [:]

        Keychain.ItemAttributes.Test.apply("Value", to: &dictionary)

        #expect(dictionary[Keychain.ItemAttributes.Test.keychainAttributeKey as String] as? String == "Value")
    }

    @Test("Apply method adds attribute with optional value to dictionary")
    func applyMethodAddsAttributeWithOptionalValueToDictionary() {
        var dictionary: [String: Any] = [:]
        let value: String? = "Value"

        Keychain.ItemAttributes.Test.apply(value, to: &dictionary)

        #expect(dictionary[Keychain.ItemAttributes.Test.keychainAttributeKey as String] as? String == "Value")
    }

    @Test("Apply method removes attribute with optional nil value from dictionary")
    func applyMethodRemovesAttributeWithOptionalNilValueFromDictionary() {
        var dictionary: [String: Any] = [:]
        let value: String? = nil

        Keychain.ItemAttributes.Test.apply(value, to: &dictionary)

        #expect(dictionary[Keychain.ItemAttributes.Test.keychainAttributeKey as String] == nil)
    }

    @Test("Apply method adds attribute with keychain value to dictionary")
    func applyMethodAddsAttributeWithKeychainValueToDictionary() throws {
        var dictionary: [String: Any] = [:]
        let value: KeychainValue = .test1

        try Keychain.ItemAttributes.Test.apply(value, to: &dictionary)

        let dictionaryValue = dictionary[Keychain.ItemAttributes.Test.keychainAttributeKey as String]
        #expect(dictionaryValue as? String == value.keychainValue)
    }

    @Test("Apply method adds attribute with optional keychain value to dictionary")
    func applyMethodAddsAttributeWithOptionalKeychainValueToDictionary() throws {
        var dictionary: [String: Any] = [:]
        let value: KeychainValue! = .test1

        try Keychain.ItemAttributes.Test.apply(value, to: &dictionary)

        let dictionaryValue = dictionary[Keychain.ItemAttributes.Test.keychainAttributeKey as String]
        #expect(dictionaryValue as? String == value.keychainValue)
    }

    @Test("Get method returns attribute value from dictionary")
    func getMethodReturnsAttributeValueFromDictionary() {
        let dictionary: [String: Any] = [
            Keychain.ItemAttributes.Test.keychainAttributeKey as String: "Value"
        ]

        let value = Keychain.ItemAttributes.Test.get(from: dictionary)

        #expect(value == "Value")
    }

    @Test("Get method returns nil when attribute is missing from dictionary")
    func getMethodReturnsNilWhenAttributeIsMissingFromDictionary() {
        let dictionary: [String: Any] = [:]

        let value = Keychain.ItemAttributes.Test.get(from: dictionary)

        #expect(value == nil)
    }

    @Test("Get method returns nil when attribute has wrong type in dictionary")
    func getMethodReturnsNilWhenAttributeHasWrongTypeInDictionary() {
        let dictionary: [String: Any] = [
            Keychain.ItemAttributes.Test.keychainAttributeKey as String: 123
        ]

        let value = Keychain.ItemAttributes.Test.get(from: dictionary)

        #expect(value == nil)
    }

    @Test("Get method returns keychain value from dictionary")
    func getMethodReturnsKeychainValueFromDictionary() {
        let dictionary: [String: Any] = [
            Keychain.ItemAttributes.Test.keychainAttributeKey as String: "test1"
        ]

        let value: KeychainValue? = Keychain.ItemAttributes.Test.get(from: dictionary)

        #expect(value == .test1)
    }

    @Test("Get method returns nil when keychain value is invalid")
    func getMethodReturnsNilWhenKeychainValueIsInvalid() {
        let dictionary: [String: Any] = [
            Keychain.ItemAttributes.Test.keychainAttributeKey as String: "invalid"
        ]

        let value: KeychainValue? = Keychain.ItemAttributes.Test.get(from: dictionary)

        #expect(value == nil)
    }

    @Test("AuthenticationUIKey applySkipUI sets correct value")
    func authenticationUIKeyApplySkipUISetsCorrectValue() {
        var query: [String: Any] = [:]

        Keychain.ItemAttributes.AuthenticationUI.applySkipUI(to: &query)

        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
    }
}

private extension Keychain.ItemAttributes {
    enum Test: Attribute {
        typealias ValueType = String

        static var keychainAttributeKey: CFString {
            "Test" as CFString
        }
    }
}

private extension ItemAttributesTests {
    enum KeychainValue: String, Keychain.KeychainValueConvertible {
        case test1
        case test2

        var keychainValue: String { rawValue }

        init?(keychainValue: String) {
            self.init(rawValue: keychainValue)
        }
    }
}
