@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("SecureEnclaveKeysParseAttributesTests")
struct SecureEnclaveKeysParseAttributesTests {
    // MARK: - Successful Parsing Tests

    @Test("parseAttributes with minimal required attributes")
    func parseAttributesWithMinimalAttributes() throws {
        let applicationTag = "tag".data(using: .utf8)!
        let dict: [String: Any] = [
            kSecAttrApplicationTag as String: applicationTag,
        ]

        let attributes = try Keychain.SecureEnclaveKeys.parseAttributes(from: dict)

        #expect(attributes.applicationTag == applicationTag)
        #expect(attributes.applicationLabel == Data())
        #expect(attributes.label == nil)
        #expect(attributes.accessGroup == nil)
    }

    @Test("parseAttributes with all attributes")
    func parseAttributesWithAllAttributes() throws {
        let applicationTag = "tag".data(using: .utf8)!
        let applicationLabel = "label".data(using: .utf8)!
        let dict: [String: Any] = [
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrApplicationLabel as String: applicationLabel,
            kSecAttrLabel as String: "Test Key",
            kSecAttrAccessGroup as String: "group.test",
        ]

        let attributes = try Keychain.SecureEnclaveKeys.parseAttributes(from: dict)

        #expect(attributes.applicationTag == applicationTag)
        #expect(attributes.applicationLabel == applicationLabel)
        #expect(attributes.label == "Test Key")
        #expect(attributes.accessGroup == "group.test")
    }

    // MARK: - Failure Tests

    @Test(
        "parseAttributes returns nil when required attribute is missing",
        arguments: [
            MissingAttributeTestCase(
                "application tag",
                key: kSecAttrApplicationTag
            ),
        ]
    )
    func parseAttributesReturnsNilWhenRequiredAttributeMissing(testCase: MissingAttributeTestCase) throws {
        let applicationTag = "tag".data(using: .utf8)!

        var dict: [String: Any] = [
            kSecAttrApplicationTag as String: applicationTag,
        ]

        testCase.removeValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.SecureEnclaveKeys.parseAttributes(from: dict)
        }
    }

    // MARK: - Type Coercion Tests

    @Test(
        "parseAttributes throws when required attribute has wrong type",
        arguments: [
            WrongTypeTestCase(
                "application tag",
                key: kSecAttrApplicationTag,
                wrongValue: "tag"
            ),
        ]
    )
    func parseAttributesThrowsWhenRequiredAttributeHasWrongType(testCase: WrongTypeTestCase) {
        let applicationTag = "tag".data(using: .utf8)!

        var dict: [String: Any] = [
            kSecAttrApplicationTag as String: applicationTag,
        ]

        testCase.setWrongValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.SecureEnclaveKeys.parseAttributes(from: dict)
        }
    }

    @Test("parseAttributes ignores optional attributes with wrong types")
    func parseAttributesIgnoresOptionalAttributesWithWrongTypes() throws {
        let applicationTag = "tag".data(using: .utf8)!
        let dict: [String: Any] = [
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrApplicationLabel as String: "label",
            kSecAttrLabel as String: 123,
            kSecAttrAccessGroup as String: 456,
        ]

        let attributes = try Keychain.SecureEnclaveKeys.parseAttributes(from: dict)

        #expect(attributes.applicationTag == applicationTag)
        #expect(attributes.applicationLabel == Data())
        #expect(attributes.label == nil)
        #expect(attributes.accessGroup == nil)
    }
}

extension SecureEnclaveKeysParseAttributesTests {
    struct MissingAttributeTestCase: Sendable {
        let name: String
        let secAttrKey: String

        init(_ name: String, key: CFString) {
            self.name = name
            self.secAttrKey = key as String
        }

        func removeValue(in dict: inout [String: Any]) {
            dict.removeValue(forKey: secAttrKey)
        }
    }

    struct WrongTypeTestCase: Sendable {
        let name: String
        let secAttrKey: String
        let wrongValue: @Sendable () -> Any

        init(_ name: String, key: CFString, wrongValue: @Sendable @escaping @autoclosure () -> Any) {
            self.name = name
            self.secAttrKey = key as String
            self.wrongValue = wrongValue
        }

        func setWrongValue(in dict: inout [String: Any]) {
            dict[secAttrKey] = wrongValue()
        }
    }
}
