@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("KeysParseAttributesTests")
struct KeysParseAttributesTests {
    // MARK: - Successful Parsing Tests

    @Test("parseAttributes with minimal required attributes")
    func parseAttributesWithMinimalAttributes() throws {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)

        let dict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrCreationDate as String: creationDate,
        ]

        let attributes = try Keychain.Keys.parseAttributes(from: dict)

        #expect(attributes.algorithm == .rsa)
        #expect(attributes.keyClass == .privateKey)
        #expect(attributes.keySizeInBits == 2048)
        #expect(attributes.applicationLabel == nil)
        #expect(attributes.applicationTag == nil)
        #expect(attributes.label == nil)
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.accessGroup == nil)
        #expect(attributes.synchronizable == false)
    }

    @Test("parseAttributes with all attributes")
    func parseAttributesWithAllAttributes() throws {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let applicationLabel = Data("label".utf8)
        let applicationTag = Data("tag".utf8)
        let dict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrApplicationLabel as String: applicationLabel,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrLabel as String: "Test Key",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrAccessGroup as String: "group.test",
            kSecAttrSynchronizable as String: true,
        ]

        let attributes = try Keychain.Keys.parseAttributes(from: dict)

        #expect(attributes.algorithm == .ellipticCurve)
        #expect(attributes.keyClass == .publicKey)
        #expect(attributes.keySizeInBits == 256)
        #expect(attributes.applicationLabel == applicationLabel)
        #expect(attributes.applicationTag == applicationTag)
        #expect(attributes.label == "Test Key")
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.accessGroup == "group.test")
        #expect(attributes.synchronizable == true)
    }

    // MARK: - Failure Tests

    @Test(
        "parseAttributes returns nil when required attribute is missing",
        arguments: [
            MissingAttributeTestCase(
                "key type missing",
                key: kSecAttrKeyType
            ),
            MissingAttributeTestCase(
                "key class missing",
                key: kSecAttrKeyClass
            ),
            MissingAttributeTestCase(
                "keySizeInBits missing",
                key: kSecAttrKeySizeInBits
            ),
        ]
    )
    func parseAttributesReturnsNilWhenRequiredAttributeMissing(testCase: MissingAttributeTestCase) {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)

        var dict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrCreationDate as String: creationDate,
        ]

        testCase.removeValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.Keys.parseAttributes(from: dict)
        }
    }

    // MARK: - Type Coercion Tests

    @Test(
        "parseAttributes throws when required attribute has wrong type",
        arguments: [
            WrongTypeTestCase(
                "key type with wrong type",
                key: kSecAttrKeyType,
                wrongValue: 123
            ),
            WrongTypeTestCase(
                "key class with wrong type",
                key: kSecAttrKeyClass,
                wrongValue: 456
            ),
            WrongTypeTestCase(
                "keySizeInBits with wrong type",
                key: kSecAttrKeySizeInBits,
                wrongValue: "2048"
            ),
        ]
    )
    func parseAttributesThrowsWhenRequiredAttributeHasWrongType(testCase: WrongTypeTestCase) {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)

        var dict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrCreationDate as String: creationDate,
        ]

        testCase.setWrongValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.Keys.parseAttributes(from: dict)
        }
    }

    @Test("parseAttributes ignores optional attributes with wrong types")
    func parseAttributesIgnoresOptionalAttributesWithWrongTypes() throws {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let dict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrApplicationLabel as String: "label",
            kSecAttrApplicationTag as String: "tag",
            kSecAttrLabel as String: 123,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrAccessGroup as String: 456,
            kSecAttrSynchronizable as String: "false",
        ]

        let attributes = try Keychain.Keys.parseAttributes(from: dict)

        #expect(attributes.applicationLabel == nil)
        #expect(attributes.applicationTag == nil)
        #expect(attributes.label == nil)
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.accessGroup == nil)
        #expect(attributes.synchronizable == false)
    }
}

// MARK: - Test Case Structures

extension KeysParseAttributesTests {
    struct MissingAttributeTestCase: Sendable {
        let name: String
        let secAttrKey: String

        init(_ name: String, key: CFString) {
            self.name = name
            secAttrKey = key as String
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
            secAttrKey = key as String
            self.wrongValue = wrongValue
        }

        func setWrongValue(in dict: inout [String: Any]) {
            dict[secAttrKey] = wrongValue()
        }
    }
}
