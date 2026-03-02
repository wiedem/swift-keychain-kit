@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("GenericPassword.parseAttributes Tests")
struct GenericPasswordParseAttributesTests {
    // MARK: - Successful Parsing Tests

    @Test("parseAttributes with minimal required attributes")
    func parseAttributesWithMinimalAttributes() throws {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        let dict: [String: Any] = [
            kSecAttrAccount as String: "test@example.com",
            kSecAttrService as String: "com.example.service",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
        ]

        let attributes = try Keychain.GenericPassword.parseAttributes(from: dict)

        #expect(attributes.account == "test@example.com")
        #expect(attributes.service == "com.example.service")
        #expect(attributes.itemAccessibility == .afterFirstUnlockThisDeviceOnly)
        #expect(attributes.label == nil)
        #expect(attributes.itemDescription == nil)
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.modificationDate == modificationDate)
        #expect(attributes.accessGroup == "TEAMID.com.example.default")
        #expect(attributes.synchronizable == false)
    }

    @Test("parseAttributes with all attributes")
    func parseAttributesWithAllAttributes() throws {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        let dict: [String: Any] = [
            kSecAttrAccount as String: "user@example.com",
            kSecAttrService as String: "com.example.app",
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecAttrLabel as String: "My Password",
            kSecAttrDescription as String: "User password for example service",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.shared",
            kSecAttrSynchronizable as String: true,
        ]

        let attributes = try Keychain.GenericPassword.parseAttributes(from: dict)

        #expect(attributes.account == "user@example.com")
        #expect(attributes.service == "com.example.app")
        #expect(attributes.itemAccessibility == .whenUnlocked)
        #expect(attributes.label == "My Password")
        #expect(attributes.itemDescription == "User password for example service")
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.modificationDate == modificationDate)
        #expect(attributes.accessGroup == "TEAMID.com.example.shared")
        #expect(attributes.synchronizable == true)
    }

    @Test(
        "parseAttributes with synchronizable values",
        arguments: [
            SynchronizableTestCase(
                "true",
                value: true,
                expected: true
            ),
            SynchronizableTestCase(
                "false",
                value: false,
                expected: false
            ),
            SynchronizableTestCase(
                "missing",
                value: nil,
                expected: false
            ),
        ]
    )
    func parseAttributesWithSynchronizableValues(testCase: SynchronizableTestCase) throws {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecAttrAccount as String: "test@example.com",
            kSecAttrService as String: "com.example.service",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
        ]

        if let value = testCase.value {
            dict[kSecAttrSynchronizable as String] = value
        }

        let attributes = try Keychain.GenericPassword.parseAttributes(from: dict)

        #expect(attributes.synchronizable == testCase.expected)
    }

    // MARK: - Failure Tests

    @Test(
        "parseAttributes returns nil when required attribute is missing",
        arguments: [
            MissingAttributeTestCase(
                "account missing",
                key: kSecAttrAccount
            ),
            MissingAttributeTestCase(
                "service missing",
                key: kSecAttrService
            ),
        ]
    )
    func parseAttributesReturnsNilWhenRequiredAttributeMissing(testCase: MissingAttributeTestCase) {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecAttrAccount as String: "test@example.com",
            kSecAttrService as String: "com.example.service",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
        ]

        testCase.removeValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.GenericPassword.parseAttributes(from: dict)
        }
    }

    // MARK: - Type Coercion Tests

    @Test(
        "parseAttributes throws when required attribute has wrong type",
        arguments: [
            WrongTypeTestCase(
                "account with wrong type",
                key: kSecAttrAccount,
                wrongValue: 123
            ),
            WrongTypeTestCase(
                "service with wrong type",
                key: kSecAttrService,
                wrongValue: 456
            ),
        ]
    )
    func parseAttributesThrowsWhenRequiredAttributeHasWrongType(testCase: WrongTypeTestCase) {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecAttrAccount as String: "test@example.com",
            kSecAttrService as String: "com.example.service",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
        ]

        testCase.setWrongValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.GenericPassword.parseAttributes(from: dict)
        }
    }

    @Test("parseAttributes ignores optional attributes with wrong types")
    func parseAttributesIgnoresOptionalAttributesWithWrongTypes() throws {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        let dict: [String: Any] = [
            kSecAttrAccount as String: "test@example.com",
            kSecAttrService as String: "com.example.service",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrLabel as String: 789, // Wrong type - should be ignored
            kSecAttrDescription as String: 101_112, // Wrong type - should be ignored
        ]

        let attributes = try Keychain.GenericPassword.parseAttributes(from: dict)

        #expect(attributes.account == "test@example.com")
        #expect(attributes.service == "com.example.service")
        #expect(attributes.itemAccessibility == .afterFirstUnlockThisDeviceOnly)
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.modificationDate == modificationDate)
        #expect(attributes.accessGroup == "TEAMID.com.example.default")
        #expect(attributes.label == nil)
        #expect(attributes.itemDescription == nil)
    }
}

// MARK: - Test Case Structures

extension GenericPasswordParseAttributesTests {
    struct SynchronizableTestCase: Sendable {
        let name: String
        let value: Bool?
        let expected: Bool

        init(_ name: String, value: Bool?, expected: Bool) {
            self.name = name
            self.value = value
            self.expected = expected
        }
    }

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
