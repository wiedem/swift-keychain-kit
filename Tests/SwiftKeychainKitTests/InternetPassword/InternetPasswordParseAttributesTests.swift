@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("InternetPassword.parseAttributes Tests")
struct InternetPasswordParseAttributesTests {
    // MARK: - Successful Parsing Tests

    @Test("parseAttributes with minimal required attributes")
    func parseAttributesWithMinimalAttributes() throws {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        let dict: [String: Any] = [
            kSecAttrAccount as String: "test@example.com",
            kSecAttrServer as String: "example.com",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
        ]

        let attributes = try Keychain.InternetPassword.parseAttributes(from: dict)

        #expect(attributes.account == "test@example.com")
        #expect(attributes.server == "example.com")
        #expect(attributes.itemAccessibility == .afterFirstUnlockThisDeviceOnly)
        #expect(attributes.networkProtocol == nil)
        #expect(attributes.authenticationType == nil)
        #expect(attributes.port == 0)
        #expect(attributes.path == "")
        #expect(attributes.securityDomain == "")
        #expect(attributes.label == nil)
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
            kSecAttrServer as String: "example.com",
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecAttrProtocol as String: kSecAttrProtocolHTTPS,
            kSecAttrAuthenticationType as String: kSecAttrAuthenticationTypeHTTPBasic,
            kSecAttrPort as String: 443,
            kSecAttrPath as String: "/login",
            kSecAttrSecurityDomain as String: "example.com",
            kSecAttrLabel as String: "My Internet Password",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.shared",
            kSecAttrSynchronizable as String: true,
        ]

        let attributes = try Keychain.InternetPassword.parseAttributes(from: dict)

        #expect(attributes.account == "user@example.com")
        #expect(attributes.server == "example.com")
        #expect(attributes.itemAccessibility == .whenUnlocked)
        #expect(attributes.networkProtocol == .https)
        #expect(attributes.authenticationType == .httpBasic)
        #expect(attributes.port == 443)
        #expect(attributes.path == "/login")
        #expect(attributes.securityDomain == "example.com")
        #expect(attributes.label == "My Internet Password")
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
            kSecAttrServer as String: "example.com",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
        ]

        if let value = testCase.value {
            dict[kSecAttrSynchronizable as String] = value
        }

        let attributes = try Keychain.InternetPassword.parseAttributes(from: dict)
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
                "server missing",
                key: kSecAttrServer
            ),
        ]
    )
    func parseAttributesReturnsNilWhenRequiredAttributeMissing(testCase: MissingAttributeTestCase) {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecAttrAccount as String: "test@example.com",
            kSecAttrServer as String: "example.com",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
        ]

        testCase.removeValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.InternetPassword.parseAttributes(from: dict)
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
                "server with wrong type",
                key: kSecAttrServer,
                wrongValue: 456
            ),
        ]
    )
    func parseAttributesThrowsWhenRequiredAttributeHasWrongType(testCase: WrongTypeTestCase) {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecAttrAccount as String: "test@example.com",
            kSecAttrServer as String: "example.com",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
        ]

        testCase.setWrongValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.InternetPassword.parseAttributes(from: dict)
        }
    }

    @Test("parseAttributes ignores optional attributes with wrong types")
    func parseAttributesIgnoresOptionalAttributesWithWrongTypes() throws {
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        let dict: [String: Any] = [
            kSecAttrAccount as String: "test@example.com",
            kSecAttrServer as String: "example.com",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrProtocol as String: 1, // Wrong type - should be ignored
            kSecAttrAuthenticationType as String: 2, // Wrong type - should be ignored
            kSecAttrPort as String: "443", // Wrong type - should be ignored
            kSecAttrPath as String: 123, // Wrong type - should be ignored
            kSecAttrSecurityDomain as String: 456, // Wrong type - should be ignored
            kSecAttrLabel as String: 789, // Wrong type - should be ignored
        ]

        let attributes = try Keychain.InternetPassword.parseAttributes(from: dict)

        #expect(attributes.account == "test@example.com")
        #expect(attributes.server == "example.com")
        #expect(attributes.itemAccessibility == .afterFirstUnlockThisDeviceOnly)
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.modificationDate == modificationDate)
        #expect(attributes.accessGroup == "TEAMID.com.example.default")
        #expect(attributes.networkProtocol == nil)
        #expect(attributes.authenticationType == nil)
        #expect(attributes.port == 0)
        #expect(attributes.path == "")
        #expect(attributes.securityDomain == "")
        #expect(attributes.label == nil)
    }
}

// MARK: - Test Case Structures

extension InternetPasswordParseAttributesTests {
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
