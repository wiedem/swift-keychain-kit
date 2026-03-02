@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("Certificates.parseAttributes Tests")
struct CertificatesParseAttributesTests {
    // MARK: - Successful Parsing Tests

    @Test("parseAttributes with minimal required attributes")
    func parseAttributesWithMinimalAttributes() throws {
        let issuerData = Data("CA Issuer".utf8)
        let serialData = Data([0xAB, 0xCD])
        let subjectData = Data("Subject".utf8)
        let publicKeyHashData = Data("Hash".utf8)
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        let dict: [String: Any] = [
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrSubject as String: subjectData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
        ]

        let attributes = try Keychain.Certificates.parseAttributes(from: dict)

        #expect(attributes.certificateType == 1)
        #expect(attributes.issuer == issuerData)
        #expect(attributes.serialNumber == serialData)
        #expect(attributes.subject == subjectData)
        #expect(attributes.publicKeyHash == publicKeyHashData)
        #expect(attributes.itemAccessibility == .afterFirstUnlockThisDeviceOnly)
        #expect(attributes.accessGroup == "TEAMID.com.example.default")
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.modificationDate == modificationDate)
        #expect(attributes.certificateEncoding == nil)
        #expect(attributes.subjectKeyID == nil)
        #expect(attributes.label == nil)
        #expect(attributes.synchronizable == false)
    }

    @Test("parseAttributes with all attributes")
    func parseAttributesWithAllAttributes() throws {
        let issuerData = Data("CA Issuer".utf8)
        let serialData = Data([0xAB, 0xCD])
        let subjectData = Data("Subject".utf8)
        let subjectKeyIDData = Data("KeyID".utf8)
        let publicKeyHashData = Data("Hash".utf8)
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        let dict: [String: Any] = [
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrCertificateEncoding as String: 3,
            kSecAttrSubject as String: subjectData,
            kSecAttrSubjectKeyID as String: subjectKeyIDData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrLabel as String: "Test Certificate",
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecAttrAccessGroup as String: "TEAMID.com.example.shared",
            kSecAttrSynchronizable as String: true,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
        ]

        let attributes = try Keychain.Certificates.parseAttributes(from: dict)

        #expect(attributes.certificateType == 1)
        #expect(attributes.issuer == issuerData)
        #expect(attributes.serialNumber == serialData)
        #expect(attributes.certificateEncoding == 3)
        #expect(attributes.subject == subjectData)
        #expect(attributes.subjectKeyID == subjectKeyIDData)
        #expect(attributes.publicKeyHash == publicKeyHashData)
        #expect(attributes.label == "Test Certificate")
        #expect(attributes.itemAccessibility == .whenUnlocked)
        #expect(attributes.accessGroup == "TEAMID.com.example.shared")
        #expect(attributes.synchronizable == true)
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.modificationDate == modificationDate)
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
        let issuerData = Data("CA Issuer".utf8)
        let serialData = Data([0xAB, 0xCD])
        let subjectData = Data("Subject".utf8)
        let publicKeyHashData = Data("Hash".utf8)
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrSubject as String: subjectData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
        ]

        if let value = testCase.value {
            dict[kSecAttrSynchronizable as String] = value
        }

        let attributes = try Keychain.Certificates.parseAttributes(from: dict)

        #expect(attributes.synchronizable == testCase.expected)
    }

    // MARK: - Failure Tests

    @Test(
        "parseAttributes returns nil when required attribute is missing",
        arguments: [
            MissingAttributeTestCase(
                "certificateType missing",
                key: kSecAttrCertificateType
            ),
            MissingAttributeTestCase(
                "issuer missing",
                key: kSecAttrIssuer
            ),
            MissingAttributeTestCase(
                "serialNumber missing",
                key: kSecAttrSerialNumber
            ),
            MissingAttributeTestCase(
                "subject missing",
                key: kSecAttrSubject
            ),
            MissingAttributeTestCase(
                "publicKeyHash missing",
                key: kSecAttrPublicKeyHash
            ),
        ]
    )
    func parseAttributesReturnsNilWhenRequiredAttributeMissing(testCase: MissingAttributeTestCase) {
        let issuerData = Data("CA Issuer".utf8)
        let serialData = Data([0xAB, 0xCD])
        let subjectData = Data("Subject".utf8)
        let publicKeyHashData = Data("Hash".utf8)
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrSubject as String: subjectData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
        ]

        // Remove the attribute to test
        testCase.removeValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.Certificates.parseAttributes(from: dict)
        }
    }

    // MARK: - Type Coercion Tests

    @Test(
        "parseAttributes throws when required attribute has wrong type",
        arguments: [
            WrongTypeTestCase(
                "certificateType with wrong type",
                key: kSecAttrCertificateType,
                wrongValue: "not a number"
            ),
            WrongTypeTestCase(
                "issuer with wrong type",
                key: kSecAttrIssuer,
                wrongValue: 123
            ),
        ]
    )
    func parseAttributesThrowsWhenRequiredAttributeHasWrongType(testCase: WrongTypeTestCase) {
        let issuerData = Data("CA Issuer".utf8)
        let serialData = Data([0xAB, 0xCD])
        let subjectData = Data("Subject".utf8)
        let publicKeyHashData = Data("Hash".utf8)
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrSubject as String: subjectData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
        ]

        testCase.setWrongValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.Certificates.parseAttributes(from: dict)
        }
    }

    @Test("parseAttributes ignores optional attributes with wrong types")
    func parseAttributesIgnoresOptionalAttributesWithWrongTypes() throws {
        let issuerData = Data("CA Issuer".utf8)
        let serialData = Data([0xAB, 0xCD])
        let subjectData = Data("Subject".utf8)
        let publicKeyHashData = Data("Hash".utf8)
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        let dict: [String: Any] = [
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrSubject as String: subjectData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrCertificateEncoding as String: "encoding", // Wrong type - should be ignored
            kSecAttrSubjectKeyID as String: 456, // Wrong type - should be ignored
            kSecAttrLabel as String: 789, // Wrong type - should be ignored
        ]

        let attributes = try Keychain.Certificates.parseAttributes(from: dict)

        #expect(attributes.certificateType == 1)
        #expect(attributes.issuer == issuerData)
        #expect(attributes.serialNumber == serialData)
        #expect(attributes.subject == subjectData)
        #expect(attributes.publicKeyHash == publicKeyHashData)
        #expect(attributes.itemAccessibility == .afterFirstUnlockThisDeviceOnly)
        #expect(attributes.accessGroup == "TEAMID.com.example.default")
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.modificationDate == modificationDate)
        #expect(attributes.certificateEncoding == nil)
        #expect(attributes.subjectKeyID == nil)
        #expect(attributes.label == nil)
    }
}

// MARK: - Test Case Structures

extension CertificatesParseAttributesTests {
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
