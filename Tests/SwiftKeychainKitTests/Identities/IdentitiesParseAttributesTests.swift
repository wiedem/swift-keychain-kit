@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("Identities.parseAttributes Tests")
struct IdentitiesParseAttributesTests {
    // MARK: - Successful Parsing Tests

    @Test("parseAttributes with minimal required attributes")
    func parseAttributesWithMinimalAttributes() throws {
        let issuerData = "issuer".data(using: .utf8)!
        let serialData = "serial".data(using: .utf8)!
        let subjectData = "subject".data(using: .utf8)!
        let publicKeyHashData = "publicKeyHash".data(using: .utf8)!
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)
        let persistentRef = Data([0xDE, 0xAD])

        let dict: [String: Any] = [
            kSecValuePersistentRef as String: persistentRef,
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrSubject as String: subjectData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
        ]

        let attributes = try Keychain.Identities.parseAttributes(from: dict)

        #expect(attributes.itemReference == ItemReference(persistentReferenceData: persistentRef))
        #expect(attributes.certificateType == 1)
        #expect(attributes.issuer == issuerData)
        #expect(attributes.serialNumber == serialData)
        #expect(attributes.subject == subjectData)
        #expect(attributes.publicKeyHash == publicKeyHashData)
        #expect(attributes.keyClass == .privateKey)
        #expect(attributes.algorithm == .rsa)
        #expect(attributes.keySizeInBits == 2048)
        #expect(attributes.itemAccessibility == .afterFirstUnlockThisDeviceOnly)
        #expect(attributes.accessGroup == "TEAMID.com.example.default")
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.modificationDate == modificationDate)
        #expect(attributes.certificateEncoding == nil)
        #expect(attributes.subjectKeyID == nil)
        #expect(attributes.applicationLabel == nil)
        #expect(attributes.applicationTag == nil)
        #expect(attributes.label == nil)
        #expect(attributes.synchronizable == false)
    }

    @Test("parseAttributes with all attributes")
    func parseAttributesWithAllAttributes() throws {
        let issuerData = "issuer".data(using: .utf8)!
        let serialData = "serial".data(using: .utf8)!
        let subjectData = "subject".data(using: .utf8)!
        let subjectKeyIDData = "subjectKeyID".data(using: .utf8)!
        let publicKeyHashData = "publicKeyHash".data(using: .utf8)!
        let applicationLabelData = "applicationLabel".data(using: .utf8)!
        let applicationTagData = "applicationTag".data(using: .utf8)!
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)
        let persistentRef = Data([0xDE, 0xAD])

        let dict: [String: Any] = [
            kSecValuePersistentRef as String: persistentRef,
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrCertificateEncoding as String: 3,
            kSecAttrSubject as String: subjectData,
            kSecAttrSubjectKeyID as String: subjectKeyIDData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrApplicationLabel as String: applicationLabelData,
            kSecAttrApplicationTag as String: applicationTagData,
            kSecAttrLabel as String: "Test Identity",
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecAttrAccessGroup as String: "TEAMID.com.example.shared",
            kSecAttrSynchronizable as String: true,
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
        ]

        let attributes = try Keychain.Identities.parseAttributes(from: dict)

        #expect(attributes.itemReference == ItemReference(persistentReferenceData: persistentRef))
        #expect(attributes.certificateType == 1)
        #expect(attributes.issuer == issuerData)
        #expect(attributes.serialNumber == serialData)
        #expect(attributes.certificateEncoding == 3)
        #expect(attributes.subject == subjectData)
        #expect(attributes.subjectKeyID == subjectKeyIDData)
        #expect(attributes.publicKeyHash == publicKeyHashData)
        #expect(attributes.keyClass == .publicKey)
        #expect(attributes.algorithm == .ellipticCurve)
        #expect(attributes.keySizeInBits == 256)
        #expect(attributes.applicationLabel == applicationLabelData)
        #expect(attributes.applicationTag == applicationTagData)
        #expect(attributes.label == "Test Identity")
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
        let issuerData = "issuer".data(using: .utf8)!
        let serialData = "serial".data(using: .utf8)!
        let subjectData = "subject".data(using: .utf8)!
        let publicKeyHashData = "publicKeyHash".data(using: .utf8)!
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecValuePersistentRef as String: Data([0xDE, 0xAD]),
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrSubject as String: subjectData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
        ]

        if let value = testCase.value {
            dict[kSecAttrSynchronizable as String] = value
        }

        let attributes = try Keychain.Identities.parseAttributes(from: dict)

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
            MissingAttributeTestCase(
                "keyType missing",
                key: kSecAttrKeyType
            ),
            MissingAttributeTestCase(
                "keyClass missing",
                key: kSecAttrKeyClass
            ),
            MissingAttributeTestCase(
                "keySizeInBits missing",
                key: kSecAttrKeySizeInBits
            ),
            MissingAttributeTestCase(
                "persistent reference missing",
                key: kSecValuePersistentRef
            ),
        ]
    )
    func parseAttributesReturnsNilWhenRequiredAttributeMissing(testCase: MissingAttributeTestCase) {
        let issuerData = "issuer".data(using: .utf8)!
        let serialData = "serial".data(using: .utf8)!
        let subjectData = "subject".data(using: .utf8)!
        let publicKeyHashData = "publicKeyHash".data(using: .utf8)!
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecValuePersistentRef as String: Data([0xDE, 0xAD]),
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrSubject as String: subjectData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
        ]

        testCase.removeValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.Identities.parseAttributes(from: dict)
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
            WrongTypeTestCase(
                "keyClass with wrong type",
                key: kSecAttrKeyClass,
                wrongValue: 456
            ),
        ]
    )
    func parseAttributesThrowsWhenRequiredAttributeHasWrongType(testCase: WrongTypeTestCase) {
        let issuerData = "issuer".data(using: .utf8)!
        let serialData = "serial".data(using: .utf8)!
        let subjectData = "subject".data(using: .utf8)!
        let publicKeyHashData = "publicKeyHash".data(using: .utf8)!
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        var dict: [String: Any] = [
            kSecValuePersistentRef as String: Data([0xDE, 0xAD]),
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrSubject as String: subjectData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
        ]

        testCase.setWrongValue(in: &dict)

        #expect(throws: KeychainError.attributeParsingFailed) {
            _ = try Keychain.Identities.parseAttributes(from: dict)
        }
    }

    @Test("parseAttributes ignores optional attributes with wrong types")
    func parseAttributesIgnoresOptionalAttributesWithWrongTypes() throws {
        let issuerData = "issuer".data(using: .utf8)!
        let serialData = "serial".data(using: .utf8)!
        let subjectData = "subject".data(using: .utf8)!
        let publicKeyHashData = "publicKeyHash".data(using: .utf8)!
        let creationDate = Date(timeIntervalSince1970: 1_000_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_100_000_000)

        let dict: [String: Any] = [
            kSecValuePersistentRef as String: Data([0xDE, 0xAD]),
            kSecAttrCertificateType as String: 1,
            kSecAttrIssuer as String: issuerData,
            kSecAttrSerialNumber as String: serialData,
            kSecAttrSubject as String: subjectData,
            kSecAttrPublicKeyHash as String: publicKeyHashData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: "TEAMID.com.example.default",
            kSecAttrCreationDate as String: creationDate,
            kSecAttrModificationDate as String: modificationDate,
            kSecAttrCertificateEncoding as String: "encoding", // Wrong type - should be ignored
            kSecAttrSubjectKeyID as String: 123, // Wrong type - should be ignored
            kSecAttrApplicationLabel as String: "label", // Wrong type - should be ignored
            kSecAttrApplicationTag as String: "tag", // Wrong type - should be ignored
            kSecAttrLabel as String: 456, // Wrong type - should be ignored
        ]

        let attributes = try Keychain.Identities.parseAttributes(from: dict)

        #expect(attributes.certificateType == 1)
        #expect(attributes.issuer == issuerData)
        #expect(attributes.serialNumber == serialData)
        #expect(attributes.subject == subjectData)
        #expect(attributes.publicKeyHash == publicKeyHashData)
        #expect(attributes.keyClass == .privateKey)
        #expect(attributes.algorithm == .rsa)
        #expect(attributes.keySizeInBits == 2048)
        #expect(attributes.itemAccessibility == .afterFirstUnlockThisDeviceOnly)
        #expect(attributes.accessGroup == "TEAMID.com.example.default")
        #expect(attributes.creationDate == creationDate)
        #expect(attributes.modificationDate == modificationDate)
        #expect(attributes.certificateEncoding == nil)
        #expect(attributes.subjectKeyID == nil)
        #expect(attributes.applicationLabel == nil)
        #expect(attributes.applicationTag == nil)
        #expect(attributes.label == nil)
    }
}

// MARK: - Test Case Structures

extension IdentitiesParseAttributesTests {
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
