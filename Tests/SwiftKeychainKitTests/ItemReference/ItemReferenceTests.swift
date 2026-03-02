@testable import SwiftKeychainKit
import Foundation
import Testing

@Suite("ItemReference Tests")
struct ItemReferenceTests {
    // MARK: - Codable Roundtrip

    @Test("Codable encode/decode roundtrip preserves reference")
    func codableRoundtrip() throws {
        let referenceData = Data([0xCA, 0xFE, 0xBA, 0xBE])
        let reference = ItemReference<Keychain.Keys>(persistentReferenceData: referenceData)

        let encoded = try JSONEncoder().encode(reference)
        let decoded = try JSONDecoder().decode(ItemReference<Keychain.Keys>.self, from: encoded)

        #expect(decoded == reference)
        #expect(decoded.persistentReferenceData == referenceData)
    }

    @Test("Codable roundtrip works for all item types")
    func codableRoundtripAllTypes() throws {
        let referenceData = Data([0x42])
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let genericPassword = ItemReference<Keychain.GenericPassword>(persistentReferenceData: referenceData)
        let encoded = try encoder.encode(genericPassword)
        #expect(try decoder.decode(ItemReference<Keychain.GenericPassword>.self, from: encoded) == genericPassword)

        let internetPassword = ItemReference<Keychain.InternetPassword>(persistentReferenceData: referenceData)
        let encoded2 = try encoder.encode(internetPassword)
        #expect(try decoder.decode(ItemReference<Keychain.InternetPassword>.self, from: encoded2) == internetPassword)

        let key = ItemReference<Keychain.Keys>(persistentReferenceData: referenceData)
        let encoded3 = try encoder.encode(key)
        #expect(try decoder.decode(ItemReference<Keychain.Keys>.self, from: encoded3) == key)

        let certificate = ItemReference<Keychain.Certificates>(persistentReferenceData: referenceData)
        let encoded4 = try encoder.encode(certificate)
        #expect(try decoder.decode(ItemReference<Keychain.Certificates>.self, from: encoded4) == certificate)

        let identity = ItemReference<Keychain.Identities>(persistentReferenceData: referenceData)
        let encoded5 = try encoder.encode(identity)
        #expect(try decoder.decode(ItemReference<Keychain.Identities>.self, from: encoded5) == identity)
    }

    // MARK: - Cross-Type Safety

    @Test("Decoding with wrong item class throws DecodingError")
    func crossTypeDecodingFails() throws {
        let genericPassword = ItemReference<Keychain.GenericPassword>(persistentReferenceData: Data([0xFF]))
        let encoded = try JSONEncoder().encode(genericPassword)

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(ItemReference<Keychain.InternetPassword>.self, from: encoded)
        }
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(ItemReference<Keychain.Keys>.self, from: encoded)
        }
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(ItemReference<Keychain.Certificates>.self, from: encoded)
        }
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(ItemReference<Keychain.Identities>.self, from: encoded)
        }
    }

    // MARK: - Equatable / Hashable

    @Test("References with same data are equal")
    func equalReferences() {
        let referenceData = Data([0x01, 0x02, 0x03])
        let reference1 = ItemReference<Keychain.GenericPassword>(persistentReferenceData: referenceData)
        let reference2 = ItemReference<Keychain.GenericPassword>(persistentReferenceData: referenceData)

        #expect(reference1 == reference2)
        #expect(reference1.hashValue == reference2.hashValue)
    }

    @Test("References with different data are not equal")
    func unequalReferences() {
        let reference1 = ItemReference<Keychain.GenericPassword>(persistentReferenceData: Data([0x01]))
        let reference2 = ItemReference<Keychain.GenericPassword>(persistentReferenceData: Data([0x02]))

        #expect(reference1 != reference2)
    }

    @Test("References can be used as Dictionary keys")
    func referencesAsDictionaryKeys() {
        let reference1 = ItemReference<Keychain.GenericPassword>(persistentReferenceData: Data([0x01]))
        let reference2 = ItemReference<Keychain.GenericPassword>(persistentReferenceData: Data([0x02]))

        var dictionary: [ItemReference<Keychain.GenericPassword>: String] = [:]
        dictionary[reference1] = "first"
        dictionary[reference2] = "second"

        #expect(dictionary[reference1] == "first")
        #expect(dictionary[reference2] == "second")
        #expect(dictionary.count == 2)
    }
}
