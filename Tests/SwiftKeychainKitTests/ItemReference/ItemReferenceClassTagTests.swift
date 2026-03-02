@testable import SwiftKeychainKit
import Testing

@Suite("ItemReferenceClassTag Tests")
struct ItemReferenceClassTagTests {
    @Test("Each item type maps to expected tag value")
    func expectedTagValues() {
        #expect(Keychain.GenericPassword.itemReferenceClassTag == .genericPassword)
        #expect(Keychain.InternetPassword.itemReferenceClassTag == .internetPassword)
        #expect(Keychain.Keys.itemReferenceClassTag == .keys)
        #expect(Keychain.Certificates.itemReferenceClassTag == .certificates)
        #expect(Keychain.Identities.itemReferenceClassTag == .identities)
    }
}
