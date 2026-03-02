@testable import SwiftKeychainKit
import Foundation
import LocalAuthentication
import Security
import Testing

@Suite("ItemReference QueryBuilder Tests")
struct ItemReferenceQueryBuilderTests {
    @Test("persistentReferenceQuery with specific values sets all attributes")
    func persistentReferenceQueryWithSpecificValues() {
        let persistentRef = Data([0x01, 0x02, 0x03])
        let context = LAContext()

        let query = Keychain.persistentReferenceQuery(
            persistentRef,
            skipIfUIRequired: true,
            authenticationContext: context
        )

        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query[kSecValuePersistentRef as String] as? Data == persistentRef)
        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 4)
    }

    @Test("persistentReferenceQuery with nil values omits optional attributes")
    func persistentReferenceQueryWithNilValues() {
        let persistentRef = Data([0x04, 0x05])

        let query = Keychain.persistentReferenceQuery(
            persistentRef,
            skipIfUIRequired: false,
            authenticationContext: nil
        )

        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query[kSecValuePersistentRef as String] as? Data == persistentRef)
        #expect(query[kSecUseAuthenticationUI as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 2)
    }
}
