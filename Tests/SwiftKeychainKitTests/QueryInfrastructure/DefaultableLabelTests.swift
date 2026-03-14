@testable import SwiftKeychainKit
import Testing

@Suite("DefaultableLabel Tests")
struct DefaultableLabelTests {
    // MARK: - ExpressibleByStringLiteral

    @Test("String literal creates custom label")
    func stringLiteralCreatesCustomLabel() {
        let label: Keychain.DefaultableLabel = "My Certificate"
        #expect(label.value == "My Certificate")
    }

    @Test("String literal value matches .custom value")
    func stringLiteralMatchesCustomValue() {
        let literal: Keychain.DefaultableLabel = "Root CA"
        let explicit: Keychain.DefaultableLabel = .custom("Root CA")
        #expect(literal.value == explicit.value)
    }
}
