@testable import SwiftKeychainKit
import Foundation
import Testing

@Suite("ApplicationLabelTests")
struct ApplicationLabelTests {
    @Test("utf8 creates data label from string")
    func utf8CreatesDataLabelFromString() {
        let label = Keychain.Keys.ApplicationLabel.utf8("label-value")

        switch label {
        case .publicKeyHash:
            Issue.record("Expected .data application label, got .publicKeyHash")
        case let .data(data):
            #expect(data == Data("label-value".utf8))
        }
    }
}
