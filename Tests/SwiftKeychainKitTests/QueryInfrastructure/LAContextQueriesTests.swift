@testable import SwiftKeychainKit
import Foundation
import LocalAuthentication
import Security
import Testing

@Suite("LAContextQueriesTests")
struct LAContextQueriesTests {
    @Test("apply adds context to query")
    func applyAddsContext() {
        var query: [String: Any] = [:]
        let context: LAContext? = LAContext()
        context.apply(to: &query)
        #expect(query[kSecUseAuthenticationContext as String] as? LAContext === context)
    }

    @Test("apply does not add nil context")
    func applyDoesNotAddNilContext() {
        var query: [String: Any] = [:]
        let context: LAContext? = nil
        context.apply(to: &query)
        #expect(query.isEmpty)
    }
}
