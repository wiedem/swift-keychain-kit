@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("SynchronizableScope Tests")
struct SynchronizableScopeTests {
    // MARK: - ExpressibleByBooleanLiteral

    @Test("Boolean literal true creates synchronized scope")
    func trueLiteralCreatesSynchronizedScope() {
        let scope: Keychain.SynchronizableScope = true
        #expect(scope == .synchronized)
    }

    @Test("Boolean literal false creates notSynchronized scope")
    func falseLiteralCreatesNotSynchronizedScope() {
        let scope: Keychain.SynchronizableScope = false
        #expect(scope == .notSynchronized)
    }
}
