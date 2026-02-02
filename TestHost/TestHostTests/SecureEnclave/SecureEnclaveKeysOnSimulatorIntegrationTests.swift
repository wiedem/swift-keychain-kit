import Foundation
import SwiftKeychainKit
import Testing

#if targetEnvironment(simulator)
private let isRunningOnSimulator = true
#else
private let isRunningOnSimulator = false
#endif

@Suite(
    "Secure Enclave Keys Integration Tests",
    .enabled(if: isRunningOnSimulator),
    .tags(.secureEnclave)
)
final class SecureEnclaveKeysOnSimulatorIntegrationTests {
    private let keychainApplicationTag = "SecureEnclaveKeysOnSimulatorIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!

    @Test("Generate throws secureEnclaveNotAvailable on simulator")
    func generateThrowsOnSimulator() async throws {
        await #expect(throws: KeychainError.secureEnclaveNotAvailable) {
            try await Keychain.SecureEnclaveKeys.generate(
                applicationTag: keychainApplicationTag
            )
        }
    }
}
