@testable import SwiftKeychainKit
import Foundation
import Testing

@Test("Temporary: SecretData parallel use should be rejected")
func secretDataParallelUseIsRejected() async throws {
    let secret = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
    await bad(secret: secret)
}

// Temporary test scaffolding for experimenting with move-only + concurrency behavior.
// Enable the block below when you want to experiment with compile-time failures.
private final class SecretDataBox: Sendable {
    let secret: SecretData

    init(_ secret: consuming SecretData) {
        self.secret = secret
    }
}

private func bad(secret: consuming SecretData) async {
    let box = SecretDataBox(secret)
    let handle = Task.detached {
        _ = box.secret.withUnsafeBytes { $0.count }
    }

    _ = box.secret.withUnsafeBytes { $0.count }

    _ = await handle.value
}
