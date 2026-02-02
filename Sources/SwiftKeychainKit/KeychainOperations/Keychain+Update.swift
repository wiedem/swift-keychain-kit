private import Foundation
private import Security

extension Keychain {
    static func updateItems(
        query: [String: Any],
        attributesToUpdate: [String: Any]
    ) throws(KeychainError) {
        let status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)

        if status != errSecSuccess {
            throw KeychainError.securityError(status)
        }
    }
}
