private import Foundation
private import Security

extension Keychain {
    static func deleteItems(query: [String: Any]) throws(KeychainError) -> Bool {
        let status = SecItemDelete(query as CFDictionary)

        if status == errSecItemNotFound {
            return false
        }

        if status != errSecSuccess {
            throw KeychainError.securityError(status)
        }

        return true
    }
}
