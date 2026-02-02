private import Foundation
private import Security

extension Keychain {
    static func addItem(query: [String: Any]) throws(KeychainError) {
        let status = SecItemAdd(query as CFDictionary, nil)

        if status != errSecSuccess {
            throw KeychainError.securityError(status)
        }
    }
}
