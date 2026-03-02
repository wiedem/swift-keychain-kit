internal import Foundation
private import Security

extension Keychain {
    static func addItemReturningPersistentReference(query: [String: Any]) throws(KeychainError) -> Data {
        var query = query
        query[kSecReturnPersistentRef as String] = true

        var result: CFTypeRef?
        let status = SecItemAdd(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            throw KeychainError.securityError(status)
        }

        guard let resultData = result as? Data else {
            throw .dataConversionFailed
        }

        return resultData
    }
}
