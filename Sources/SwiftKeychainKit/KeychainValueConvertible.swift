internal import Foundation

extension Keychain {
    protocol KeychainValueProviding {
        associatedtype KeychainValue

        var keychainValue: KeychainValue { get throws(KeychainError) }
    }
}

extension Keychain {
    protocol KeychainValueInitializable {
        associatedtype KeychainValue

        init?(keychainValue: KeychainValue)
    }
}

extension Keychain {
    typealias KeychainValueConvertible = KeychainValueInitializable & KeychainValueProviding
}
