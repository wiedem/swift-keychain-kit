public import Foundation
public import Security

public extension Keychain.Keys.ApplicationLabel {
    /// Resolves the application label of a [SecKey](https://developer.apple.com/documentation/security/seckey).
    ///
    /// For public and private keys, the application label is the hash of the public key as computed by the Security
    /// framework. This is the same value that the Keychain computes automatically when you store a key with
    /// ``publicKeyHash``.
    ///
    /// This method does not access the Keychain. It reads the attribute directly from the in-memory key representation.
    ///
    /// - Parameter key: The [SecKey](https://developer.apple.com/documentation/security/seckey) to read the application
    ///   label from.
    ///
    /// - Returns: The application label data, or `nil` if the attribute is not available.
    static func resolve(for key: SecKey) -> Data? {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any] else {
            return nil
        }
        return attributes[kSecAttrApplicationLabel as String] as? Data
    }

    /// Resolves the application label of a key conforming to ``SecKeyRepresentable``.
    ///
    /// For public and private keys, the application label is the hash of the public key as computed by the Security
    /// framework. This is the same value that the Keychain computes automatically when you store a key with
    /// ``publicKeyHash``.
    ///
    /// This method does not access the Keychain. It converts the key to a
    /// [SecKey](https://developer.apple.com/documentation/security/seckey) and reads the attribute from the in-memory
    /// key representation.
    ///
    /// - Parameter key: A key conforming to ``SecKeyRepresentable``.
    ///
    /// - Returns: The application label data, or `nil` if the attribute is not available.
    ///
    /// - Throws: ``SecKeyConversionError`` if the key cannot be converted to a
    ///   [SecKey](https://developer.apple.com/documentation/security/seckey).
    static func resolve(for key: some SecKeyRepresentable) throws(SecKeyConversionError) -> Data? {
        try resolve(for: key.makeSecKey())
    }
}
