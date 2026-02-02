public import Foundation

public extension Keychain.Keys {
    /// The application label attribute for a key.
    ///
    /// Use this value to control how the application label is represented when storing keys in the Keychain.
    /// For public and private keys, the Keychain derives the label from the public key hash.
    ///
    /// - SeeAlso: [kSecAttrApplicationLabel](https://developer.apple.com/documentation/security/ksecattrapplicationlabel)
    enum ApplicationLabel: Sendable {
        /// Let the Keychain derive the label from the public key hash.
        case publicKeyHash

        /// Provide a custom application label value.
        ///
        /// - Parameter data: The data to store as the application label.
        case data(Data)
    }
}

public extension Keychain.Keys.ApplicationLabel {
    /// Creates an application label from the UTF-8 encoded representation of the given string.
    ///
    /// - Parameter string: The string to encode as UTF-8 data.
    static func utf8(_ string: String) -> Self {
        .data(Data(string.utf8))
    }
}
