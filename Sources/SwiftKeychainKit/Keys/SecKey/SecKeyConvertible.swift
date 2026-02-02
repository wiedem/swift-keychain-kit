public import Security

/// A type that can be initialized from a [SecKey](https://developer.apple.com/documentation/security/seckey).
///
/// Conform to this protocol to enable retrieving custom key types from the Keychain. The Keychain.Keys methods provide
/// generic overloads that return any ``SecKeyInitializable`` type.
///
/// - Throws: An error if the provided key cannot be converted into the conforming type.
public protocol SecKeyInitializable: ~Copyable {
    /// Creates an instance from a [SecKey](https://developer.apple.com/documentation/security/seckey).
    ///
    /// - Parameter secKey: The [SecKey](https://developer.apple.com/documentation/security/seckey) to initialize from.
    init(secKey: SecKey) throws
}

/// A type that can provide a [SecKey](https://developer.apple.com/documentation/security/seckey) representation.
///
/// Conform to this protocol to enable storing custom key types in the Keychain. The Keychain.Keys methods provide generic
/// overloads that accept any ``SecKeyRepresentable`` type.
public protocol SecKeyRepresentable: ~Copyable {
    /// Creates a [SecKey](https://developer.apple.com/documentation/security/seckey) representation of this key.
    ///
    /// - Returns: A [SecKey](https://developer.apple.com/documentation/security/seckey) that represents this key.
    ///
    /// - Throws: ``SecKeyConversionError`` if the representation cannot be created.
    func makeSecKey() throws(SecKeyConversionError) -> SecKey
}

/// A type that can be converted to and initialized from a
/// [SecKey](https://developer.apple.com/documentation/security/seckey).
///
/// Use this alias when you need a key type that supports round-tripping to and from
/// [SecKey](https://developer.apple.com/documentation/security/seckey).
public typealias SecKeyConvertible = SecKeyInitializable & SecKeyRepresentable
