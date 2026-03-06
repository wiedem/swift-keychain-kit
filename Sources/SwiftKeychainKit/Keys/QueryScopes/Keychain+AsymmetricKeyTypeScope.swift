public extension Keychain {
    /// Defines the scope for querying asymmetric cryptographic keys by algorithm and optional key class.
    ///
    /// Use this type to specify which key algorithm to search for when querying the Keychain. You can optionally narrow
    /// the search to a specific key class (public or private) or search for both classes using `.any`.
    enum AsymmetricKeyTypeScope: Equatable, Sendable {
        /// Search for RSA keys with an optional key class filter.
        ///
        /// - Parameter keyClassScope: The key class to match. Defaults to `.any` to match both public and private keys.
        case rsa(AsymmetricKeyClassScope = .any)

        /// Search for Elliptic Curve keys with an optional key class filter.
        ///
        /// - Parameter keyClassScope: The key class to match. Defaults to `.any` to match both public and private keys.
        case ellipticCurve(AsymmetricKeyClassScope = .any)
    }
}

public extension Keychain.AsymmetricKeyTypeScope {
    /// Creates a scope from a concrete ``AsymmetricKeyType`` value.
    ///
    /// Use this factory method to convert an ``AsymmetricKeyType`` into a scope for query and delete operations.
    /// This is particularly useful when you have a key type stored in a variable.
    ///
    /// - Parameter keyType: The key type to create a scope from.
    /// - Returns: A scope matching the key type's algorithm and class.
    static func keyType(_ keyType: AsymmetricKeyType) -> Self {
        keyType.scope
    }

    /// Creates a scope from a type conforming to ``AsymmetricKeyTypeProviding``.
    ///
    /// Use this factory method to create a scope directly from a CryptoKit key type or any other type
    /// that declares its asymmetric key type through the ``AsymmetricKeyTypeProviding`` protocol.
    ///
    /// - Parameter keyType: The metatype whose asymmetric key type to use.
    /// - Returns: A scope matching the type's declared algorithm and class.
    static func keyType(_ keyType: (some AsymmetricKeyTypeProviding).Type) -> Self {
        Self.keyType(keyType.asymmetricKeyType)
    }
}

public extension Keychain.AsymmetricKeyTypeScope {
    /// The key class scope associated with this key type scope.
    ///
    /// Returns the ``Keychain/AsymmetricKeyClassScope`` that specifies whether to search for public keys, private keys,
    /// or both.
    var keyClassScope: Keychain.AsymmetricKeyClassScope {
        switch self {
        case let .rsa(keyClassScope),
             let .ellipticCurve(keyClassScope):
            keyClassScope
        }
    }
}
