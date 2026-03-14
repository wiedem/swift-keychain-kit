public extension Keychain {
    /// The label value for certificates and identities.
    ///
    /// Labels are user-visible strings that help identify items in the Keychain. Use `.default` to let the Keychain
    /// automatically derive a label from the item's attributes (e.g., from the certificate's subject name), or use
    /// `.custom(_:)` to provide an explicit label.
    ///
    /// - SeeAlso: [kSecAttrLabel](https://developer.apple.com/documentation/security/ksecattrlabel)
    enum DefaultableLabel: Sendable {
        /// Let the Keychain automatically derive a label from the item's attributes.
        ///
        /// For certificates, the label is typically derived from the certificate's subject name. For identities, the label may be
        /// derived from the associated certificate.
        case `default`

        /// Use an explicit label string.
        ///
        /// - Parameter value: The custom label to apply to the item.
        case custom(String)
    }
}

extension Keychain.DefaultableLabel: ExpressibleByUnicodeScalarLiteral {
    public init(unicodeScalarLiteral value: String) {
        self = .custom(value)
    }
}

extension Keychain.DefaultableLabel: ExpressibleByExtendedGraphemeClusterLiteral {
    public init(extendedGraphemeClusterLiteral value: String) {
        self = .custom(value)
    }
}

extension Keychain.DefaultableLabel: ExpressibleByStringLiteral {
    /// Creates a custom label from a string literal.
    public init(stringLiteral value: String) {
        self = .custom(value)
    }
}

extension Keychain.DefaultableLabel {
    var value: String? {
        switch self {
        case .default:
            nil
        case let .custom(value):
            value
        }
    }
}
