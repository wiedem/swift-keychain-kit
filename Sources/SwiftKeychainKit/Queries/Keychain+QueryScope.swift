public extension Keychain {
    /// A query scope that specifies whether to match a specific value or any value.
    ///
    /// Use this type to control matching behavior in operations that support filtering by optional attributes. The `.any` case
    /// matches entries regardless of the attribute's value, while `.specific` matches only entries with the exact value
    /// provided.
    enum QueryScope<Value, Attribute> {
        /// Match any value for this attribute.
        case any

        /// Match only the specific value provided.
        case specific(Value)
    }
}

extension Keychain.QueryScope: Sendable where Value: Sendable {}
extension Keychain.QueryScope: Equatable where Value: Equatable {}

extension Keychain.QueryScope {
    var value: Value? {
        switch self {
        case .any:
            nil
        case let .specific(value):
            value
        }
    }
}

extension Keychain.QueryScope where Attribute: Keychain.ItemAttributes.Attribute, Value == Attribute.ValueType {
    func apply(to query: inout [String: Any]) {
        Attribute.apply(value, to: &query)
    }
}

extension Keychain.QueryScope where Attribute: Keychain.ItemAttributes.Attribute, Value: Keychain.KeychainValueProviding, Attribute.ValueType == Value.KeychainValue {
    func apply(to query: inout [String: Any]) throws(KeychainError) {
        try Attribute.apply(value, to: &query)
    }
}
