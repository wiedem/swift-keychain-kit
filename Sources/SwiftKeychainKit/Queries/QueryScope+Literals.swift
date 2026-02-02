public import Foundation

// MARK: - ExpressibleByStringLiteral

extension Keychain.QueryScope: ExpressibleByUnicodeScalarLiteral where Value == String {
    public init(unicodeScalarLiteral value: String) {
        self = .specific(value)
    }
}

extension Keychain.QueryScope: ExpressibleByExtendedGraphemeClusterLiteral where Value == String {
    public init(extendedGraphemeClusterLiteral value: String) {
        self = .specific(value)
    }
}

extension Keychain.QueryScope: ExpressibleByStringLiteral where Value == String {
    public init(stringLiteral value: String) {
        self = .specific(value)
    }
}

// MARK: - ExpressibleByIntegerLiteral

extension Keychain.QueryScope: ExpressibleByIntegerLiteral where Value == Int {
    public init(integerLiteral value: Int) {
        self = .specific(value)
    }
}

// MARK: - ExpressibleByArrayLiteral

extension Keychain.QueryScope: ExpressibleByArrayLiteral where Value == Data {
    public init(arrayLiteral elements: UInt8...) {
        self = .specific(Data(elements))
    }
}
