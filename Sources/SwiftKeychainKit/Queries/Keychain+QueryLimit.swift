internal import Foundation
private import Security

public extension Keychain {
    /// Specifies the maximum number of results to return from a Keychain query.
    ///
    /// Use this type with query methods to control how many items are returned.
    ///
    /// - SeeAlso: [kSecMatchLimit](https://developer.apple.com/documentation/security/ksecmatchlimit)
    enum QueryLimit: Sendable {
        /// Return all matching items without limiting the result set.
        ///
        /// Use with care: large result sets can be expensive and may trigger repeated user prompts when items require
        /// authentication.
        case unlimited

        /// Return at most the specified number of matching items.
        case count(_ count: Int)
    }
}

public extension Keychain.QueryLimit {
    /// Convenience for ``QueryLimit/count(_:)`` with a value of `1`.
    static let one: Keychain.QueryLimit = .count(1)

    /// Returns `true` when the limit requests a single item.
    var isSingle: Bool {
        guard case let .count(count) = self else {
            return false
        }
        return count == 1
    }
}

extension Keychain.QueryLimit: ExpressibleByIntegerLiteral {
    /// Creates a count-based limit from an integer literal.
    public init(integerLiteral value: Int) {
        self = .count(value)
    }
}

extension Keychain.QueryLimit: Keychain.KeychainValueProviding {
    var keychainValue: Any {
        switch self {
        case .unlimited:
            kSecMatchLimitAll
        case let .count(count):
            count == 1 ? kSecMatchLimitOne : count
        }
    }
}
