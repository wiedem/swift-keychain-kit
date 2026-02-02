private import Darwin

/// Compares two ``SecretDataProtocol`` values for equality using constant-time comparison.
///
/// This operator uses a timing-resistant comparison algorithm for the data contents to prevent timing-based side-channel
/// attacks. However, it returns early if the lengths differ, as length is not considered secret information.
///
/// - Parameters:
///   - lhs: The first value to compare.
///   - rhs: The second value to compare.
///
/// - Returns: `true` if both values contain the same bytes; `false` otherwise.
public func == (
    lhs: borrowing some SecretDataProtocol & ~Copyable,
    rhs: borrowing some SecretDataProtocol & ~Copyable
) -> Bool {
    lhs.withUnsafeBytes { lhsBuf in
        rhs.withUnsafeBytes { rhsBuf in
            guard lhsBuf.count == rhsBuf.count else {
                return false
            }
            guard lhsBuf.count != 0 else {
                return true
            }

            let result = timingsafe_bcmp(
                lhsBuf.baseAddress!,
                rhsBuf.baseAddress!,
                lhsBuf.count
            )
            return result == 0
        }
    }
}
