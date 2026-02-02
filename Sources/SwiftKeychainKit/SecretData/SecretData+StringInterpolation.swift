public extension String.StringInterpolation {
    /// Redacted interpolation for move-only `SecretData`.
    ///
    /// Prints metadata only (length), never the actual bytes.
    mutating func appendInterpolation(_ value: borrowing SecretData) {
        appendLiteral("SecretData(redacted, count: \(value.count) bytes)")
    }

    /// Optional: Debug-flavored interpolation.
    mutating func appendInterpolation(debug value: borrowing SecretData) {
        appendLiteral("SecretData<redacted>(count: \(value.count) bytes)")
    }
}
