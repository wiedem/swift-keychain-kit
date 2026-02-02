public import Foundation

public extension Keychain.QueryScope where Value == Data {
    /// Match the UTF-8 encoded representation of the given string.
    ///
    /// - Parameter string: The string to encode as UTF-8 data.
    static func utf8(_ string: String) -> Self {
        .specific(Data(string.utf8))
    }
}
