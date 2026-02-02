public import CryptoKit
public import Foundation

public extension Keychain.QueryScope where Value == Data {
    /// Match the raw bytes of the given cryptographic digest.
    ///
    /// - Parameter digest: The digest whose bytes to match.
    static func digest(_ digest: some Digest) -> Self {
        .specific(Data(digest))
    }

    /// Match the SHA-1 hash of the given data.
    ///
    /// - Parameter data: The data to hash.
    static func sha1(_ data: some DataProtocol) -> Self {
        .digest(Insecure.SHA1.hash(data: data))
    }

    /// Match the SHA-256 hash of the given data.
    ///
    /// - Parameter data: The data to hash.
    static func sha256(_ data: some DataProtocol) -> Self {
        .digest(SHA256.hash(data: data))
    }
}
