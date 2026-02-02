/// Main namespace for all Keychain operations.
///
/// SwiftKeychainKit provides type-safe access to the Data Protection Keychain on iOS and macOS. All operations are
/// organized under this namespace.
public enum Keychain {
    /// Namespace for generic password operations.
    public enum GenericPassword {}

    /// Namespace for internet password operations.
    public enum InternetPassword {}

    /// Namespace for cryptographic key operations.
    public enum Keys {}

    /// Namespace for certificate operations.
    public enum Certificates {}

    /// Namespace for identity operations.
    public enum Identities {}

    /// Namespace for Secure Enclave key operations.
    public enum SecureEnclaveKeys {}
}
