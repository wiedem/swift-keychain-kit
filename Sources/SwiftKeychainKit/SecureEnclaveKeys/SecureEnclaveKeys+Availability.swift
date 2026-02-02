#if !targetEnvironment(simulator)
private import CryptoKit
#endif

public extension Keychain.SecureEnclaveKeys {
    /// Indicates whether the Secure Enclave is available on the current device.
    ///
    /// The Secure Enclave is available on:
    /// - iPhone 5s and later
    /// - iPad Air and later
    /// - iPad mini 2 and later
    /// - iPad Pro (all models)
    /// - Mac computers with Apple silicon or the T2 chip
    ///
    /// The Secure Enclave is not available in the iOS or macOS simulators.
    ///
    /// - Returns: `true` if the Secure Enclave is available, `false` otherwise.
    static var isAvailable: Bool {
        #if targetEnvironment(simulator)
        false
        #else
        SecureEnclave.isAvailable
        #endif
    }
}
