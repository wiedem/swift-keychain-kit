public extension Keychain.InternetPassword {
    /// The authentication type used by an internet password entry.
    ///
    /// - SeeAlso: [kSecAttrAuthenticationType](https://developer.apple.com/documentation/security/ksecattrauthenticationtype)
    enum AuthenticationType: Sendable {
        /// Windows NT LAN Manager authentication.
        case ntlm

        /// Microsoft Network authentication (MSN).
        case msn

        /// Distributed password authentication.
        case dpa

        /// Remote password authentication.
        case rpa

        /// HTTP Basic authentication.
        case httpBasic

        /// HTTP Digest authentication.
        case httpDigest

        /// HTML form-based authentication.
        case htmlForm

        /// Default authentication.
        case `default`
    }
}
