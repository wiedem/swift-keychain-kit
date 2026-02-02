public extension Keychain.InternetPassword {
    /// The network protocol used by an internet password entry.
    ///
    /// - SeeAlso: [kSecAttrProtocol](https://developer.apple.com/documentation/security/ksecattrprotocol)
    enum NetworkProtocol: Sendable {
        /// File Transfer Protocol.
        case ftp

        /// FTP over TLS/SSL (implicit).
        case ftpAccount

        /// HTTP protocol.
        case http

        /// IRC protocol.
        case irc

        /// NNTP protocol.
        case nntp

        /// POP3 protocol.
        case pop3

        /// SMTP protocol.
        case smtp

        /// SOCKS protocol.
        case socks

        /// IMAP protocol.
        case imap

        /// LDAP protocol.
        case ldap

        /// AFP over AppleTalk protocol.
        case appleTalk

        /// AFP over TCP protocol.
        case afp

        /// Telnet protocol.
        case telnet

        /// SSH protocol.
        case ssh

        /// FTP over TLS/SSL (explicit).
        case ftps

        /// HTTP over TLS/SSL.
        case https

        /// HTTP proxy.
        case httpProxy

        /// HTTPS proxy.
        case httpsProxy

        /// FTP proxy.
        case ftpProxy

        /// SMB protocol.
        case smb

        /// RTSP protocol.
        case rtsp

        /// RTSP proxy.
        case rtspProxy

        /// DAAP protocol.
        case daap

        /// Remote Apple Events protocol.
        case eppc

        /// IPP protocol.
        case ipp

        /// NNTPS protocol.
        case nntps

        /// LDAPS protocol.
        case ldaps

        /// Telnet over TLS/SSL.
        case telnetS

        /// IMAPS protocol.
        case imaps

        /// IRCS protocol.
        case ircs

        /// POP3S protocol.
        case pop3S
    }
}
