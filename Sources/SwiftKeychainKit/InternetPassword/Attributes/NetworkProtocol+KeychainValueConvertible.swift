internal import Foundation
private import Security

extension Keychain.InternetPassword.NetworkProtocol: Keychain.KeychainValueConvertible {
    var keychainValue: CFString {
        switch self {
        case .ftp:
            kSecAttrProtocolFTP
        case .ftpAccount:
            kSecAttrProtocolFTPAccount
        case .http:
            kSecAttrProtocolHTTP
        case .irc:
            kSecAttrProtocolIRC
        case .nntp:
            kSecAttrProtocolNNTP
        case .pop3:
            kSecAttrProtocolPOP3
        case .smtp:
            kSecAttrProtocolSMTP
        case .socks:
            kSecAttrProtocolSOCKS
        case .imap:
            kSecAttrProtocolIMAP
        case .ldap:
            kSecAttrProtocolLDAP
        case .appleTalk:
            kSecAttrProtocolAppleTalk
        case .afp:
            kSecAttrProtocolAFP
        case .telnet:
            kSecAttrProtocolTelnet
        case .ssh:
            kSecAttrProtocolSSH
        case .ftps:
            kSecAttrProtocolFTPS
        case .https:
            kSecAttrProtocolHTTPS
        case .httpProxy:
            kSecAttrProtocolHTTPProxy
        case .httpsProxy:
            kSecAttrProtocolHTTPSProxy
        case .ftpProxy:
            kSecAttrProtocolFTPProxy
        case .smb:
            kSecAttrProtocolSMB
        case .rtsp:
            kSecAttrProtocolRTSP
        case .rtspProxy:
            kSecAttrProtocolRTSPProxy
        case .daap:
            kSecAttrProtocolDAAP
        case .eppc:
            kSecAttrProtocolEPPC
        case .ipp:
            kSecAttrProtocolIPP
        case .nntps:
            kSecAttrProtocolNNTPS
        case .ldaps:
            kSecAttrProtocolLDAPS
        case .telnetS:
            kSecAttrProtocolTelnetS
        case .imaps:
            kSecAttrProtocolIMAPS
        case .ircs:
            kSecAttrProtocolIRCS
        case .pop3S:
            kSecAttrProtocolPOP3S
        }
    }

    init?(keychainValue: CFString) {
        switch keychainValue {
        case kSecAttrProtocolFTP:
            self = .ftp
        case kSecAttrProtocolFTPAccount:
            self = .ftpAccount
        case kSecAttrProtocolHTTP:
            self = .http
        case kSecAttrProtocolIRC:
            self = .irc
        case kSecAttrProtocolNNTP:
            self = .nntp
        case kSecAttrProtocolPOP3:
            self = .pop3
        case kSecAttrProtocolSMTP:
            self = .smtp
        case kSecAttrProtocolSOCKS:
            self = .socks
        case kSecAttrProtocolIMAP:
            self = .imap
        case kSecAttrProtocolLDAP:
            self = .ldap
        case kSecAttrProtocolAppleTalk:
            self = .appleTalk
        case kSecAttrProtocolAFP:
            self = .afp
        case kSecAttrProtocolTelnet:
            self = .telnet
        case kSecAttrProtocolSSH:
            self = .ssh
        case kSecAttrProtocolFTPS:
            self = .ftps
        case kSecAttrProtocolHTTPS:
            self = .https
        case kSecAttrProtocolHTTPProxy:
            self = .httpProxy
        case kSecAttrProtocolHTTPSProxy:
            self = .httpsProxy
        case kSecAttrProtocolFTPProxy:
            self = .ftpProxy
        case kSecAttrProtocolSMB:
            self = .smb
        case kSecAttrProtocolRTSP:
            self = .rtsp
        case kSecAttrProtocolRTSPProxy:
            self = .rtspProxy
        case kSecAttrProtocolDAAP:
            self = .daap
        case kSecAttrProtocolEPPC:
            self = .eppc
        case kSecAttrProtocolIPP:
            self = .ipp
        case kSecAttrProtocolNNTPS:
            self = .nntps
        case kSecAttrProtocolLDAPS:
            self = .ldaps
        case kSecAttrProtocolTelnetS:
            self = .telnetS
        case kSecAttrProtocolIMAPS:
            self = .imaps
        case kSecAttrProtocolIRCS:
            self = .ircs
        case kSecAttrProtocolPOP3S:
            self = .pop3S
        default:
            return nil
        }
    }
}
