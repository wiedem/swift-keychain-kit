internal import Foundation
private import Security

extension Keychain.InternetPassword.AuthenticationType: Keychain.KeychainValueConvertible {
    var keychainValue: CFString {
        switch self {
        case .ntlm:
            kSecAttrAuthenticationTypeNTLM
        case .msn:
            kSecAttrAuthenticationTypeMSN
        case .dpa:
            kSecAttrAuthenticationTypeDPA
        case .rpa:
            kSecAttrAuthenticationTypeRPA
        case .httpBasic:
            kSecAttrAuthenticationTypeHTTPBasic
        case .httpDigest:
            kSecAttrAuthenticationTypeHTTPDigest
        case .htmlForm:
            kSecAttrAuthenticationTypeHTMLForm
        case .default:
            kSecAttrAuthenticationTypeDefault
        }
    }

    init?(keychainValue: CFString) {
        switch keychainValue {
        case kSecAttrAuthenticationTypeNTLM:
            self = .ntlm
        case kSecAttrAuthenticationTypeMSN:
            self = .msn
        case kSecAttrAuthenticationTypeDPA:
            self = .dpa
        case kSecAttrAuthenticationTypeRPA:
            self = .rpa
        case kSecAttrAuthenticationTypeHTTPBasic:
            self = .httpBasic
        case kSecAttrAuthenticationTypeHTTPDigest:
            self = .httpDigest
        case kSecAttrAuthenticationTypeHTMLForm:
            self = .htmlForm
        case kSecAttrAuthenticationTypeDefault:
            self = .default
        default:
            return nil
        }
    }
}
