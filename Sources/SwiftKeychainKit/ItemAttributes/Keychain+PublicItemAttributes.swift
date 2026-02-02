internal import Foundation
private import Security

public extension Keychain.ItemAttributes {
    enum Account: Attribute {
        typealias ValueType = String

        static var keychainAttributeKey: CFString {
            kSecAttrAccount
        }
    }

    enum AccessGroup: Attribute {
        typealias ValueType = String

        static var keychainAttributeKey: CFString {
            kSecAttrAccessGroup
        }
    }

    enum ApplicationLabel: Attribute {
        typealias ValueType = Data

        static var keychainAttributeKey: CFString {
            kSecAttrApplicationLabel
        }
    }

    enum ApplicationTag: Attribute {
        typealias ValueType = Data

        static var keychainAttributeKey: CFString {
            kSecAttrApplicationTag
        }
    }

    enum CertificateType: Attribute {
        typealias ValueType = Int

        static var keychainAttributeKey: CFString {
            kSecAttrCertificateType
        }
    }

    enum CertificateEncoding: Attribute {
        typealias ValueType = Int

        static var keychainAttributeKey: CFString {
            kSecAttrCertificateEncoding
        }
    }

    enum Issuer: Attribute {
        typealias ValueType = Data

        static var keychainAttributeKey: CFString {
            kSecAttrIssuer
        }
    }

    enum KeySizeInBits: Attribute {
        typealias ValueType = Int

        static var keychainAttributeKey: CFString {
            kSecAttrKeySizeInBits
        }
    }

    enum Label: Attribute {
        typealias ValueType = String

        static var keychainAttributeKey: CFString {
            kSecAttrLabel
        }
    }

    enum Path: Attribute {
        typealias ValueType = String

        static var keychainAttributeKey: CFString {
            kSecAttrPath
        }
    }

    enum Port: Attribute {
        typealias ValueType = Int

        static var keychainAttributeKey: CFString {
            kSecAttrPort
        }
    }

    enum PublicKeyHash: Attribute {
        typealias ValueType = Data

        static var keychainAttributeKey: CFString {
            kSecAttrPublicKeyHash
        }
    }

    enum SecurityDomain: Attribute {
        typealias ValueType = String

        static var keychainAttributeKey: CFString {
            kSecAttrSecurityDomain
        }
    }

    enum SerialNumber: Attribute {
        typealias ValueType = Data

        static var keychainAttributeKey: CFString {
            kSecAttrSerialNumber
        }
    }

    enum Server: Attribute {
        typealias ValueType = String

        static var keychainAttributeKey: CFString {
            kSecAttrServer
        }
    }

    enum Subject: Attribute {
        typealias ValueType = Data

        static var keychainAttributeKey: CFString {
            kSecAttrSubject
        }
    }

    enum SubjectKeyID: Attribute {
        typealias ValueType = Data

        static var keychainAttributeKey: CFString {
            kSecAttrSubjectKeyID
        }
    }

    enum Service: Attribute {
        typealias ValueType = String

        static var keychainAttributeKey: CFString {
            kSecAttrService
        }
    }

    enum Synchronizable: Attribute {
        typealias ValueType = Bool

        static var keychainAttributeKey: CFString {
            kSecAttrSynchronizable
        }
    }

    enum ItemDescription: Attribute {
        typealias ValueType = String

        static var keychainAttributeKey: CFString {
            kSecAttrDescription
        }
    }

    enum ItemAccessibility: Attribute {
        typealias ValueType = CFString

        static var keychainAttributeKey: CFString {
            kSecAttrAccessible
        }
    }
}
