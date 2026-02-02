public import CryptoKit
private import Foundation
public import Security

extension P256.Signing.PrivateKey: SecKeyConvertible & AsymmetricKeyTypeProviding {
    public static var asymmetricKeyType: AsymmetricKeyType {
        .ellipticCurve(.privateKey)
    }

    public func makeSecKey() throws(SecKeyConversionError) -> SecKey {
        do {
            return try .make(
                keyType: .ellipticCurve(.privateKey),
                keyData: x963Representation as CFData
            )
        } catch {
            throw SecKeyConversionError.secKeyCreationFailed(underlyingError: error)
        }
    }

    public init(secKey: SecKey) throws {
        self = try secKey.externalRepresentation().withUnsafeBytes { buffer in
            try Self(x963Representation: buffer)
        }
    }
}

extension P256.KeyAgreement.PrivateKey: SecKeyConvertible & AsymmetricKeyTypeProviding {
    public static var asymmetricKeyType: AsymmetricKeyType {
        .ellipticCurve(.privateKey)
    }

    public func makeSecKey() throws(SecKeyConversionError) -> SecKey {
        do {
            return try .make(
                keyType: .ellipticCurve(.privateKey),
                keyData: x963Representation as CFData
            )
        } catch {
            throw SecKeyConversionError.secKeyCreationFailed(underlyingError: error)
        }
    }

    public init(secKey: SecKey) throws {
        self = try secKey.externalRepresentation().withUnsafeBytes { buffer in
            try Self(x963Representation: buffer)
        }
    }
}

extension P384.Signing.PrivateKey: SecKeyConvertible & AsymmetricKeyTypeProviding {
    public static var asymmetricKeyType: AsymmetricKeyType {
        .ellipticCurve(.privateKey)
    }

    public func makeSecKey() throws(SecKeyConversionError) -> SecKey {
        do {
            return try .make(
                keyType: .ellipticCurve(.privateKey),
                keyData: x963Representation as CFData
            )
        } catch {
            throw SecKeyConversionError.secKeyCreationFailed(underlyingError: error)
        }
    }

    public init(secKey: SecKey) throws {
        self = try secKey.externalRepresentation().withUnsafeBytes { buffer in
            try Self(x963Representation: buffer)
        }
    }
}

extension P384.KeyAgreement.PrivateKey: SecKeyConvertible & AsymmetricKeyTypeProviding {
    public static var asymmetricKeyType: AsymmetricKeyType {
        .ellipticCurve(.privateKey)
    }

    public func makeSecKey() throws(SecKeyConversionError) -> SecKey {
        do {
            return try .make(
                keyType: .ellipticCurve(.privateKey),
                keyData: x963Representation as CFData
            )
        } catch {
            throw SecKeyConversionError.secKeyCreationFailed(underlyingError: error)
        }
    }

    public init(secKey: SecKey) throws {
        self = try secKey.externalRepresentation().withUnsafeBytes { buffer in
            try Self(x963Representation: buffer)
        }
    }
}

extension P521.Signing.PrivateKey: SecKeyConvertible & AsymmetricKeyTypeProviding {
    public static var asymmetricKeyType: AsymmetricKeyType {
        .ellipticCurve(.privateKey)
    }

    public func makeSecKey() throws(SecKeyConversionError) -> SecKey {
        do {
            return try .make(
                keyType: .ellipticCurve(.privateKey),
                keyData: x963Representation as CFData
            )
        } catch {
            throw SecKeyConversionError.secKeyCreationFailed(underlyingError: error)
        }
    }

    public init(secKey: SecKey) throws {
        self = try secKey.externalRepresentation().withUnsafeBytes { buffer in
            try Self(x963Representation: buffer)
        }
    }
}

extension P521.KeyAgreement.PrivateKey: SecKeyConvertible & AsymmetricKeyTypeProviding {
    public static var asymmetricKeyType: AsymmetricKeyType {
        .ellipticCurve(.privateKey)
    }

    public func makeSecKey() throws(SecKeyConversionError) -> SecKey {
        do {
            return try .make(
                keyType: .ellipticCurve(.privateKey),
                keyData: x963Representation as CFData
            )
        } catch {
            throw SecKeyConversionError.secKeyCreationFailed(underlyingError: error)
        }
    }

    public init(secKey: SecKey) throws {
        self = try secKey.externalRepresentation().withUnsafeBytes { buffer in
            try Self(x963Representation: buffer)
        }
    }
}
