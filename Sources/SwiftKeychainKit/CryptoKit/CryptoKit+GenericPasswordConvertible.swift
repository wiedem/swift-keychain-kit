public import CryptoKit
private import Foundation
public import LocalAuthentication

extension Curve25519.KeyAgreement.PrivateKey: Keychain.GenericPasswordConvertible {
    public func genericPasswordRepresentation() throws -> any (SecretDataProtocol & ~Copyable) {
        try SecretData.makeByCopying(fromUnsafeSource: rawRepresentation)
    }

    public init(genericPasswordRepresentation data: consuming some SecretDataProtocol & ~Copyable) throws {
        self = try data.withUnsafeBytes { buffer in
            try Self(rawRepresentation: buffer)
        }
    }
}

extension Curve25519.Signing.PrivateKey: Keychain.GenericPasswordConvertible {
    public func genericPasswordRepresentation() throws -> any (SecretDataProtocol & ~Copyable) {
        try SecretData.makeByCopying(fromUnsafeSource: rawRepresentation)
    }

    public init(genericPasswordRepresentation data: consuming some SecretDataProtocol & ~Copyable) throws {
        self = try data.withUnsafeBytes { buffer in
            try Self(rawRepresentation: buffer)
        }
    }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey: Keychain.GenericPasswordConvertible {
    public func genericPasswordRepresentation() throws -> any (SecretDataProtocol & ~Copyable) {
        try SecretData.makeByCopying(fromUnsafeSource: dataRepresentation)
    }

    public init(genericPasswordRepresentation data: consuming some SecretDataProtocol & ~Copyable) throws {
        self = try data.withUnsafeBytes { buffer in
            // Note that using an unsafe Data copy is acceptable in this case since the data is an encrypted block
            // only the Secure Enclave can later use to restore the key.
            try Self(dataRepresentation: Data(buffer))
        }
    }
}

extension SecureEnclave.P256.Signing.PrivateKey: Keychain.GenericPasswordConvertible {
    public func genericPasswordRepresentation() throws -> any (SecretDataProtocol & ~Copyable) {
        try SecretData.makeByCopying(fromUnsafeSource: dataRepresentation)
    }

    public init(genericPasswordRepresentation data: consuming some SecretDataProtocol & ~Copyable) throws {
        self = try data.withUnsafeBytes { buffer in
            // Note that using an unsafe Data copy is acceptable in this case since the data is an encrypted block
            // only the Secure Enclave can later use to restore the key.
            try Self(dataRepresentation: Data(buffer))
        }
    }

    public init(
        genericPasswordRepresentation data: consuming some SecretDataProtocol & ~Copyable,
        authenticationContext: LAContext
    ) throws {
        self = try data.withUnsafeBytes { buffer in
            // Note that using an unsafe Data copy is acceptable in this case since the data is an encrypted block
            // only the Secure Enclave can later use to restore the key.
            try Self(
                dataRepresentation: Data(buffer),
                authenticationContext: authenticationContext
            )
        }
    }
}
