internal import Foundation
internal import Security

extension SecKey {
    static func make(
        keyType: AsymmetricKeyType,
        keyData: CFData
    ) throws -> SecKey {
        var attributes = [String: Any]()
        keyType.keychainQueryScope.apply(to: &attributes)

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(keyData, attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as any Error
        }
        return secKey
    }

    func externalRepresentation() throws -> SecretData {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(self, &error) else {
            throw error!.takeRetainedValue() as any Error
        }
        return try SecretData.makeByCopying(fromUnsafeData: data)
    }
}
