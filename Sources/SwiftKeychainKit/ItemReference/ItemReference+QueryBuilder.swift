internal import Foundation
internal import LocalAuthentication
private import Security

extension Keychain {
    static func persistentReferenceQuery(
        _ persistentRef: Data,
        skipIfUIRequired: Bool,
        authenticationContext: LAContext?
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecUseDataProtectionKeychain as String: true,
            kSecValuePersistentRef as String: persistentRef,
        ]

        if skipIfUIRequired {
            Keychain.ItemAttributes.AuthenticationUI.applySkipUI(to: &query)
        }

        authenticationContext.apply(to: &query)

        return query
    }
}
