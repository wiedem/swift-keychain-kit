internal import LocalAuthentication
private import Security

extension LAContext? {
    func apply(to query: inout [String: Any]) {
        Keychain.ItemAttributes.AuthenticationContext.apply(self, to: &query)
    }
}
