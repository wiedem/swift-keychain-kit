internal import Foundation

extension Keychain.Keys.ApplicationLabel {
    var dataValue: Data? {
        switch self {
        case .publicKeyHash:
            nil
        case let .data(data):
            data
        }
    }
}
