/// Tags used to identify the Keychain item class of a serialized ``ItemReference``.
public enum ItemReferenceClassTag: UInt8, Sendable, Codable {
    case genericPassword = 1
    case internetPassword = 2
    case keys = 3
    case certificates = 4
    case identities = 5
}

/// A type that provides an ``ItemReferenceClassTag`` for use with ``ItemReference`` serialization.
public protocol ItemReferenceTaggable {
    /// The class tag identifying the Keychain item class.
    static var itemReferenceClassTag: ItemReferenceClassTag { get }
}
