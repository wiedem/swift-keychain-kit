public import Foundation

/// A type-safe reference to a Keychain item that can be stored and used to retrieve the item later.
///
/// An item reference uniquely identifies a specific Keychain item, allowing you to retrieve it without
/// reproducing the original query parameters. Item references are obtained by storing an item with one
/// of the `add()` methods that return an ``ItemReference``.
///
/// The generic parameter `ItemClass` associates the reference with a specific Keychain item type,
/// preventing accidental use of a reference for the wrong item class.
public struct ItemReference<ItemClass>: Sendable, Hashable {
    let persistentReferenceData: Data

    /// Creates an item reference from raw persistent reference data.
    ///
    /// Use this initializer to create an ``ItemReference`` from persistent reference data obtained
    /// outside of SwiftKeychainKit, for example from another Keychain framework or from direct
    /// Security framework calls using [`kSecReturnPersistentRef`](https://developer.apple.com/documentation/security/ksecreturnpersistentref).
    ///
    /// If the data does not represent a valid persistent reference, subsequent calls to
    /// `get(itemReference:)` or `attributes(itemReference:)` will return `nil`.
    ///
    /// - Parameter persistentReferenceData: The raw persistent reference data from the Keychain.
    public init(persistentReferenceData: Data) {
        self.persistentReferenceData = persistentReferenceData
    }
}

public extension ItemReference where ItemClass: ItemReferenceTaggable {
    /// The item class tag identifying the Keychain item type this reference points to.
    static var itemClass: ItemReferenceClassTag {
        ItemClass.itemReferenceClassTag
    }
}
