# ``SwiftKeychainKit/SecretData``

## Topics

### Creating SecretData

- ``init(count:initializer:)``
- ``makeRandom(count:)``
- ``makeByCopying(from:)-(UnsafeRawBufferPointer)``
- ``makeByCopying(from:)-(ContiguousBytes)``
- ``makeByCopying(fromUnsafeData:)``
- ``makeByCopyingUTF8(fromUnsafeString:)-(String)``
- ``makeByCopyingUTF8(fromUnsafeString:)-(NSString)``
- ``makeByCopying(fromUnsafeSource:)``
- ``makeByCopyingAndWiping(from:)``
- ``makeByCopyingAndWiping(unsafeData:)``

### Accessing Data

- ``withUnsafeBytes(_:)-1qbde``
- ``withUnsafeBytes(_:)-lk68``
- ``duplicate()``

### Comparing Data

- ``==(_:_:)``

## See Also

- <doc:HandlingSecretData>
- ``SecretDataError``
- ``Keychain/GenericPassword``
- ``Keychain/InternetPassword``
