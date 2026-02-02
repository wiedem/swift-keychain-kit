# ``Keychain/AccessControl``


## Usage Examples

### Simple Usage

Use static constants for common configurations:

```swift
try await Keychain.Keys.addPrivateKey(
    key,
    accessControl: .whenUnlockedThisDeviceOnly
)
```

### With Biometry

Use the initializer for custom setups with access constraints:

```swift
let accessControl = Keychain.AccessControl(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .biometryAny
)
try await Keychain.Keys.addPrivateKey(
    key,
    accessControl: accessControl
)
```
