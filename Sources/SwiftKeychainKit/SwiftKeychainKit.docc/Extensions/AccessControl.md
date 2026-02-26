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

### Pre-Authentication

Use ``evaluate(operation:localizedReason:context:)`` to authenticate the user before performing a Keychain operation. Pass the same context as `authenticationContext` to avoid a repeated prompt:

```swift
import LocalAuthentication

let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .biometryAny
)

let context = LAContext()
try await accessControl.evaluate(
    operation: .useItem,
    localizedReason: "Authenticate to access your credentials",
    context: context
)

let data = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    authenticationContext: context
)
```
