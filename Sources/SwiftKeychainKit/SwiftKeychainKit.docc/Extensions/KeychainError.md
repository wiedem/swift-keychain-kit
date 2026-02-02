# ``KeychainError``


## Overview

`KeychainError` provides strongly-typed error handling for Keychain operations.
Instead of working with raw OSStatus codes, you can use pattern matching with
specific error cases.

For detailed error handling patterns and guidance on providing localized error
messages, see <doc:ErrorHandling>.

## Topics

### Error Codes

- ``KeychainError/Code``

### Common Error Patterns

- ``KeychainError/duplicateItem``
- ``KeychainError/itemNotFound``
- ``KeychainError/anyAppEntitlementsError``

### Error Information

- ``KeychainError/code``

## See Also

- <doc:ErrorHandling>
- ``Keychain``
- <doc:GettingStarted>
