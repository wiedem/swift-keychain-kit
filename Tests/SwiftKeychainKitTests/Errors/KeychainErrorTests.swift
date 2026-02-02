@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("KeychainError Tests")
struct KeychainErrorTests {
    // MARK: - Error Code Tests

    @Test("Security error code")
    func securityErrorCode() {
        let error = KeychainError.securityError(errSecDuplicateItem)
        #expect(error.code == .securityError(SecurityFrameworkError(status: errSecDuplicateItem)))
    }

    // MARK: - Pattern Matching Tests

    @Test("Duplicate item pattern matches errSecDuplicateItem")
    func duplicateItemPatternMatching() {
        let error: any Error = KeychainError.securityError(errSecDuplicateItem)
        #expect(KeychainError.duplicateItem ~= error)
    }

    @Test("Duplicate item pattern does not match other security errors")
    func duplicateItemPatternDoesNotMatchOthers() {
        let error: any Error = KeychainError.securityError(errSecItemNotFound)
        #expect(!(KeychainError.duplicateItem ~= error))
    }

    @Test("Item not found pattern matches errSecItemNotFound")
    func itemNotFoundPatternMatching() {
        let error: any Error = KeychainError.securityError(errSecItemNotFound)
        #expect(KeychainError.itemNotFound ~= error)
    }

    @Test("Item not found pattern does not match other security errors")
    func itemNotFoundPatternDoesNotMatchOthers() {
        let error: any Error = KeychainError.securityError(errSecDuplicateItem)
        #expect(!(KeychainError.itemNotFound ~= error))
    }

    @Test("Pattern matching does not match non-KeychainError")
    func patternMatchingNonKeychainError() {
        struct OtherError: Error {}
        let error = OtherError()
        #expect(!(KeychainError.duplicateItem ~= error))
    }

    @Test("Pattern matching in catch clause with duplicateItem")
    func catchDuplicateItemPattern() {
        #expect(throws: KeychainError.duplicateItem) {
            throw KeychainError.duplicateItem
        }
    }

    @Test("Pattern matching in catch clause with itemNotFound")
    func catchItemNotFoundPattern() {
        #expect(throws: KeychainError.itemNotFound) {
            throw KeychainError.itemNotFound
        }
    }

    // MARK: - Equatable Tests

    @Test("Same security error codes are equal")
    func securityErrorEquality() {
        let error1 = KeychainError.securityError(errSecDuplicateItem)
        let error2 = KeychainError.securityError(errSecDuplicateItem)
        #expect(error1 == error2)
    }

    @Test("Different security error codes are not equal")
    func securityErrorInequality() {
        let error1 = KeychainError.securityError(errSecDuplicateItem)
        let error2 = KeychainError.securityError(errSecItemNotFound)
        #expect(error1 != error2)
    }

    @Test("Same non-security error codes are equal")
    func nonSecurityErrorEquality() {
        let error1 = KeychainError.invalidParameters
        let error2 = KeychainError.invalidParameters
        #expect(error1 == error2)
    }

    @Test("Different non-security error codes are not equal")
    func nonSecurityErrorInequality() {
        let error1 = KeychainError.invalidParameters
        let error2 = KeychainError.stringDecodingFailed
        #expect(error1 != error2)
    }

    @Test("Security and non-security errors are not equal")
    func securityAndNonSecurityInequality() {
        let error1 = KeychainError.securityError(errSecDuplicateItem)
        let error2 = KeychainError.invalidParameters
        #expect(error1 != error2)
    }

    // MARK: - Code Enum Tests

    @Test("Code enum security case equality")
    func codeEnumSecurityEquality() {
        let code1 = KeychainError.Code.securityError(SecurityFrameworkError(status: errSecDuplicateItem))
        let code2 = KeychainError.Code.securityError(SecurityFrameworkError(status: errSecDuplicateItem))
        #expect(code1 == code2)
    }

    @Test("Code enum security case inequality")
    func codeEnumSecurityInequality() {
        let code1 = KeychainError.Code.securityError(SecurityFrameworkError(status: errSecDuplicateItem))
        let code2 = KeychainError.Code.securityError(SecurityFrameworkError(status: errSecItemNotFound))
        #expect(code1 != code2)
    }

    @Test("Code enum non-security case equality")
    func codeEnumNonSecurityEquality() {
        let code1 = KeychainError.Code.invalidParameters
        let code2 = KeychainError.Code.invalidParameters
        #expect(code1 == code2)
    }

    // MARK: - All Error Cases Tests

    @Test("All non-security error codes create correct errors")
    func allNonSecurityErrorCodes() {
        #expect(KeychainError.invalidParameters.code == .invalidParameters)
        #expect(KeychainError.stringDecodingFailed.code == .stringDecodingFailed)
        #expect(KeychainError.dataConversionFailed.code == .dataConversionFailed)
        #expect(KeychainError.publicKeyNotSupported.code == .publicKeyNotSupported)
        #expect(KeychainError.multipleItemsFound.code == .multipleItemsFound)
        #expect(KeychainError.secureEnclaveNotAvailable.code == .secureEnclaveNotAvailable)
        #expect(KeychainError.attributeParsingFailed.code == .attributeParsingFailed)
    }

    @Test("Access control error with NSError")
    func accessControlErrorWithNSError() {
        let nsError = NSError(domain: "TestDomain", code: 42)
        let error = KeychainError.accessControlError(nsError)

        if case let .accessControlError(wrappedError) = error.code {
            #expect(wrappedError.domain == "TestDomain")
            #expect(wrappedError.code == 42)
        } else {
            Issue.record("Expected accessControlError case")
        }
    }

    // MARK: - SecurityFrameworkError Tests

    @Test("SecurityFrameworkError provides message for known status")
    func securityFrameworkErrorMessage() {
        let error = SecurityFrameworkError(status: errSecDuplicateItem)
        #expect(error.message?.isEmpty == false)
    }

    @Test("SecurityFrameworkError provides message for unknown status")
    func securityFrameworkErrorUnknownStatus() {
        let error = SecurityFrameworkError(status: -99999)
        #expect(error.message?.isEmpty == false)
    }

    // MARK: - Debug Description Tests

    @Test("Debug description for security error includes code")
    func debugDescriptionForSecurityError() {
        let error = KeychainError.securityError(errSecDuplicateItem)
        #expect(error.debugDescription.contains("\(errSecDuplicateItem)"))
    }

    @Test("Debug description for non-security errors")
    func debugDescriptionForNonSecurityErrors() {
        #expect(KeychainError.invalidParameters.debugDescription == "Invalid parameters for Keychain operation")
        #expect(KeychainError.stringDecodingFailed.debugDescription == "Failed to decode Keychain data as UTF-8 string")
        #expect(KeychainError.dataConversionFailed.debugDescription == "Failed to convert Keychain data to the requested type")
        #expect(KeychainError.publicKeyNotSupported.debugDescription == "Public keys are not supported for Keychain key storage")
        #expect(KeychainError.multipleItemsFound.debugDescription == "Multiple items found when at most one was expected")
        #expect(KeychainError.secureEnclaveNotAvailable.debugDescription == "Secure Enclave is not available on this device")
        #expect(KeychainError.attributeParsingFailed.debugDescription == "Failed to parse Keychain item attributes")
    }
}
