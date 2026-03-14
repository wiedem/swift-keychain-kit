import BasicContainers
import LocalAuthentication
import SwiftKeychainKit
import Testing

@Suite(
    "GenericPassword.query() Skip UI (Manual)",
    .tags(.userInteractive),
    .serialized
)
final class GenericPasswordQuerySkipUITests {
    private let testAccount = "skip-ui-test-\(UUID().uuidString)"
    private let testService = "com.example.skip-ui-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    // MARK: - Test: Skip item with user presence requirement

    @Test("query() with skipItemsIfUIRequired skips item requiring user presence")
    func skipItemRequiringUserPresence() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let passwordCopy = try password.duplicate()

        // Add item with user presence requirement
        try await Keychain.GenericPassword.add(
            password,
            account: testAccount,
            service: testService,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .userPresence
            )
        )

        // Query with skipItemsIfUIRequired: false - should show biometry prompt
        do {
            var results = try await Keychain.GenericPassword.query(
                account: .specific(testAccount),
                service: .specific(testService),
                skipItemsIfUIRequired: false
            )
            // If user authenticates, we get the password
            let firstResult = results.remove(at: 0)
            #expect((firstResult == passwordCopy) == true)
        } catch KeychainError.authenticationCancelled {
            // User cancelled biometry prompt
            Issue.record("Authentication prompt was cancelled by user")
            return
        }

        // Query with skipItemsIfUIRequired: true - should NOT show prompt, returns empty result
        let skippedResults = try await Keychain.GenericPassword.query(
            account: .specific(testAccount),
            service: .specific(testService),
            skipItemsIfUIRequired: true
        )
        #expect(skippedResults.isEmpty == true)
    }

    // MARK: - Test: Skip item with application password requirement showing prompt on add and query

    @Test("query() with skipItemsIfUIRequired skips item requiring application password (UI prompt on add and query)")
    func skipItemRequiringApplicationPasswordOnAddAndQuery() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let passwordCopy = try password.duplicate()

        // Should show password prompt to set the application password
        try await Keychain.GenericPassword.add(
            password,
            account: testAccount,
            service: testService,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            )
        )

        // Query with skipItemsIfUIRequired: false - should show password prompt
        do {
            var results = try await Keychain.GenericPassword.query(
                account: .specific(testAccount),
                service: .specific(testService),
                skipItemsIfUIRequired: false
            )
            // If user enters correct password, we get the data
            let firstResult = results.remove(at: 0)
            #expect((firstResult == passwordCopy) == true)
        } catch KeychainError.authenticationCancelled {
            // User cancelled password prompt
            Issue.record("Authentication prompt was cancelled by user")
            return
        }

        // Query with skipItemsIfUIRequired: true - should NOT show prompt, returns nil
        let skippedResults = try await Keychain.GenericPassword.query(
            account: .specific(testAccount),
            service: .specific(testService),
            skipItemsIfUIRequired: true
        )
        #expect(skippedResults.isEmpty == true)
    }

    // MARK: - Test: Skip item with application password requirement, providing password with LAContext to add, showing prompt on query

    @Test("query() with skipItemsIfUIRequired skips item requiring application password (context on add, UI prompt on query)")
    func skipItemRequiringApplicationPasswordOnQuery() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let passwordCopy = try password.duplicate()
        let appPassword = "1" // User must enter this password at the UI prompt during query

        let addContext = LAContext()
        try addContext.setCredential(
            #require(appPassword.data(using: .utf8)),
            type: .applicationPassword
        )

        // Should not show password prompt
        try await Keychain.GenericPassword.add(
            password,
            account: testAccount,
            service: testService,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            ),
            authenticationContext: addContext
        )

        // Query with skipItemsIfUIRequired: false - should show password prompt
        do {
            var results = try await Keychain.GenericPassword.query(
                account: .specific(testAccount),
                service: .specific(testService),
                skipItemsIfUIRequired: false
            )
            // If user enters correct password, we get the data
            let firstResult = results.remove(at: 0)
            #expect((firstResult == passwordCopy) == true)
        } catch KeychainError.authenticationCancelled {
            // User cancelled password prompt
            Issue.record("Authentication prompt was cancelled by user")
            return
        } catch KeychainError.authenticationFailed {
            // User entered invalid password prompt
            Issue.record("Invalid authentication credentials, use '\(appPassword)' for the password prompt")
            return
        }

        // Query with skipItemsIfUIRequired: true - should NOT show prompt, returns nil
        let skippedResults = try await Keychain.GenericPassword.query(
            account: .specific(testAccount),
            service: .specific(testService),
            skipItemsIfUIRequired: true
        )
        #expect(skippedResults.isEmpty == true)
    }

    // MARK: - Test: Don't skip when credentials are in context

    @Test("query() with skipItemsIfUIRequired does not skip when credentials are in LAContext")
    func dontSkipWhenCredentialsProvided() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let passwordCopy = try password.duplicate()
        let appPassword = "app-password-123".data(using: .utf8)!

        // Add item with application password requirement
        let addContext = LAContext()
        addContext.setCredential(appPassword, type: .applicationPassword)

        try await Keychain.GenericPassword.add(
            password,
            account: testAccount,
            service: testService,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            ),
            authenticationContext: addContext
        )

        // Query with skipIfUIRequired: true BUT with correct credentials
        // Item should NOT be skipped because no UI is required
        let queryContext = LAContext()
        queryContext.setCredential(appPassword, type: .applicationPassword)

        var results = try await Keychain.GenericPassword.query(
            account: .specific(testAccount),
            service: .specific(testService),
            skipItemsIfUIRequired: true,
            authenticationContext: queryContext
        )

        // Item should be returned, not skipped
        let firstResult = results.remove(at: 0)
        #expect((firstResult == passwordCopy) == true)
    }

    // MARK: - Test: Throws error when interaction not allowed

    @Test("query() throws interactionNotAllowed when context disallows interaction")
    func queryThrowsErrorWhenInteractionNotAllowed() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let appPassword = "app-password-123".data(using: .utf8)!

        // Add item with application password requirement
        let addContext = LAContext()
        addContext.setCredential(appPassword, type: .applicationPassword)

        try await Keychain.GenericPassword.add(
            password,
            account: testAccount,
            service: testService,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            ),
            authenticationContext: addContext
        )

        // query() with skipItemsIfUIRequired: false and LAContext.interactionNotAllowed = true
        // Should throw KeychainError.interactionNotAllowed
        let queryContext = LAContext()
        queryContext.interactionNotAllowed = true

        await #expect(throws: KeychainError.interactionNotAllowed) {
            _ = try await Keychain.GenericPassword.query(
                account: .specific(testAccount),
                service: .specific(testService),
                skipItemsIfUIRequired: false,
                authenticationContext: queryContext
            )
        }
    }

    // MARK: - Test: Query multiple items with mixed authentication requirements

    @Test("query() with skipItemsIfUIRequired filters out items requiring UI")
    func queryMultipleItemsWithMixedRequirements() async throws {
        let password1 = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password-no-auth")
        let password1Copy = try password1.duplicate()
        let passwordCopy = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password-with-user-presence")
        let account1 = "account-1-\(UUID().uuidString)"
        let account2 = "account-2-\(UUID().uuidString)"

        defer {
            _ = try? Keychain.GenericPassword.delete(
                account: .specific(account1),
                service: .specific(testService),
                accessGroup: .any,
                synchronizable: .any
            )
            _ = try? Keychain.GenericPassword.delete(
                account: .specific(account2),
                service: .specific(testService),
                accessGroup: .any,
                synchronizable: .any
            )
        }

        // Add item without authentication requirement
        try await Keychain.GenericPassword.add(
            password1,
            account: account1,
            service: testService
        )

        // Add item with user presence requirement
        try await Keychain.GenericPassword.add(
            passwordCopy,
            account: account2,
            service: testService,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .userPresence
            )
        )

        // Query with skipItemsIfUIRequired: true
        // Should only return the first item (no auth requirement)
        var results = try await Keychain.GenericPassword.query(
            service: .specific(testService),
            skipItemsIfUIRequired: true,
            limit: .count(2)
        )

        // Should get exactly one result (the item without auth requirement)
        #expect(results.count == 1)
        let firstResult = results.remove(at: 0)
        #expect((firstResult == password1Copy) == true)
    }
}

// MARK: - Helpers

private extension GenericPasswordQuerySkipUITests {
    func cleanup() {
        do {
            try Keychain.GenericPassword.delete(
                account: .specific(testAccount),
                service: .specific(testService),
                accessGroup: .any,
                synchronizable: .any
            )
        } catch {
            print("Failed to clean up generic password after test: \(error)")
        }
    }
}
