import LocalAuthentication
import SwiftKeychainKit
import Testing

@Suite(
    "GenericPassword.get() Skip UI (Manual)",
    .tags(.userInteractive),
    .enabled(
        if: AppEntitlementsAccessGroupProvider.isDefaultAccessGroupAvailable,
        "Default keychain access group could not be determined"
    ),
    .serialized
)
final class GenericPasswordGetSkipUITests {
    private let testAccount = "get-skip-ui-test-\(UUID().uuidString)"
    private let testService = "com.example.get-skip-ui-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    // MARK: - Test: get() with user presence requirement

    @Test("get() with skipIfUIRequired skips item requiring user presence")
    func getSkipsItemRequiringUserPresence() async throws {
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

        // get() with skipIfUIRequired: false - should show prompt
        do {
            let result = try await Keychain.GenericPassword.get(
                account: testAccount,
                service: testService,
                accessGroup: .default,
                synchronizable: false,
                skipIfUIRequired: false
            )

            // If user authenticates, we get the password
            let data = try requireUnwrapped(result)
            #expect((data == passwordCopy) == true)
        } catch KeychainError.authenticationCancelled {
            // User cancelled authentication prompt
            Issue.record("Authentication prompt was cancelled by user")
            return
        }

        // get() with skipIfUIRequired: true - should NOT show prompt, returns nil
        let skippedResult = try await Keychain.GenericPassword.get(
            account: testAccount,
            service: testService,
            accessGroup: .default,
            synchronizable: false,
            skipIfUIRequired: true
        )
        #expect((skippedResult == nil) == true)
    }

    // MARK: - Test: get() with application password - prompt on add and query

    @Test("get() with skipIfUIRequired skips item requiring application password (UI prompt on add and get)")
    func getSkipsItemRequiringApplicationPasswordWithPrompts() async throws {
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

        // get() with skipIfUIRequired: false - should show password prompt
        do {
            let result = try await Keychain.GenericPassword.get(
                account: testAccount,
                service: testService,
                accessGroup: .default,
                synchronizable: false,
                skipIfUIRequired: false
            )
            // If user enters correct password, we get the data
            let data = try requireUnwrapped(result)
            #expect((data == passwordCopy) == true)
        } catch KeychainError.authenticationCancelled {
            // User cancelled password prompt
            Issue.record("Authentication prompt was cancelled by user")
            return
        }

        // get() with skipIfUIRequired: true - should NOT show prompt, returns nil
        let skippedResult = try await Keychain.GenericPassword.get(
            account: testAccount,
            service: testService,
            accessGroup: .default,
            synchronizable: false,
            skipIfUIRequired: true
        )
        #expect((skippedResult == nil) == true)
    }

    // MARK: - Test: get() with application password - context on add, prompt on get

    @Test("get() with skipIfUIRequired skips item requiring application password (context on add, UI prompt on get)")
    func getSkipsItemRequiringApplicationPasswordWithContext() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let passwordCopy = try password.duplicate()
        let appPassword = "1" // User must enter this password at the UI prompt during get

        let addContext = LAContext()
        try addContext.setCredential(
            #require(appPassword.data(using: .utf8)),
            type: .applicationPassword
        )

        // Should NOT show password prompt during add (context provided)
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

        // get() with skipIfUIRequired: false - should show password prompt
        do {
            let result = try await Keychain.GenericPassword.get(
                account: testAccount,
                service: testService,
                accessGroup: .default,
                synchronizable: false,
                skipIfUIRequired: false
            )
            // If user enters correct password, we get the data
            let data = try requireUnwrapped(result)
            #expect((data == passwordCopy) == true)
        } catch KeychainError.authenticationCancelled {
            // User cancelled password prompt
            Issue.record("Authentication prompt was cancelled by user")
            return
        } catch KeychainError.authenticationFailed {
            // User entered invalid password
            Issue.record("Invalid authentication credentials, use '\(appPassword)' for the password prompt")
            return
        }

        // get() with skipIfUIRequired: true - should NOT show prompt, returns nil
        let skippedResult = try await Keychain.GenericPassword.get(
            account: testAccount,
            service: testService,
            accessGroup: .default,
            synchronizable: false,
            skipIfUIRequired: true
        )
        #expect((skippedResult == nil) == true)
    }

    // MARK: - Test: get() doesn't skip when credentials are in context

    @Test("get() with skipIfUIRequired does not skip when credentials are in LAContext")
    func getDontSkipWhenCredentialsProvided() async throws {
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

        // get() with skipIfUIRequired: true BUT with correct credentials
        // Item should NOT be skipped because no UI is required
        let queryContext = LAContext()
        queryContext.setCredential(appPassword, type: .applicationPassword)

        let result = try await Keychain.GenericPassword.get(
            account: testAccount,
            service: testService,
            accessGroup: .default,
            synchronizable: false,
            skipIfUIRequired: true,
            authenticationContext: queryContext
        )

        // Item should be returned, not skipped
        let data = try requireUnwrapped(result)
        #expect((data == passwordCopy) == true)
    }

    // MARK: - Test: Throws error when interaction not allowed

    @Test("get() throws interactionNotAllowed when context disallows interaction")
    func getThrowsErrorWhenInteractionNotAllowed() async throws {
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

        // get() with skipIfUIRequired: false and LAContext.interactionNotAllowed = true
        // Should throw KeychainError.interactionNotAllowed
        let getContext = LAContext()
        getContext.interactionNotAllowed = true

        await #expect(throws: KeychainError.interactionNotAllowed) {
            _ = try await Keychain.GenericPassword.get(
                account: testAccount,
                service: testService,
                accessGroup: .default,
                synchronizable: false,
                skipIfUIRequired: false,
                authenticationContext: getContext
            )
        }
    }
}

// MARK: - Helpers

private extension GenericPasswordGetSkipUITests {
    func cleanup() {
        do {
            try Keychain.GenericPassword.delete(
                account: .specific(testAccount),
                service: .specific(testService),
                accessGroup: .any,
                synchronizable: .any
            )
        } catch {
            print("Failed to clean up after test: \(error)")
        }
    }
}
