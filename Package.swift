// swift-tools-version: 6.2
import PackageDescription

let commonSwiftSettings: [SwiftSetting] = [
    .enableUpcomingFeature("InternalImportsByDefault"),
]

let package = Package(
    name: "SwiftKeychainKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "SwiftKeychainKit",
            targets: ["SwiftKeychainKit"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-collections.git", .upToNextMajor(from: "1.3.0")),
        .package(url: "https://github.com/wiedem/app-entitlements.git", .upToNextMajor(from: "2.0.0")),
    ],
    targets: [
        .target(
            name: "SwiftKeychainKit",
            dependencies: [
                .product(name: "BasicContainers", package: "swift-collections"),
                .product(name: "AppEntitlements", package: "app-entitlements"),
            ],
            resources: [
                .process("Resources/PrivacyInfo.xcprivacy"),
            ],
            swiftSettings: commonSwiftSettings
        ),
        .testTarget(
            name: "SwiftKeychainKitTests",
            dependencies: [
                "SwiftKeychainKit",
            ],
            swiftSettings: commonSwiftSettings
        ),
    ],
    swiftLanguageModes: [.v6]
)
