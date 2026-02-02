// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftKeychainKit",
    defaultLocalization: "en",
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
    targets: [
        .target(
            name: "SwiftKeychainKit",
            dependencies: [],
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "SwiftKeychainKitTests",
            dependencies: ["SwiftKeychainKit"]
        ),
    ]
)
