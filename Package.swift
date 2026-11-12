// swift-tools-version: 5.9
// SLMtune for macOS. `scripts/build-app.sh` builds the targets and assembles SLMtune.app (with the cores) and SLMtune.dmg.
// On Linux only the shared logic and its tests build (scripts/linux-check.sh), the app needs AppKit/SwiftUI.
import PackageDescription

// The app reaches internal types of SLMShared with `@testable import`, so the library is always built with testing on.
let shared: [SwiftSetting] = [.unsafeFlags(["-enable-testing"])]

var targets: [Target] = [
    .target(name: "SLMShared", path: "Sources/SLMShared", swiftSettings: shared),
    .executableTarget(name: "ConfigDump", dependencies: ["SLMShared"], path: "tools/ConfigDump"),
    .testTarget(name: "SLMSharedTests", dependencies: ["SLMShared"], path: "Tests/SLMSharedTests"),
]
var dependencies: [Package.Dependency] = []

#if os(macOS)
dependencies += [
    // SSH for «Мои серверы»
    .package(url: "https://github.com/orlandos-nl/Citadel", from: "0.12.0"),
    // Self-signed certificates for Hysteria2 / TrustTunnel on your own server
    .package(url: "https://github.com/apple/swift-certificates", from: "1.21.0"),
    .package(url: "https://github.com/apple/swift-crypto", from: "3.0.0"),
    .package(url: "https://github.com/apple/swift-asn1", from: "1.0.0"),
    // swift-collections 1.6 needs a newer Swift than the Intel CI runners' Xcode 16 (Swift 6.1).
    .package(url: "https://github.com/apple/swift-collections", "1.1.0"..<"1.6.0"),
]
targets += [
    .executableTarget(
        name: "SLMtune",
        dependencies: [
            "SLMShared",
            .product(name: "Citadel", package: "Citadel"),
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ],
        path: "Sources/SLMtune"),
    // Root helper (LaunchDaemon): TUN, the pf kill switch, the system proxy. Installed once with the admin password.
    .executableTarget(name: "SLMtuneHelper", dependencies: ["SLMShared"], path: "Sources/SLMtuneHelper"),
]
#endif

let package = Package(
    name: "SLMtune",
    platforms: [.macOS(.v13)],
    dependencies: dependencies,
    targets: targets
)
