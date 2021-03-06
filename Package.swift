// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "InternetProtocols",
    platforms: [
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "InternetProtocols",
            targets: ["InternetProtocols"]),
    ],
    dependencies: [
        .package(url: "https://github.com/OperatorFoundation/Bits.git", from: "1.1.0"),
        .package(url: "https://github.com/OperatorFoundation/Datable.git", from: "3.0.5"),
        .package(url: "https://github.com/OperatorFoundation/SwiftPCAP.git", from: "1.3.1"),
    ],
    targets: [
        .target(
            name: "InternetProtocols",
            dependencies: ["Datable", "Bits"]),
        .testTarget(
            name: "InternetProtocolsTests",
            dependencies: ["InternetProtocols", "SwiftPCAP"])
    ],
    swiftLanguageVersions: [.v5]
)
