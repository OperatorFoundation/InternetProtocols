// swift-tools-version:5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "InternetProtocols",
    platforms: [
        .macOS(.v14),
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "InternetProtocols",
            targets: ["InternetProtocols"]),
    ],
    dependencies: [
        .package(url: "https://github.com/OperatorFoundation/Bits", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/Datable.git", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/Net.git", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/SwiftHexTools.git", branch: "main"),
    ],
    targets: [
        .target(
            name: "InternetProtocols",
            dependencies: ["Bits", "Datable", "Net", "SwiftHexTools"]),
        .testTarget(
            name: "InternetProtocolsTests",
            dependencies: ["InternetProtocols", "SwiftHexTools"])
    ],
    swiftLanguageVersions: [.v5]
)
