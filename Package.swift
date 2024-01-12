// swift-tools-version:5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "InternetProtocols",
    platforms: [
        .macOS(.v13),
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "InternetProtocols",
            targets: ["InternetProtocols"]),
    ],
    dependencies: [
        .package(url: "https://github.com/OperatorFoundation/Bits.git", branch: "release"),
        .package(url: "https://github.com/OperatorFoundation/Datable.git", branch: "release"),
        .package(url: "https://github.com/OperatorFoundation/Net.git", branch: "release"),
        .package(url: "https://github.com/OperatorFoundation/SwiftHexTools.git", branch: "release"),
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
