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
        .package(url: "https://github.com/OperatorFoundation/Bits", from: "2.0.4"),
        .package(url: "https://github.com/OperatorFoundation/Datable", from: "4.0.1"),
        .package(url: "https://github.com/OperatorFoundation/Net", from: "0.0.10"),
        .package(url: "https://github.com/OperatorFoundation/SwiftHexTools", from: "1.2.6"),
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
