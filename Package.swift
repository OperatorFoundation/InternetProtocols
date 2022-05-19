// swift-tools-version:5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "InternetProtocols",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "InternetProtocols",
            targets: ["InternetProtocols"]),
    ],
    dependencies: [
        .package(url: "https://github.com/OperatorFoundation/Bits.git", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/Datable.git", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/Net.git", branch: "main"),
    ],
    targets: [
        .target(
            name: "InternetProtocols",
            dependencies: ["Bits", "Datable", "Net"]),
        .testTarget(
            name: "InternetProtocolsTests",
            dependencies: ["InternetProtocols"])
    ],
    swiftLanguageVersions: [.v5]
)
