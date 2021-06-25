// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-argon2",
    products: [
        .library(name: "Argon2", targets: ["Argon2"]),
    ],
    dependencies: [
        .package(name: "c-argon2", url: "https://github.com/youjinp/argon2", from: "0.0.2")
    ],
    targets: [
        .target(
            name: "Argon2",
            dependencies: [
                .product(name: "CArgon2", package: "c-argon2")
            ]),
        .testTarget(
            name: "Argon2Tests",
            dependencies: ["Argon2"]),
    ]
)
