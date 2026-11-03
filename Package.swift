// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwiftXTEA",
    products: [
        .library(name: "SwiftXTEA", targets: ["SwiftXTEA"])
    ],
    targets: [
        .target(name: "SwiftXTEA"),
        .testTarget(name: "SwiftXTEATests", dependencies: ["SwiftXTEA"])
    ]
)
