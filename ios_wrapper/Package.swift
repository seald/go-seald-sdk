// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SealdSdk",
    products: [
        .library(
            name: "SealdSdk",
            targets: ["SealdSdk"])
    ],
    targets: [
        .target(
            name: "SealdSdk",
            dependencies: ["SealdSdkInternals"],
            path: "SealdSdk/Classes",
            publicHeadersPath: "."
        ),
        .binaryTarget(
            name: "SealdSdkInternals",
            path: "SealdSdk/Frameworks/SealdSdkInternals.xcframework"
        )
    ]
)
