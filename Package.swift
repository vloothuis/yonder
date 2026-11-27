// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Yonder",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [.library(name: "Yonder", targets: ["Yonder"])],
    targets: [
        .target(name: "Yonder", path: "yonder-swift/Sources/Yonder"),
        .testTarget(name: "YonderTests", dependencies: ["Yonder"], path: "yonder-swift/Tests/YonderTests"),
    ]
)
