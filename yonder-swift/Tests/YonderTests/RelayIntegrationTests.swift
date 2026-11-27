import Foundation
import XCTest
@testable import Yonder

/// Runs the SDK against the Go relay. Set YONDER_RELAY_BIN to a built
/// `yonder-relay` binary; the tests are skipped without it.
final class RelayIntegrationTests: XCTestCase {
    private var relay: Process?
    private var port = 0
    private var relayURL: URL { URL(string: "http://127.0.0.1:\(port)")! }

    override func setUp() async throws {
        guard let bin = ProcessInfo.processInfo.environment["YONDER_RELAY_BIN"] else {
            throw XCTSkip("YONDER_RELAY_BIN is not set")
        }
        port = Int.random(in: 20000 ..< 40000)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["-listen", "127.0.0.1:\(port)", "-base", "share.localhost:\(port)", "-token", "secret"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        relay = p
        for _ in 0 ..< 50 {
            if let (status, _) = try? await curl(["http://127.0.0.1:\(port)/"]), status != 0 { return }
            try await Task.sleep(for: .milliseconds(50))
        }
        XCTFail("relay did not start")
    }

    override func tearDown() {
        relay?.terminate()
        relay?.waitUntilExit()
    }

    // MARK: Helpers

    /// Runs curl and returns (status, body).
    @discardableResult
    private func curl(_ args: [String]) async throws -> (Int, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        p.arguments = ["-s", "--noproxy", "*", "-w", "\n%{http_code}"] + args
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        let data = try await Task.detached { try out.fileHandleForReading.readToEnd() ?? Data() }.value
        p.waitUntilExit()
        var text = String(decoding: data, as: UTF8.self)
        let statusLine = text.split(separator: "\n").last.map(String.init) ?? "0"
        text = String(text.dropLast(statusLine.count + 1))
        return (Int(statusLine) ?? 0, text)
    }

    private func hostArgs(_ share: URL) -> (url: String, host: String) {
        ("http://127.0.0.1:\(port)", "Host: \(share.host!):\(port)")
    }

    /// Presents the code and returns the session cookie header.
    private func login(_ listener: YonderListener, expect: Int = 204) async throws -> String {
        let code = listener.url.fragment!.replacingOccurrences(of: "c=", with: "")
        let (url, host) = hostArgs(listener.address)
        let origin = "http://\(listener.address.host!):\(port)"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        p.arguments = ["-s", "--noproxy", "*", "-D", "-", "-o", "/dev/null", "-H", host, "-H", "Origin: \(origin)",
                       "--data-urlencode", "code=\(code)", url + "/_yonder/auth"]
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        let data = try await Task.detached { try out.fileHandleForReading.readToEnd() ?? Data() }.value
        p.waitUntilExit()
        let headers = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(headers.hasPrefix("HTTP/1.1 \(expect)"), headers)
        guard let line = headers.split(separator: "\r\n").first(where: { $0.lowercased().hasPrefix("set-cookie:") }),
              let value = line.split(separator: ":", maxSplits: 1).last?.split(separator: ";").first else { return "" }
        return "Cookie: " + value.trimmingCharacters(in: .whitespaces)
    }

    private func get(_ listener: YonderListener, _ path: String, cookie: String, extra: [String] = []) async throws -> (Int, String) {
        let (url, host) = hostArgs(listener.address)
        return try await curl(["-H", host, "-H", cookie] + extra + [url + path])
    }

    private func serve(_ listener: YonderListener, _ handler: @escaping YonderHTTPServer.Handler) -> Task<Void, Never> {
        Task { await YonderHTTPServer(handler: handler).serve(listener) }
    }

    // MARK: Tests

    func testRoundTripAndClose() async throws {
        let listener = try await YonderListener.listen(relay: relayURL, token: "secret")
        let server = serve(listener) { req in
            .text("hello \(req.method) \(req.path) q=\(req.query ?? "") from \(req.visitor.remoteAddress) host=\(req.headers["host"] ?? "")")
        }
        defer { server.cancel() }
        XCTAssertTrue(listener.url.absoluteString.hasPrefix(listener.address.absoluteString))
        let cookie = try await login(listener)
        let (status, body) = try await get(listener, "/a/b?x=1", cookie: cookie)
        XCTAssertEqual(status, 200)
        XCTAssertEqual(body, "hello GET /a/b q=x=1 from 127.0.0.1 host=\(listener.address.host!):\(port)")

        listener.close()
        let reason = await listener.waitUntilEnded()
        XCTAssertEqual(reason, .closed)
        let (after, _) = try await get(listener, "/", cookie: cookie)
        XCTAssertEqual(after, 404)
    }

    func testLargeResponseUsesFlowControl() async throws {
        let listener = try await YonderListener.listen(relay: relayURL, token: "secret")
        let big = Data((0 ..< 3_000_000).map { UInt8(truncatingIfNeeded: $0 % 251) })
        let server = serve(listener) { _ in YonderHTTPResponse(status: 200, body: .data(big)) }
        defer { server.cancel(); listener.close() }
        let cookie = try await login(listener)
        let (url, host) = hostArgs(listener.address)
        let (url2, _) = hostArgs(listener.address)
        let (status, body) = try await curl(["-H", host, "-H", cookie, url2 + "/"])
        XCTAssertEqual(status, 200)
        XCTAssertEqual(body.utf8.count, String(decoding: big, as: UTF8.self).utf8.count)
        _ = url

        // Many requests at once, to exercise stream setup and teardown.
        try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0 ..< 20 {
                group.addTask { try await self.get(listener, "/", cookie: cookie, extra: ["-o", "/dev/null"]).0 }
            }
            for try await code in group { XCTAssertEqual(code, 200) }
        }
    }

    func testStreamEndsWhenVisitorLeaves() async throws {
        let listener = try await YonderListener.listen(relay: relayURL, token: "secret")
        let terminated = expectation(description: "stream terminated")
        let server = serve(listener) { _ in
            let (stream, continuation) = AsyncStream.makeStream(of: Data.self)
            continuation.onTermination = { _ in terminated.fulfill() }
            continuation.yield(Data("data: first\n\n".utf8))
            return YonderHTTPResponse(status: 200, headers: [("Content-Type", "text/event-stream")],
                                      body: .stream(stream, keepAlive: Data(":\n\n".utf8), keepAliveInterval: .milliseconds(300)))
        }
        defer { server.cancel(); listener.close() }
        let cookie = try await login(listener)
        let (_, body) = try await get(listener, "/events", cookie: cookie, extra: ["--max-time", "1.2"])
        XCTAssertTrue(body.hasPrefix("data: first\n\n"), body)
        XCTAssertTrue(body.contains(":\n\n"), "no keep-alive in \(body)")
        await fulfillment(of: [terminated], timeout: 5)
    }

    func testApprove() async throws {
        let answers = AnswerBox([false, true])
        let listener = try await YonderListener.listen(relay: relayURL, token: "secret") { visitor in
            XCTAssertEqual(visitor.remoteAddress, "127.0.0.1")
            return answers.next()
        }
        let server = serve(listener) { _ in .text("in") }
        defer { server.cancel(); listener.close() }
        _ = try await login(listener, expect: 403)
        let cookie = try await login(listener)
        let (status, body) = try await get(listener, "/", cookie: cookie)
        XCTAssertEqual(status, 200)
        XCTAssertEqual(body, "in")
    }

    func testBadTokenIsRefused() async throws {
        do {
            _ = try await YonderListener.listen(relay: relayURL, token: "wrong")
            XCTFail("listen succeeded")
        } catch let error as YonderError {
            XCTAssertEqual(error, .refused(status: 401, message: "The relay did not accept the token."))
        }
    }
}

final class AnswerBox: @unchecked Sendable {
    private let lock = NSLock()
    private var answers: [Bool]
    init(_ answers: [Bool]) { self.answers = answers }
    func next() -> Bool { lock.withLock { answers.removeFirst() } }
}

final class UnitTests: XCTestCase {
    func testHeaderEncoding() {
        let h = Yamux.header(.windowUpdate, [.syn, .fin], 0x0102_0304, 0x0A0B_0C0D)
        XCTAssertEqual([UInt8](h), [0, 1, 0, 5, 1, 2, 3, 4, 10, 11, 12, 13])
    }

    func testRelayURLRules() throws {
        XCTAssertEqual(try YonderListener.connectURL(URL(string: "https://share.example.com/x?y")!).absoluteString,
                       "wss://share.example.com/_yonder/connect")
        XCTAssertEqual(try YonderListener.connectURL(URL(string: "http://share.localhost:8787")!).absoluteString,
                       "ws://share.localhost:8787/_yonder/connect")
        XCTAssertThrowsError(try YonderListener.connectURL(URL(string: "http://example.com")!))
        XCTAssertThrowsError(try YonderListener.connectURL(URL(string: "ftp://example.com")!))
    }
}
