import Foundation

/// An HTTP request from a visitor.
public struct YonderHTTPRequest: Sendable {
    public var method: String
    /// The path without the query, percent-encoded as sent.
    public var path: String
    public var query: String?
    /// Header names are lowercased. Repeated headers are joined with ", ".
    public var headers: [String: String]
    public var body: Data
    public var visitor: YonderVisitor
}

/// An HTTP response.
public struct YonderHTTPResponse: Sendable {
    public enum Body: Sendable {
        case data(Data)
        /// Chunks written as they arrive. The response ends when the stream
        /// finishes; when the visitor leaves first, iteration is cancelled, so
        /// the stream's `onTermination` runs. While no chunk arrives for
        /// `keepAliveInterval`, `keepAlive` is written, if set.
        case stream(AsyncStream<Data>, keepAlive: Data? = nil, keepAliveInterval: Duration = .seconds(20))
    }

    public var status: Int
    public var headers: [(name: String, value: String)]
    public var body: Body

    public init(status: Int, headers: [(name: String, value: String)] = [], body: Body = .data(Data())) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    public static func text(_ text: String, status: Int = 200) -> YonderHTTPResponse {
        YonderHTTPResponse(status: status, headers: [("Content-Type", "text/plain; charset=utf-8")], body: .data(Data(text.utf8)))
    }
}

/// A minimal HTTP/1.1 server for a yonder share: one request per connection,
/// headers up to 16 KB, bodies up to 64 KB, no chunked request bodies.
public struct YonderHTTPServer: Sendable {
    public typealias Handler = @Sendable (YonderHTTPRequest) async -> YonderHTTPResponse

    let handler: Handler
    let headTimeout: Duration

    public init(headTimeout: Duration = .seconds(10), handler: @escaping Handler) {
        self.handler = handler
        self.headTimeout = headTimeout
    }

    /// Serves the listener's connections until the share ends.
    public func serve(_ listener: YonderListener) async {
        await withTaskGroup(of: Void.self) { group in
            for await connection in listener.connections {
                group.addTask { await handle(connection) }
            }
            group.cancelAll()
        }
    }

    func handle(_ conn: YonderConnection) async {
        let timeout = Task {
            try await Task.sleep(for: headTimeout)
            conn.reset()
        }
        let request: YonderHTTPRequest
        do {
            request = try await Self.readRequest(conn)
            timeout.cancel()
        } catch {
            timeout.cancel()
            if case HTTPParseError.status(let status) = error {
                try? await Self.write(YonderHTTPResponse.text(Self.reason(status), status: status), to: conn, head: false)
                conn.close()
            } else {
                conn.reset()
            }
            return
        }
        let response = await handler(request)
        do {
            try await Self.write(response, to: conn, head: request.method == "HEAD")
            conn.close()
        } catch {
            conn.reset()
        }
    }

    enum HTTPParseError: Error { case status(Int), malformed }

    static func readRequest(_ conn: YonderConnection) async throws -> YonderHTTPRequest {
        var data = Data()
        let separator = Data("\r\n\r\n".utf8)
        var headEnd: Range<Data.Index>?
        while headEnd == nil {
            guard let chunk = try await conn.read(maxLength: 16 * 1024) else { throw HTTPParseError.malformed }
            data.append(chunk)
            headEnd = data.range(of: separator)
            if headEnd == nil && data.count > 16 * 1024 { throw HTTPParseError.status(431) }
        }
        guard let headEnd, let head = String(data: data[..<headEnd.lowerBound], encoding: .utf8) else {
            throw HTTPParseError.status(400)
        }
        var lines = head.components(separatedBy: "\r\n")
        let requestLine = lines.removeFirst().split(separator: " ", omittingEmptySubsequences: false)
        guard requestLine.count == 3, requestLine[2].hasPrefix("HTTP/1.") else { throw HTTPParseError.status(400) }
        var headers: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { throw HTTPParseError.status(400) }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = headers[name].map { $0 + ", " + value } ?? value
        }
        if headers["transfer-encoding"] != nil { throw HTTPParseError.status(411) }
        var body = data[headEnd.upperBound...]
        if let lengthText = headers["content-length"] {
            guard let length = Int(lengthText), length >= 0 else { throw HTTPParseError.status(400) }
            guard length <= 64 * 1024 else { throw HTTPParseError.status(413) }
            while body.count < length {
                guard let chunk = try await conn.read(maxLength: length - body.count) else { throw HTTPParseError.malformed }
                body.append(chunk)
            }
            body = body.prefix(length)
        }
        let target = String(requestLine[1])
        let parts = target.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        return YonderHTTPRequest(method: String(requestLine[0]), path: String(parts[0]),
                                 query: parts.count > 1 ? String(parts[1]) : nil,
                                 headers: headers, body: Data(body), visitor: conn.visitor)
    }

    static func write(_ response: YonderHTTPResponse, to conn: YonderConnection, head: Bool) async throws {
        var lines = ["HTTP/1.1 \(response.status) \(reason(response.status))"]
        for (name, value) in response.headers where !name.contains("\r") && !name.contains("\n")
            && !value.contains("\r") && !value.contains("\n") {
            lines.append("\(name): \(value)")
        }
        lines.append("Connection: close")
        switch response.body {
        case .data(let body):
            lines.append("Content-Length: \(body.count)")
            var out = Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
            if !head { out.append(body) }
            try await conn.write(out)
        case .stream(let stream, let keepAlive, let interval):
            try await conn.write(Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8))
            if head { return }
            try await pump(stream, to: conn, keepAlive: keepAlive, interval: interval)
        }
    }

    /// Writes the stream's chunks until it finishes or the visitor leaves.
    private static func pump(_ stream: AsyncStream<Data>, to conn: YonderConnection, keepAlive: Data?, interval: Duration) async throws {
        let lastWrite = LastWrite()
        try await withThrowingTaskGroup(of: Void.self) { group in
            // The request is complete, so the relay sends nothing more: the read
            // ends when the visitor leaves.
            group.addTask {
                while try await conn.read(maxLength: 1024) != nil {}
                throw CancellationError()
            }
            group.addTask {
                for await chunk in stream {
                    try await conn.write(chunk)
                    lastWrite.touch()
                }
            }
            if let keepAlive {
                group.addTask {
                    while true {
                        try await Task.sleep(for: interval)
                        if lastWrite.idle >= interval {
                            try await conn.write(keepAlive)
                            lastWrite.touch()
                        }
                    }
                }
            }
            // The first task to finish decides: the stream ended, or the visitor left.
            _ = try await group.next()
            group.cancelAll()
        }
    }

    private final class LastWrite: @unchecked Sendable {
        private let lock = NSLock()
        private var at = ContinuousClock.now
        func touch() { lock.withLock { at = .now } }
        var idle: Duration { lock.withLock { ContinuousClock.now - at } }
    }

    static func reason(_ status: Int) -> String {
        switch status {
        case 200: "OK"
        case 204: "No Content"
        case 304: "Not Modified"
        case 400: "Bad Request"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 405: "Method Not Allowed"
        case 411: "Length Required"
        case 413: "Content Too Large"
        case 431: "Request Header Fields Too Large"
        case 500: "Internal Server Error"
        case 503: "Service Unavailable"
        default: "Status"
        }
    }
}
