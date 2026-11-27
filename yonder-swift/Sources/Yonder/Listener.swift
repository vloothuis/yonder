import CryptoKit
import Foundation

/// Why a share failed or ended.
public enum YonderError: Error, LocalizedError, Equatable, Sendable {
    /// The relay URL is not https, or plain http on a host other than this machine.
    case invalidRelay(String)
    /// The relay refused the connection.
    case refused(status: Int, message: String)
    case protocolError(String)
    /// The connection to the relay ended.
    case relayClosed(String)
    /// The listener was closed.
    case closed
    /// The stream was reset.
    case reset

    public var errorDescription: String? {
        switch self {
        case .invalidRelay(let m), .protocolError(let m), .relayClosed(let m): m
        case .refused(_, let m): m
        case .closed: "The share was closed."
        case .reset: "The connection was reset."
        }
    }
}

/// Someone who asked to open a share. Both fields come from the relay and the
/// visitor's browser; they are not verified.
public struct YonderVisitor: Sendable, Equatable {
    public let remoteAddress: String
    public let userAgent: String
}

/// A visitor connection: one HTTP request and its response.
public final class YonderConnection: Sendable {
    public let visitor: YonderVisitor
    let stream: YamuxStream

    init(visitor: YonderVisitor, stream: YamuxStream) {
        self.visitor = visitor
        self.stream = stream
    }

    /// Returns up to `maxLength` bytes, or nil when the visitor side has finished sending.
    public func read(maxLength: Int = 32 * 1024) async throws -> Data? { try await stream.read(maxLength: maxLength) }

    /// Writes all of `data`. Concurrent writes are serialised.
    public func write(_ data: Data) async throws { try await stream.write(data) }

    /// Ends this side of the connection after pending writes.
    public func close() { stream.close() }

    /// Aborts the connection.
    public func reset() { stream.reset() }
}

/// One share on a yonder relay. The link works until `close()` or until the
/// relay connection ends; there is no reconnect.
public final class YonderListener: @unchecked Sendable {
    /// The link to hand out. It carries the access code in its fragment.
    public let url: URL
    /// The share's address without the code.
    public let address: URL
    /// Visitor connections. Iterate from one task only.
    public let connections: AsyncStream<YonderConnection>

    private let continuation: AsyncStream<YonderConnection>.Continuation
    private var session: YamuxSession!
    private let approve: (@Sendable (YonderVisitor) async -> Bool)?
    private let lock = NSLock()
    private var endReason: YonderError?
    private var endWaiters: [CheckedContinuation<YonderError, Never>] = []

    /// Registers a share with the relay.
    ///
    /// - Parameters:
    ///   - relay: the relay's base URL. Plain http is accepted only for loopback and `*.localhost`.
    ///   - token: the client token.
    ///   - approve: if set, called for each visitor who has the right code. Runs in
    ///     its own task, which is cancelled when the relay stops waiting (after 60
    ///     seconds) or the share ends. Return true to let the visitor in.
    public static func listen(relay: URL, token: String,
                              approve: (@Sendable (YonderVisitor) async -> Bool)? = nil) async throws -> YonderListener {
        let wsURL = try connectURL(relay)
        var codeBytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, codeBytes.count, &codeBytes) == errSecSuccess else {
            throw YonderError.protocolError("no random bytes")
        }
        let code = Data(codeBytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let hash = SHA256.hash(data: Data(code.utf8)).map { String(format: "%02x", $0) }.joined()

        var request = URLRequest(url: wsURL)
        request.setValue(Wire.version, forHTTPHeaderField: Wire.headerVersion)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(hash, forHTTPHeaderField: Wire.headerCodeHash)
        if approve != nil { request.setValue("1", forHTTPHeaderField: Wire.headerApprove) }

        let transport = try await WebSocketTransport.connect(request)
        let headers = transport.responseHeaders
        func fail(_ error: YonderError) -> YonderError { transport.close(); return error }
        guard headers[Wire.headerVersion.lowercased()] == Wire.version else {
            throw fail(.protocolError("The relay speaks another protocol version."))
        }
        guard let share = headers[Wire.headerURL.lowercased()], let address = URL(string: share) else {
            throw fail(.protocolError("The relay sent no share address."))
        }
        if approve != nil, headers[Wire.headerApprove.lowercased()] != "1" {
            throw fail(.protocolError("The relay does not support approving visitors."))
        }
        var base = share
        while base.hasSuffix("/") { base.removeLast() }
        guard let link = URL(string: base + "/#c=" + code) else { throw fail(.protocolError("bad share address")) }

        let listener = YonderListener(url: link, address: address, approve: approve)
        listener.session = YamuxSession(transport: transport,
                                        onStream: { [weak listener] in listener?.accept($0) },
                                        onEnd: { [weak listener] in listener?.ended($0) })
        listener.session.start()
        return listener
    }

    private init(url: URL, address: URL, approve: (@Sendable (YonderVisitor) async -> Bool)?) {
        self.url = url
        self.address = address
        self.approve = approve
        (connections, continuation) = AsyncStream.makeStream(bufferingPolicy: .bufferingOldest(64))
    }

    deinit { session?.end(.closed) }

    /// Ends the share. The relay drops the link at once.
    public func close() { session.end(.closed) }

    /// Waits until the share ends and returns why: `.closed` after `close()`,
    /// otherwise the error that ended it.
    public func waitUntilEnded() async -> YonderError {
        await withCheckedContinuation { c in
            let reason: YonderError? = lock.withLock {
                if let endReason { return endReason }
                endWaiters.append(c)
                return nil
            }
            if let reason { c.resume(returning: reason) }
        }
    }

    public var isEnded: Bool { lock.withLock { endReason != nil } }

    private func ended(_ reason: YonderError) {
        let waiters = lock.withLock {
            endReason = reason
            defer { endWaiters.removeAll() }
            return endWaiters
        }
        continuation.finish()
        waiters.forEach { $0.resume(returning: reason) }
    }

    private func accept(_ stream: YamuxStream) {
        Task { [weak self] in
            guard let self else { stream.reset(); return }
            let timeout = Task {
                try await Task.sleep(for: .seconds(10))
                stream.reset()
            }
            let preamble: (type: UInt8, Wire.Preamble)
            do {
                let head = try await stream.readExactly(3)
                let length = Int(head[head.startIndex + 1]) << 8 | Int(head[head.startIndex + 2])
                guard length <= Wire.maxPreamble else { throw YonderError.protocolError("preamble too large") }
                let body = try await stream.readExactly(length)
                preamble = (head[head.startIndex], try JSONDecoder().decode(Wire.Preamble.self, from: body))
                timeout.cancel()
            } catch {
                timeout.cancel()
                stream.reset()
                return
            }
            let visitor = YonderVisitor(remoteAddress: preamble.1.remoteAddr, userAgent: preamble.1.userAgent ?? "")
            switch preamble.type {
            case Wire.typeHTTP:
                if case .dropped = continuation.yield(YonderConnection(visitor: visitor, stream: stream)) {
                    stream.reset()
                }
            case Wire.typeApprove:
                await answerApproval(stream: stream, visitor: visitor)
            default:
                stream.reset()
            }
        }
    }

    private func answerApproval(stream: YamuxStream, visitor: YonderVisitor) async {
        let approve = self.approve
        let decision = Task<Bool, Never> {
            guard let approve else { return false }
            return await approve(visitor)
        }
        // The relay sends nothing more: a read ends when it gives up or the share ends.
        let watcher = Task {
            while (try? await stream.read(maxLength: 256)) != nil {}
            decision.cancel()
        }
        let allow = await decision.value
        if !decision.isCancelled, let reply = try? JSONEncoder().encode(Wire.ApproveReply(allow: allow)) {
            try? await stream.write(reply + Data("\n".utf8))
        }
        stream.close()
        _ = watcher
    }

    static func connectURL(_ relay: URL) throws -> URL {
        guard var parts = URLComponents(url: relay, resolvingAgainstBaseURL: false),
              let host = parts.host?.lowercased(), !host.isEmpty else {
            throw YonderError.invalidRelay("The relay address is not a valid URL.")
        }
        switch parts.scheme?.lowercased() {
        case "https": parts.scheme = "wss"
        case "http":
            guard isLocalHost(host) else {
                throw YonderError.invalidRelay("Plain http is only allowed for a relay on this machine.")
            }
            parts.scheme = "ws"
        default:
            throw YonderError.invalidRelay("The relay address must start with https://.")
        }
        parts.path = Wire.connectPath
        parts.query = nil
        parts.fragment = nil
        guard let url = parts.url else { throw YonderError.invalidRelay("The relay address is not a valid URL.") }
        return url
    }

    static func isLocalHost(_ host: String) -> Bool {
        var h = host.lowercased()
        if h.hasSuffix(".") { h.removeLast() }
        if h.hasPrefix("[") && h.hasSuffix("]") { h = String(h.dropFirst().dropLast()) }
        return h == "localhost" || h.hasSuffix(".localhost") || h == "::1" || h.hasPrefix("127.")
    }
}

/// The relay connection over URLSessionWebSocketTask.
final class WebSocketTransport: NSObject, FrameTransport, URLSessionWebSocketDelegate, @unchecked Sendable {
    private var session: URLSession!
    private var task: URLSessionWebSocketTask!
    private let lock = NSLock()
    private var opened: CheckedContinuation<Void, any Error>?
    private(set) var responseHeaders: [String: String] = [:]

    static func connect(_ request: URLRequest) async throws -> WebSocketTransport {
        let t = WebSocketTransport()
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        t.session = URLSession(configuration: config, delegate: t, delegateQueue: nil)
        t.task = t.session.webSocketTask(with: request)
        t.task.maximumMessageSize = 4 << 20
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, any Error>) in
                t.lock.withLock { t.opened = c }
                t.task.resume()
            }
        } onCancel: {
            t.close()
        }
        return t
    }

    func send(_ data: Data) async throws { try await task.send(.data(data)) }

    func receive() async throws -> Data {
        switch try await task.receive() {
        case .data(let d): return d
        case .string: throw YonderError.protocolError("unexpected text message")
        @unknown default: throw YonderError.protocolError("unexpected message")
        }
    }

    func close() {
        task?.cancel(with: .normalClosure, reason: nil)
        session?.invalidateAndCancel()
    }

    private func finishOpen(_ result: Result<Void, any Error>) {
        let c = lock.withLock { defer { opened = nil }; return opened }
        c?.resume(with: result)
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        if let response = webSocketTask.response as? HTTPURLResponse {
            var headers: [String: String] = [:]
            for (k, v) in response.allHeaderFields {
                if let k = k as? String, let v = v as? String { headers[k.lowercased()] = v }
            }
            lock.withLock { responseHeaders = headers }
        }
        finishOpen(.success(()))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        let status = (task.response as? HTTPURLResponse)?.statusCode ?? 0
        let message: String
        switch status {
        case 400: message = "The relay does not accept this client. It may need an update."
        case 401: message = "The relay did not accept the token."
        case 429: message = "There are too many shares for this token. Stop one and try again."
        case 0: message = error?.localizedDescription ?? "The relay could not be reached."
        default: message = "The relay refused the connection (HTTP \(status))."
        }
        finishOpen(.failure(status == 0 ? YonderError.relayClosed(message) : YonderError.refused(status: status, message: message)))
    }

    // Never follow redirects: the token must only go to the relay that was given.
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
