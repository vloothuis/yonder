import Foundation

// A server-side yamux session, compatible with hashicorp/yamux. The relay opens
// streams; this side accepts them and never opens its own. See DESIGN.md for
// the rules that hashicorp/yamux enforces by ending the session.

/// Moves bytes to and from the relay. `receive` returns the next chunk of the
/// byte stream and throws when the connection ends.
protocol FrameTransport: Sendable {
    func send(_ data: Data) async throws
    func receive() async throws -> Data
    func close()
}

enum Yamux {
    static let initialWindow: UInt32 = 256 * 1024
    static let maxStreams = 256
    static let maxFrameData = 64 * 1024
    static let headerSize = 12

    enum FrameType: UInt8 {
        case data = 0, windowUpdate = 1, ping = 2, goAway = 3
    }

    struct Flags: OptionSet {
        let rawValue: UInt16
        static let syn = Flags(rawValue: 1)
        static let ack = Flags(rawValue: 2)
        static let fin = Flags(rawValue: 4)
        static let rst = Flags(rawValue: 8)
    }

    static func header(_ type: FrameType, _ flags: Flags, _ id: UInt32, _ length: UInt32) -> Data {
        var d = Data(capacity: headerSize)
        d.append(0) // version
        d.append(type.rawValue)
        d.append(UInt8(flags.rawValue >> 8)); d.append(UInt8(flags.rawValue & 0xff))
        for shift in stride(from: 24, through: 0, by: -8) { d.append(UInt8((id >> UInt32(shift)) & 0xff)) }
        for shift in stride(from: 24, through: 0, by: -8) { d.append(UInt8((length >> UInt32(shift)) & 0xff)) }
        return d
    }
}

/// Sends frames in order: control frames first, then data frames. Each stream
/// has at most one data frame queued, because a write waits for its frame to
/// be sent before queuing the next.
final class FrameWriter: @unchecked Sendable {
    private let lock = NSLock()
    private var control: [Data] = []
    private var data: [(frame: Data, sent: CheckedContinuation<Void, any Error>)] = []
    private var waiter: CheckedContinuation<Void, Never>?
    private var closedError: (any Error)?

    func sendControl(_ frame: Data) {
        let w: CheckedContinuation<Void, Never>? = lock.withLock {
            guard closedError == nil else { return nil }
            control.append(frame)
            defer { waiter = nil }
            return waiter
        }
        w?.resume()
    }

    func sendData(_ frame: Data) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, any Error>) in
            let result: (CheckedContinuation<Void, Never>?, (any Error)?) = lock.withLock {
                if let closedError { return (nil, closedError) }
                data.append((frame, c))
                defer { waiter = nil }
                return (waiter, nil)
            }
            if let error = result.1 { c.resume(throwing: error); return }
            result.0?.resume()
        }
    }

    func close(_ error: any Error) {
        let (w, pending): (CheckedContinuation<Void, Never>?, [CheckedContinuation<Void, any Error>]) = lock.withLock {
            guard closedError == nil else { return (nil, []) }
            closedError = error
            control.removeAll()
            let pending = data.map(\.sent)
            data.removeAll()
            defer { waiter = nil }
            return (waiter, pending)
        }
        pending.forEach { $0.resume(throwing: error) }
        w?.resume()
    }

    private enum Next {
        case control(Data)
        case data(Data, CheckedContinuation<Void, any Error>)
        case closed
        case none
    }

    private func next() -> Next {
        lock.withLock {
            if closedError != nil { return .closed }
            if !control.isEmpty { return .control(control.removeFirst()) }
            if !data.isEmpty { let d = data.removeFirst(); return .data(d.frame, d.sent) }
            return .none
        }
    }

    /// Sends frames until closed. Returns the transport error, if any.
    func run(_ transport: any FrameTransport) async -> (any Error)? {
        while true {
            switch next() {
            case .closed:
                return nil
            case .control(let frame):
                do { try await transport.send(frame) } catch { return error }
            case .data(let frame, let sent):
                do {
                    try await transport.send(frame)
                    sent.resume()
                } catch {
                    sent.resume(throwing: error)
                    return error
                }
            case .none:
                await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                    let ready = lock.withLock {
                        if closedError != nil || !control.isEmpty || !data.isEmpty { return true }
                        waiter = c
                        return false
                    }
                    if ready { c.resume() }
                }
            }
        }
    }
}

final class YamuxSession: @unchecked Sendable {
    private let transport: any FrameTransport
    let writer = FrameWriter()
    private let lock = NSLock()
    private var streams: [UInt32: YamuxStream] = [:]
    private var endError: YonderError?
    private var lastReceive = ContinuousClock.now
    private var tasks: [Task<Void, Never>] = []
    private let onStream: @Sendable (YamuxStream) -> Void
    private let onEnd: @Sendable (YonderError) -> Void
    private let idleTimeout: Duration
    private let pingInterval: Duration

    init(transport: any FrameTransport, pingInterval: Duration = .seconds(10), idleTimeout: Duration = .seconds(25),
         onStream: @escaping @Sendable (YamuxStream) -> Void, onEnd: @escaping @Sendable (YonderError) -> Void) {
        self.transport = transport
        self.pingInterval = pingInterval
        self.idleTimeout = idleTimeout
        self.onStream = onStream
        self.onEnd = onEnd
    }

    func start() {
        let reader = Task { [self] in await readLoop() }
        let writing = Task { [self] in
            if let error = await writer.run(transport) { end(.relayClosed(error.localizedDescription)) }
        }
        let keepalive = Task { [self] in await keepaliveLoop() }
        lock.withLock { tasks = [reader, writing, keepalive] }
    }

    var isEnded: Bool { lock.withLock { endError != nil } }

    func end(_ error: YonderError) {
        let (ended, open, running): (Bool, [YamuxStream], [Task<Void, Never>]) = lock.withLock {
            guard endError == nil else { return (false, [], []) }
            endError = error
            let open = Array(streams.values)
            streams.removeAll()
            return (true, open, tasks)
        }
        guard ended else { return }
        writer.close(error)
        transport.close()
        open.forEach { $0.fail(error) }
        running.forEach { $0.cancel() }
        onEnd(error)
    }

    func remove(_ id: UInt32) {
        lock.withLock { _ = streams.removeValue(forKey: id) }
    }

    private func keepaliveLoop() async {
        var opaque: UInt32 = 0
        while !Task.isCancelled {
            try? await Task.sleep(for: pingInterval)
            if Task.isCancelled { return }
            let idle = lock.withLock { ContinuousClock.now - lastReceive }
            if idle > idleTimeout {
                end(.relayClosed("The relay stopped answering."))
                return
            }
            opaque &+= 1
            writer.sendControl(Yamux.header(.ping, .syn, 0, opaque))
        }
    }

    private func readLoop() async {
        var buffer: [UInt8] = []
        var offset = 0
        do {
            while !Task.isCancelled {
                let chunk = try await transport.receive()
                lock.withLock { lastReceive = .now }
                if offset > 0 && offset == buffer.count { buffer.removeAll(keepingCapacity: true); offset = 0 }
                buffer.append(contentsOf: chunk)
                while buffer.count - offset >= Yamux.headerSize {
                    let h = offset
                    guard buffer[h] == 0, let type = Yamux.FrameType(rawValue: buffer[h + 1]) else {
                        throw YonderError.protocolError("bad yamux header")
                    }
                    let flags = Yamux.Flags(rawValue: UInt16(buffer[h + 2]) << 8 | UInt16(buffer[h + 3]))
                    let id = buffer[h + 4 ..< h + 8].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
                    let length = buffer[h + 8 ..< h + 12].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
                    var body: Data?
                    if type == .data {
                        guard length <= Yamux.initialWindow else { throw YonderError.protocolError("data frame too large") }
                        guard buffer.count - offset >= Yamux.headerSize + Int(length) else { break }
                        body = Data(buffer[h + Yamux.headerSize ..< h + Yamux.headerSize + Int(length)])
                        offset += Yamux.headerSize + Int(length)
                    } else {
                        offset += Yamux.headerSize
                    }
                    try handle(type: type, flags: flags, id: id, length: length, body: body)
                }
                if offset > 1 << 20 {
                    buffer.removeFirst(offset)
                    offset = 0
                }
            }
        } catch let error as YonderError {
            end(error)
        } catch {
            end(.relayClosed(error.localizedDescription))
        }
    }

    private func handle(type: Yamux.FrameType, flags: Yamux.Flags, id: UInt32, length: UInt32, body: Data?) throws {
        switch type {
        case .ping:
            if flags.contains(.syn) { writer.sendControl(Yamux.header(.ping, .ack, 0, length)) }
        case .goAway:
            throw YonderError.relayClosed("The relay ended the session.")
        case .data, .windowUpdate:
            var accepted: YamuxStream?
            if flags.contains(.syn) {
                let outcome: Result<YamuxStream?, YonderError> = lock.withLock {
                    guard id != 0, id % 2 == 1, streams[id] == nil else {
                        return .failure(.protocolError("unexpected stream \(id)"))
                    }
                    guard streams.count < Yamux.maxStreams else { return .success(nil) }
                    let s = YamuxStream(id: id, session: self)
                    streams[id] = s
                    return .success(s)
                }
                switch outcome {
                case .failure(let error): throw error
                case .success(nil):
                    writer.sendControl(Yamux.header(.windowUpdate, .rst, id, 0))
                    return
                case .success(let s?):
                    // ACK at once: the relay ends the session if a stream stays unacknowledged.
                    writer.sendControl(Yamux.header(.windowUpdate, .ack, id, 0))
                    accepted = s
                }
            }
            // Frames for streams that are gone are still in flight; ignore them.
            guard let stream = lock.withLock({ streams[id] }) else { return }
            if type == .windowUpdate {
                stream.addSendWindow(length)
            } else if let body, !stream.receive(body) {
                throw YonderError.protocolError("receive window exceeded")
            }
            if flags.contains(.rst) {
                stream.remoteReset()
            } else if flags.contains(.fin) {
                stream.remoteFin()
            }
            if let accepted { onStream(accepted) }
        }
    }
}

/// One yamux stream. One read and one write can be in flight at the same time;
/// writes are serialised.
final class YamuxStream: @unchecked Sendable {
    let id: UInt32
    private unowned let session: YamuxSession
    private let lock = NSLock()
    private var buffer = Data()
    private var recvWindow = Yamux.initialWindow
    private var consumed: UInt32 = 0
    private var sendWindow = Yamux.initialWindow
    private var remoteClosed = false
    private var localClosed = false
    private var finSent = false
    private var error: YonderError?
    private var readWaiter: CheckedContinuation<Void, Never>?
    private var windowWaiter: CheckedContinuation<Void, Never>?
    private let writeLock = AsyncLock()

    init(id: UInt32, session: YamuxSession) {
        self.id = id
        self.session = session
    }

    // MARK: Events from the session

    func receive(_ data: Data) -> Bool {
        let w: CheckedContinuation<Void, Never>?? = lock.withLock {
            guard UInt32(data.count) <= recvWindow else { return .none }
            recvWindow -= UInt32(data.count)
            buffer.append(data)
            defer { readWaiter = nil }
            return .some(readWaiter)
        }
        guard let w else { return false }
        w?.resume()
        return true
    }

    func addSendWindow(_ n: UInt32) {
        let w = lock.withLock {
            sendWindow &+= n
            defer { windowWaiter = nil }
            return windowWaiter
        }
        w?.resume()
    }

    func remoteFin() {
        let (r, w, done) = lock.withLock {
            remoteClosed = true
            defer { readWaiter = nil; windowWaiter = nil }
            return (readWaiter, windowWaiter, finSent)
        }
        r?.resume(); w?.resume()
        if done { session.remove(id) }
    }

    func remoteReset() {
        fail(.reset)
        session.remove(id)
    }

    func fail(_ e: YonderError) {
        let (r, w) = lock.withLock {
            if error == nil { error = e }
            defer { readWaiter = nil; windowWaiter = nil }
            return (readWaiter, windowWaiter)
        }
        r?.resume(); w?.resume()
    }

    // MARK: API

    /// Returns up to `maxLength` bytes, or nil at the end of the stream.
    func read(maxLength: Int = 32 * 1024) async throws -> Data? {
        while true {
            enum Step { case data(Data, UInt32), eof, failed(YonderError), wait }
            let step: Step = lock.withLock {
                if !buffer.isEmpty {
                    let n = min(maxLength, buffer.count)
                    let out = buffer.prefix(n)
                    buffer.removeFirst(n)
                    consumed += UInt32(n)
                    var delta: UInt32 = 0
                    if consumed >= Yamux.initialWindow / 2 {
                        delta = consumed
                        recvWindow += consumed
                        consumed = 0
                    }
                    return .data(Data(out), delta)
                }
                if let error { return .failed(error) }
                if remoteClosed { return .eof }
                return .wait
            }
            switch step {
            case .data(let d, let delta):
                if delta > 0 { session.writer.sendControl(Yamux.header(.windowUpdate, [], id, delta)) }
                return d
            case .eof: return nil
            case .failed(let e): throw e
            case .wait:
                try Task.checkCancellation()
                await withTaskCancellationHandler {
                    await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                        let ready = lock.withLock {
                            if !buffer.isEmpty || error != nil || remoteClosed { return true }
                            readWaiter = c
                            return false
                        }
                        if ready { c.resume() }
                    }
                } onCancel: {
                    let w = lock.withLock { defer { readWaiter = nil }; return readWaiter }
                    w?.resume()
                }
            }
        }
    }

    /// Reads exactly `count` bytes, or throws.
    func readExactly(_ count: Int) async throws -> Data {
        var out = Data()
        while out.count < count {
            guard let chunk = try await read(maxLength: count - out.count) else {
                throw YonderError.protocolError("stream ended early")
            }
            out.append(chunk)
        }
        return out
    }

    func write(_ data: Data) async throws {
        await writeLock.lock()
        defer { writeLock.unlock() }
        var offset = 0
        while offset < data.count {
            enum Step { case send(Int), failed(YonderError), wait }
            let step: Step = lock.withLock {
                if let error { return .failed(error) }
                if localClosed { return .failed(.closed) }
                if sendWindow == 0 { return .wait }
                let n = min(Int(sendWindow), Yamux.maxFrameData, data.count - offset)
                sendWindow -= UInt32(n)
                return .send(n)
            }
            switch step {
            case .failed(let e): throw e
            case .send(let n):
                var frame = Yamux.header(.data, [], id, UInt32(n))
                frame.append(data[data.startIndex + offset ..< data.startIndex + offset + n])
                try await session.writer.sendData(frame)
                offset += n
            case .wait:
                try Task.checkCancellation()
                await withTaskCancellationHandler {
                    await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                        let ready = lock.withLock {
                            if sendWindow > 0 || error != nil || localClosed { return true }
                            windowWaiter = c
                            return false
                        }
                        if ready { c.resume() }
                    }
                } onCancel: {
                    let w = lock.withLock { defer { windowWaiter = nil }; return windowWaiter }
                    w?.resume()
                }
            }
        }
    }

    /// Half-closes the stream after any write in progress. FIN goes out once.
    func close() {
        let first = lock.withLock {
            defer { localClosed = true }
            return !localClosed
        }
        guard first else { return }
        Task { [self] in
            await writeLock.lock()
            defer { writeLock.unlock() }
            sendFin()
        }
    }

    private func sendFin() {
        let (send, done) = lock.withLock {
            guard !finSent, error == nil else { return (false, false) }
            finSent = true
            return (true, remoteClosed)
        }
        guard send else { return }
        session.writer.sendControl(Yamux.header(.windowUpdate, .fin, id, 0))
        if done { session.remove(id) }
    }

    /// Aborts the stream in both directions.
    func reset() {
        let send = lock.withLock { error == nil }
        if send { session.writer.sendControl(Yamux.header(.windowUpdate, .rst, id, 0)) }
        fail(.reset)
        session.remove(id)
    }
}

/// A mutual exclusion lock for async code, FIFO.
final class AsyncLock: @unchecked Sendable {
    private let mutex = NSLock()
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func lock() async {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            let acquired = mutex.withLock {
                if !held { held = true; return true }
                waiters.append(c)
                return false
            }
            if acquired { c.resume() }
        }
    }

    func unlock() {
        let next: CheckedContinuation<Void, Never>? = mutex.withLock {
            if waiters.isEmpty { held = false; return nil }
            return waiters.removeFirst()
        }
        next?.resume()
    }
}
