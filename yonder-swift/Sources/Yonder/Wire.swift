import Foundation

/// The yonder protocol constants and the stream preamble. See DESIGN.md.
enum Wire {
    static let version = "1"
    static let connectPath = "/_yonder/connect"
    static let headerVersion = "Yonder-Version"
    static let headerCodeHash = "Yonder-Code-Hash"
    static let headerApprove = "Yonder-Approve"
    static let headerURL = "Yonder-URL"

    static let typeHTTP: UInt8 = 0x01
    static let typeApprove: UInt8 = 0x02
    static let maxPreamble = 4096

    struct Preamble: Codable, Equatable {
        var remoteAddr: String
        var userAgent: String?

        enum CodingKeys: String, CodingKey {
            case remoteAddr = "remote_addr"
            case userAgent = "user_agent"
        }
    }

    struct ApproveReply: Codable {
        var allow: Bool
    }

    static func encodePreamble(type: UInt8, _ preamble: Preamble) throws -> Data {
        let body = try JSONEncoder().encode(preamble)
        guard body.count <= maxPreamble else { throw YonderError.protocolError("preamble too large") }
        var out = Data([type, UInt8(body.count >> 8), UInt8(body.count & 0xff)])
        out.append(body)
        return out
    }
}
