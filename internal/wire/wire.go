// Package wire defines the protocol shared by the yonder client and relay:
// handshake headers and the preamble that starts every yamux stream.
package wire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version sent in HeaderVersion.
const Version = "1"

// Handshake headers and the connect path.
const (
	ConnectPath    = "/_yonder/connect"
	HeaderVersion  = "Yonder-Version"
	HeaderCodeHash = "Yonder-Code-Hash"
	HeaderApprove  = "Yonder-Approve"
	HeaderURL      = "Yonder-URL"
)

// Stream types.
const (
	TypeHTTP    byte = 0x01 // one HTTP request follows
	TypeApprove byte = 0x02 // one approval request; client replies with ApproveReply
)

const maxHeader = 4096

// Preamble starts every stream the relay opens.
type Preamble struct {
	Type       byte   `json:"-"`
	RemoteAddr string `json:"remote_addr"`
	UserAgent  string `json:"user_agent,omitempty"`
}

// ApproveReply is the client's answer on a TypeApprove stream.
type ApproveReply struct {
	Allow bool `json:"allow"`
}

// WritePreamble writes the type byte, a big-endian uint16 length and the JSON header.
func WritePreamble(w io.Writer, p Preamble) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(body) > maxHeader {
		return errors.New("wire: preamble too large")
	}
	buf := make([]byte, 3, 3+len(body))
	buf[0] = p.Type
	binary.BigEndian.PutUint16(buf[1:], uint16(len(body)))
	_, err = w.Write(append(buf, body...))
	return err
}

// ReadPreamble reads a preamble written by WritePreamble.
func ReadPreamble(r io.Reader) (Preamble, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Preamble{}, err
	}
	n := binary.BigEndian.Uint16(hdr[1:])
	if n > maxHeader {
		return Preamble{}, fmt.Errorf("wire: preamble length %d too large", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Preamble{}, err
	}
	var p Preamble
	if err := json.Unmarshal(body, &p); err != nil {
		return Preamble{}, fmt.Errorf("wire: bad preamble: %w", err)
	}
	p.Type = hdr[0]
	return p, nil
}

// HashCode returns the hex SHA-256 of a share code, as sent in HeaderCodeHash.
func HashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
