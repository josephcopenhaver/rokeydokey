// Package proto defines the framing used on the TCP link between the
// rokey attach and serve commands.
//
// Every message is a frame:
//
//	type   uint8
//	length uint32 (big endian, payload bytes)
//	payload
//
// Client -> server frames: Hello, Data, Resize.
// Server -> client frames: Data, Exit, Error.
package proto

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Frame types.
const (
	TypeData   uint8 = 0 // raw terminal bytes, either direction
	TypeHello  uint8 = 1 // client -> server: initial size + TERM
	TypeResize uint8 = 2 // client -> server: new window size
	TypeExit   uint8 = 3 // server -> client: editor exited with code
	TypeError  uint8 = 4 // server -> client: human readable error
)

// MaxPayload bounds a single frame so a bad peer cannot force a huge allocation.
const MaxPayload = 1 << 20

// Frame is one decoded message.
type Frame struct {
	Type    uint8
	Payload []byte
}

// Size is a terminal size carried by Hello and Resize frames.
type Size struct {
	Cols, Rows uint16
}

// Hello is the payload of a TypeHello frame.
type Hello struct {
	Size Size
	Term string
}

// Writer serialises frames onto a stream. It is safe for concurrent use.
type Writer struct {
	mu sync.Mutex
	w  *bufio.Writer
}

// NewWriter wraps w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: bufio.NewWriterSize(w, 32*1024)}
}

// Write emits one frame and flushes.
func (fw *Writer) Write(t uint8, payload []byte) error {
	if len(payload) > MaxPayload {
		return fmt.Errorf("proto: payload too large (%d bytes)", len(payload))
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	var hdr [5]byte
	hdr[0] = t
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := fw.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := fw.w.Write(payload); err != nil {
		return err
	}
	return fw.w.Flush()
}

// WriteData sends terminal bytes.
func (fw *Writer) WriteData(b []byte) error { return fw.Write(TypeData, b) }

// WriteHello sends the client greeting.
func (fw *Writer) WriteHello(h Hello) error {
	p := make([]byte, 4+len(h.Term))
	putSize(p, h.Size)
	copy(p[4:], h.Term)
	return fw.Write(TypeHello, p)
}

// WriteResize sends a new window size.
func (fw *Writer) WriteResize(s Size) error {
	var p [4]byte
	putSize(p[:], s)
	return fw.Write(TypeResize, p[:])
}

// WriteExit tells the client the editor finished.
func (fw *Writer) WriteExit(code int) error {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], uint32(int32(code)))
	return fw.Write(TypeExit, p[:])
}

// WriteError sends a diagnostic string.
func (fw *Writer) WriteError(msg string) error { return fw.Write(TypeError, []byte(msg)) }

// Reader decodes frames from a stream.
type Reader struct {
	r *bufio.Reader
}

// NewReader wraps r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReaderSize(r, 32*1024)}
}

// Read blocks until one full frame is available.
func (fr *Reader) Read() (Frame, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(fr.r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxPayload {
		return Frame{}, fmt.Errorf("proto: frame too large (%d bytes)", n)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(fr.r, p); err != nil {
		return Frame{}, err
	}
	return Frame{Type: hdr[0], Payload: p}, nil
}

// ParseHello decodes a Hello payload.
func ParseHello(p []byte) (Hello, error) {
	if len(p) < 4 {
		return Hello{}, errors.New("proto: short hello")
	}
	return Hello{Size: getSize(p), Term: string(p[4:])}, nil
}

// ParseSize decodes a Resize payload.
func ParseSize(p []byte) (Size, error) {
	if len(p) < 4 {
		return Size{}, errors.New("proto: short resize")
	}
	return getSize(p), nil
}

// ParseExit decodes an Exit payload.
func ParseExit(p []byte) (int, error) {
	if len(p) < 4 {
		return 0, errors.New("proto: short exit")
	}
	return int(int32(binary.BigEndian.Uint32(p))), nil
}

func putSize(p []byte, s Size) {
	binary.BigEndian.PutUint16(p[0:], s.Cols)
	binary.BigEndian.PutUint16(p[2:], s.Rows)
}

func getSize(p []byte) Size {
	return Size{Cols: binary.BigEndian.Uint16(p[0:]), Rows: binary.BigEndian.Uint16(p[2:])}
}
