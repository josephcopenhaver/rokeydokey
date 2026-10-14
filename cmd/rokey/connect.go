package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/josephcopenhaver/rokeydokey/internal/proto"
	"github.com/josephcopenhaver/rokeydokey/internal/secure"

	"golang.org/x/term"
)

// cmdConnect connects the local terminal to a rokey server, over QUIC with
// mutual TLS (default) or plain TCP. Keys are forwarded verbatim; the detach
// key (default Ctrl-]) closes the connection and leaves the program running
// on the server.
func cmdConnect(args []string) {
	fs := flag.NewFlagSet("rokey connect", flag.ExitOnError)
	transport := fs.String("transport", "quic", "transport: quic (mutual TLS over UDP) or tcp (plaintext)")
	addr := fs.String("peer-addr", "127.0.0.1:7000", "server address (host:port)")
	port := fs.Int("port", 0, "quic: local UDP port (0 = random, set for bilateral punch)")
	network := fs.String("network", "udp4", "quic: bind network: udp4, udp6, or udp (dual-stack)")
	peerKey := fs.String("peer-key", "", "quic: expected server fingerprint (required)")
	keyFile := fs.String("key-file", ".", "quic: key file path ('': ephemeral, '.': persistent user key)")
	detachFlag := fs.String("detach-key", "0x1d", "byte that detaches the client (Ctrl-] by default); 'none' disables")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: rokey connect [flags]\n\nflags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	detach := -1
	if *detachFlag != "none" {
		v, err := strconv.ParseInt(*detachFlag, 0, 16)
		if err != nil || v < 0 || v > 255 {
			fatal("bad -detach-key: %s", *detachFlag)
		}
		detach = int(v)
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fatal("stdin is not a terminal")
	}

	var rwc io.ReadWriteCloser
	var closeTransport func()
	switch *transport {
	case "tcp":
		conn, err := net.Dial("tcp", *addr)
		if err != nil {
			fatal("connect: %v", err)
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		rwc = conn
		closeTransport = func() { conn.Close() }
	case "quic":
		if *peerKey == "" {
			fatal("-peer-key is required with the quic transport (the server prints its fingerprint at startup)")
		}
		key, err := secure.LoadKey(*keyFile)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Fprintf(os.Stderr, "Your fingerprint: %s\n", secure.Fingerprint(&key.PublicKey))
		tr, err := secure.NewTransport(*network, *port)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Fprintf(os.Stderr, "Connecting to %s...\n", *addr)
		qc, err := tr.Dial(context.Background(), 15*time.Second, *network, *addr, key, *peerKey)
		if err != nil {
			tr.Close()
			fatal("connect: %v", err)
		}
		stream, err := qc.OpenStreamSync(context.Background())
		if err != nil {
			fatal("open stream: %v", err)
		}
		rwc = stream
		closeTransport = func() {
			_ = qc.CloseWithError(0, "")
			tr.Close()
		}
	default:
		fatal("invalid -transport %q: must be quic or tcp", *transport)
	}

	w := proto.NewWriter(rwc)
	r := proto.NewReader(rwc)

	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		fatal("get terminal size: %v", err)
	}
	termName := os.Getenv("TERM")
	if termName == "" {
		termName = "xterm-256color"
	}
	if err := w.WriteHello(proto.Hello{Size: proto.Size{Cols: uint16(cols), Rows: uint16(rows)}, Term: termName}); err != nil {
		fatal("send hello: %v", err)
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fatal("raw mode: %v", err)
	}
	restore := func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }
	defer restore()

	// exit runs once. Closing the transport makes the other goroutine's
	// pending read fail, so a second caller just waits for the process to
	// end instead of printing a spurious error.
	var exitOnce sync.Once
	exit := func(code int, format string, args ...any) {
		exitOnce.Do(func() {
			restore()
			closeTransport()
			if format != "" {
				fmt.Fprintf(os.Stderr, "\r\n"+format+"\r\n", args...)
			}
			os.Exit(code)
		})
		select {}
	}

	// Window size changes.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			c, rr, err := term.GetSize(int(os.Stdout.Fd()))
			if err == nil {
				_ = w.WriteResize(proto.Size{Cols: uint16(c), Rows: uint16(rr)})
			}
		}
	}()

	// Keyboard -> server.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if detach >= 0 {
					for _, b := range buf[:n] {
						if int(b) == detach {
							exit(0, "detached; program still running on %s", *addr)
						}
					}
				}
				if werr := w.WriteData(buf[:n]); werr != nil {
					exit(1, "connection lost: %v", werr)
				}
			}
			if err != nil {
				exit(0, "")
			}
		}
	}()

	// Server -> screen.
	for {
		f, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				exit(0, "connection closed by server")
			}
			exit(1, "connection error: %v", err)
		}
		switch f.Type {
		case proto.TypeData:
			if _, err := os.Stdout.Write(f.Payload); err != nil {
				exit(1, "write to terminal: %v", err)
			}
		case proto.TypeExit:
			code, _ := proto.ParseExit(f.Payload)
			exit(code, "program exited (status %d)", code)
		case proto.TypeError:
			exit(1, "server: %s", string(f.Payload))
		}
	}
}
