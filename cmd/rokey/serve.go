package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/josephcopenhaver/rokeydokey/internal/proto"
	"github.com/josephcopenhaver/rokeydokey/internal/secure"

	"github.com/creack/pty"
	"github.com/quic-go/quic-go"
)

// closeGraceEnv names the environment variable that bounds how long the
// server waits for a departing client to read its final frame and hang up
// before tearing the connection down. Accepts a Go duration ("3s", "500ms").
const (
	closeGraceEnv     = "ROKEY_CLOSE_GRACE"
	defaultCloseGrace = 3 * time.Second
)

// closeGrace reads closeGraceEnv, falling back to defaultCloseGrace when
// unset. An unparsable or negative value is a startup error.
func closeGrace() (time.Duration, error) {
	v := os.Getenv(closeGraceEnv)
	if v == "" {
		return defaultCloseGrace, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", closeGraceEnv, v, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s=%q: must not be negative", closeGraceEnv, v)
	}
	return d, nil
}

// cmdServe hosts a terminal program (the user's shell by default) inside a
// pseudo-terminal and exposes it to one client at a time, over QUIC with
// mutual TLS (default) or plain TCP. The program keeps running when the
// client disconnects, and a later client re-attaches to the same session.
// The server exits when the program exits.
func cmdServe(args []string) {
	fs := flag.NewFlagSet("rokey serve", flag.ExitOnError)
	transport := fs.String("transport", "quic", "transport: quic (mutual TLS over UDP) or tcp (plaintext)")
	listen := fs.String("listen", "127.0.0.1:7000", "tcp: address to listen on")
	port := fs.Int("port", 0, "quic: UDP port to listen on (0 = random)")
	network := fs.String("network", "udp4", "quic: bind network: udp4, udp6, or udp (dual-stack)")
	peerKey := fs.String("peer-key", "", "quic: expected client fingerprint (required)")
	keyFile := fs.String("key-file", "", "quic: key file path (default: ephemeral, '.': persistent user key)")
	clientAddr := fs.String("client-addr", "", "quic: client's public address for bilateral hole punching")
	program := fs.String("cmd", "", "program to host (default: $SHELL, then /bin/sh); arguments follow after --")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: rokey serve [flags] [-- program args...]\n\nflags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	bin, err := findProgram(*program)
	if err != nil {
		fatal("%v", err)
	}
	grace, err := closeGrace()
	if err != nil {
		fatal("%v", err)
	}
	srv := &server{bin: bin, args: fs.Args(), done: make(chan int, 1), closeGrace: grace}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var closeTransport func()
	switch *transport {
	case "tcp":
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			fatal("%v", err)
		}
		log.Printf("listening on tcp %s (plaintext), program %s, args %q", ln.Addr(), bin, fs.Args())
		closeTransport = func() { ln.Close() }
		go srv.acceptTCP(ln)
	case "quic":
		if *peerKey == "" {
			fatal("-peer-key is required with the quic transport (run `rokey show-key` on the client)")
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
		var stopPunch func()
		if *clientAddr != "" {
			stopPunch, err = tr.StartPunch(ctx, *network, *clientAddr)
			if err != nil {
				log.Printf("punch toward %s failed: %v (continuing without punch)", *clientAddr, err)
			} else {
				log.Printf("punching toward client at %s", *clientAddr)
			}
		}
		ln, err := tr.Listen(key, *peerKey)
		if err != nil {
			fatal("%v", err)
		}
		log.Printf("listening on %s port %d (quic, mutual TLS), program %s, args %q", *network, tr.LocalPort(), bin, fs.Args())
		closeTransport = func() { ln.Close(); tr.Close() }
		go srv.acceptQUIC(ctx, ln, stopPunch)
	default:
		fatal("invalid -transport %q: must be quic or tcp", *transport)
	}

	// Forward termination to the program so it can back up and exit cleanly;
	// the server then exits via the normal "program exited" path.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Printf("received %v, stopping program", sig)
		if !srv.signalProgram(syscall.SIGTERM) {
			srv.done <- 130
			return
		}
		select {
		case <-time.After(5 * time.Second):
			log.Printf("program did not exit, killing")
			srv.signalProgram(syscall.SIGKILL)
		case <-sigs:
			srv.signalProgram(syscall.SIGKILL)
		}
	}()

	code := <-srv.done
	srv.waitForClient(srv.closeGrace)
	cancel()
	closeTransport()
	log.Printf("program exited with status %d", code)
	os.Exit(code)
}

// findProgram resolves the program to host: the -cmd value, else the
// user's shell, else /bin/sh. A bare name is looked up on $PATH.
func findProgram(explicit string) (string, error) {
	cand := explicit
	if cand == "" {
		cand = os.Getenv("SHELL")
	}
	if cand == "" {
		cand = "/bin/sh"
	}
	p, err := exec.LookPath(cand)
	if err != nil {
		return "", fmt.Errorf("program %q: %w", cand, err)
	}
	return p, nil
}

// attachment is the one client currently viewing the session.
type attachment struct {
	w    *proto.Writer
	rwc  io.ReadWriteCloser
	done chan struct{} // closed when the client's handler returns
}

type server struct {
	bin        string
	args       []string
	done       chan int
	closeGrace time.Duration // see closeGraceEnv

	mu     sync.Mutex
	cmd    *exec.Cmd
	ptmx   *os.File
	client *attachment // nil when detached
}

func (s *server) acceptTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go s.handle(c, c.RemoteAddr().String())
	}
}

func (s *server) acceptQUIC(ctx context.Context, ln *quic.Listener, stopPunch func()) {
	for {
		qc, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		// The handshake verified the client's fingerprint; stop punching.
		if stopPunch != nil {
			stopPunch()
			stopPunch = nil
		}
		go func() {
			remote := qc.RemoteAddr().String()
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			stream, err := qc.AcceptStream(sctx)
			cancel()
			if err != nil {
				log.Printf("%s: no stream opened: %v", remote, err)
				_ = qc.CloseWithError(1, "no stream")
				return
			}
			s.handle(stream, remote)
			// Closing the connection discards unsent stream data, so give
			// the client a moment to read the final frame and hang up first.
			select {
			case <-qc.Context().Done():
			case <-time.After(s.closeGrace):
			}
			_ = qc.CloseWithError(0, "")
		}()
	}
}

// start launches the program with the given size and TERM. Caller holds s.mu.
func (s *server) start(h proto.Hello) error {
	cmd := exec.Command(s.bin, s.args...)
	cmd.Env = append(os.Environ(), "TERM="+h.Term)
	ws := &pty.Winsize{Rows: h.Size.Rows, Cols: h.Size.Cols}
	ptmx, err := pty.StartWithSize(cmd, ws)
	if err != nil {
		return err
	}
	// Put the master in blocking mode before anything reads it. Go's
	// netpoller (kqueue on macOS) does not reliably wake for pty masters,
	// and pty.Setsize would otherwise flip the mode mid-read anyway.
	if err := syscall.SetNonblock(int(ptmx.Fd()), false); err != nil {
		ptmx.Close()
		_ = cmd.Process.Kill()
		return err
	}
	s.cmd = cmd
	s.ptmx = ptmx
	log.Printf("started %s (pid %d) %dx%d TERM=%s", s.bin, cmd.Process.Pid, h.Size.Cols, h.Size.Rows, h.Term)

	// Pump program output to whichever client is attached. This goroutine
	// must always drain the pty so the program never blocks on write.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				s.mu.Lock()
				c := s.client
				s.mu.Unlock()
				if c != nil {
					if werr := c.w.WriteData(buf[:n]); werr != nil {
						s.detach(c)
					}
				}
			}
			if err != nil {
				break
			}
		}
		code := 0
		if err := cmd.Wait(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else {
				code = 1
			}
		}
		s.mu.Lock()
		c := s.client
		s.mu.Unlock()
		if c != nil {
			_ = c.w.WriteExit(code)
			_ = c.rwc.Close() // graceful end of stream after the exit frame
		}
		s.done <- code
	}()
	return nil
}

// waitForClient gives the attached client's handler up to d to finish, so
// the exit frame is delivered before the transport goes away.
func (s *server) waitForClient(d time.Duration) {
	s.mu.Lock()
	c := s.client
	s.mu.Unlock()
	if c == nil {
		return
	}
	select {
	case <-c.done:
	case <-time.After(d):
	}
}

// signalProgram sends sig to the program. It reports false when no program
// has been started.
func (s *server) signalProgram(sig syscall.Signal) bool {
	s.mu.Lock()
	cmd := s.cmd
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return false
	}
	_ = cmd.Process.Signal(sig)
	return true
}

// detach drops c if it is the attached client.
func (s *server) detach(c *attachment) {
	s.mu.Lock()
	if s.client == c {
		s.client = nil
		log.Printf("client detached")
	}
	s.mu.Unlock()
}

// resize applies a new window size and nudges the program to redraw even if
// the size is unchanged (most full-screen programs only repaint on an
// actual change).
func (s *server) resize(sz proto.Size, force bool) {
	s.mu.Lock()
	ptmx, cmd := s.ptmx, s.cmd
	s.mu.Unlock()
	if ptmx == nil {
		return
	}
	if force && sz.Cols > 1 {
		if err := pty.Setsize(ptmx, &pty.Winsize{Rows: sz.Rows, Cols: sz.Cols - 1}); err != nil {
			log.Printf("setsize: %v", err)
		}
		_ = cmd.Process.Signal(syscall.SIGWINCH)
		time.Sleep(20 * time.Millisecond)
	}
	if err := pty.Setsize(ptmx, &pty.Winsize{Rows: sz.Rows, Cols: sz.Cols}); err != nil {
		log.Printf("setsize: %v", err)
	}
	_ = cmd.Process.Signal(syscall.SIGWINCH)
	log.Printf("resized to %dx%d (force=%v)", sz.Cols, sz.Rows, force)
}

// isCleanClose reports whether err is an orderly end of the client's
// connection rather than a failure.
func isCleanClose(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	var appErr *quic.ApplicationError
	return errors.As(err, &appErr) && appErr.ErrorCode == 0
}

// handle runs one client connection (a TCP conn or a QUIC stream) to
// completion.
func (s *server) handle(rwc io.ReadWriteCloser, remote string) {
	defer rwc.Close()
	r := proto.NewReader(rwc)
	w := proto.NewWriter(rwc)
	log.Printf("connection from %s", remote)

	f, err := r.Read()
	if err != nil || f.Type != proto.TypeHello {
		_ = w.WriteError("expected hello")
		return
	}
	hello, err := proto.ParseHello(f.Payload)
	if err != nil {
		_ = w.WriteError(err.Error())
		return
	}
	if hello.Term == "" {
		hello.Term = "xterm-256color"
	}

	s.mu.Lock()
	if s.client != nil {
		s.mu.Unlock()
		_ = w.WriteError("session busy: another client is attached")
		log.Printf("rejected %s: busy", remote)
		return
	}
	fresh := s.cmd == nil
	if fresh {
		if err := s.start(hello); err != nil {
			s.mu.Unlock()
			_ = w.WriteError("start program: " + err.Error())
			log.Printf("start program: %v", err)
			return
		}
	}
	att := &attachment{w: w, rwc: rwc, done: make(chan struct{})}
	s.client = att
	s.mu.Unlock()
	log.Printf("client attached (%dx%d)", hello.Size.Cols, hello.Size.Rows)
	defer close(att.done)
	defer s.detach(att)

	if !fresh {
		s.resize(hello.Size, true)
	}

	for {
		f, err := r.Read()
		if err != nil {
			if !isCleanClose(err) {
				log.Printf("read from client: %v", err)
			}
			return
		}
		switch f.Type {
		case proto.TypeData:
			s.mu.Lock()
			ptmx := s.ptmx
			s.mu.Unlock()
			if ptmx == nil {
				return
			}
			if _, err := ptmx.Write(f.Payload); err != nil {
				return
			}
		case proto.TypeResize:
			sz, err := proto.ParseSize(f.Payload)
			if err == nil {
				s.resize(sz, false)
			}
		default:
			log.Printf("ignoring frame type %d", f.Type)
		}
	}
}
