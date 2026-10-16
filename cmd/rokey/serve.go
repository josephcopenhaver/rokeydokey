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

// serveOpts holds the values of the `rokey serve` flags.
type serveOpts struct {
	transport, listen, network, peerKey, keyFile, peerAddr, program string
	port                                                            int
	restart                                                         bool
}

// serveFlagSet defines the `rokey serve` flags. It is separate from cmdServe
// so the completion catalogue can be checked against the real flag set.
func serveFlagSet() (*flag.FlagSet, *serveOpts) {
	fs := flag.NewFlagSet("rokey serve", flag.ExitOnError)
	o := &serveOpts{}
	fs.StringVar(&o.transport, "transport", "quic", "transport: quic (mutual TLS over UDP) or tcp (plaintext)")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:7000", "tcp: address to listen on")
	fs.IntVar(&o.port, "port", 0, "quic: UDP port to listen on (0 = random)")
	fs.StringVar(&o.network, "network", "udp4", "quic: bind network: udp4, udp6, or udp (dual-stack)")
	fs.StringVar(&o.peerKey, "peer-key", "", "quic: expected client fingerprint (required)")
	fs.StringVar(&o.keyFile, "key-file", "", "quic: key file path (default: ephemeral, '.': persistent user key)")
	fs.StringVar(&o.peerAddr, "peer-addr", "", "quic: client's public address (host:port) to hole punch toward")
	fs.BoolVar(&o.restart, "restart", false, "keep serving after the program exits; the next client starts it again")
	fs.StringVar(&o.program, "cmd", "", "program to host (default: $SHELL, then /bin/sh); arguments follow after --")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: rokey serve [flags] [-- program args...]\n\nflags:\n")
		fs.PrintDefaults()
	}
	return fs, o
}

// cmdServe hosts a terminal program (the user's shell by default) inside a
// pseudo-terminal and exposes it to one client at a time, over QUIC with
// mutual TLS (default) or plain TCP. The program keeps running when the
// client disconnects, and a later client reconnects to the same session.
// The server exits when the program exits, unless -restart is set, in which
// case the next client starts the program again.
func cmdServe(args []string) {
	fs, o := serveFlagSet()
	_ = fs.Parse(args)

	bin, err := findProgram(o.program)
	if err != nil {
		fatal("%v", err)
	}
	grace, err := closeGrace()
	if err != nil {
		fatal("%v", err)
	}
	srv := &server{bin: bin, args: fs.Args(), restart: o.restart, done: make(chan int, 1), closeGrace: grace}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var closeTransport func()
	switch o.transport {
	case "tcp":
		ln, err := net.Listen("tcp", o.listen)
		if err != nil {
			fatal("%v", err)
		}
		log.Printf("listening on tcp %s (plaintext), program %s, args %q", ln.Addr(), bin, fs.Args())
		closeTransport = func() { ln.Close() }
		go srv.acceptTCP(ln)
	case "quic":
		if o.peerKey == "" {
			fatal("-peer-key is required with the quic transport (run `rokey show-key` on the client)")
		}
		key, err := secure.LoadKey(o.keyFile)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Fprintf(os.Stderr, "Your fingerprint: %s\n", secure.Fingerprint(&key.PublicKey))

		tr, err := secure.NewTransport(o.network, o.port)
		if err != nil {
			fatal("%v", err)
		}
		var punch *puncher
		if o.peerAddr != "" {
			punch = newPuncher(ctx, tr, o.network, o.peerAddr)
			punch.resume()
		}
		ln, err := tr.Listen(key, o.peerKey)
		if err != nil {
			fatal("%v", err)
		}
		log.Printf("listening on %s port %d (quic, mutual TLS), program %s, args %q", o.network, tr.LocalPort(), bin, fs.Args())
		closeTransport = func() { ln.Close(); tr.Close() }
		go srv.acceptQUIC(ctx, ln, punch)
	default:
		fatal("invalid -transport %q: must be quic or tcp", o.transport)
	}

	// Forward termination to the program so it can back up and exit cleanly;
	// the server then exits via the normal "program exited" path. With
	// -restart, marking the server as stopping first makes that exit final.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Printf("received %v, stopping program", sig)
		srv.beginShutdown()
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

	var code int
	for {
		code = <-srv.done
		if !srv.willRestart() {
			break
		}
		log.Printf("program exited with status %d; the next client starts it again", code)
	}
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

// puncher keeps UDP hole punching toward the peer running whenever no QUIC
// connection is live. Only outbound traffic opens or refreshes the server's
// NAT mapping, so once a client leaves and the mapping expires, the next
// connection attempt is dropped at the NAT unless punching has resumed.
// While a connection is live its keepalives do that job and punching pauses.
type puncher struct {
	ctx     context.Context
	tr      *secure.Transport
	network string
	addr    string

	mu   sync.Mutex
	live int    // accepted QUIC connections that have not ended yet
	stop func() // non-nil while punching
}

func newPuncher(ctx context.Context, tr *secure.Transport, network, addr string) *puncher {
	return &puncher{ctx: ctx, tr: tr, network: network, addr: addr}
}

// resume starts punching unless a connection is live, punching is already
// running, or the server is shutting down. The peer address is re-resolved
// on every resume.
func (p *puncher) resume() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.live > 0 || p.stop != nil || p.ctx.Err() != nil {
		return
	}
	stop, err := p.tr.StartPunch(p.ctx, p.network, p.addr)
	if err != nil {
		log.Printf("punch toward %s failed: %v (continuing without punch)", p.addr, err)
		return
	}
	p.stop = stop
	log.Printf("punching toward peer at %s", p.addr)
}

// track pauses punching for the lifetime of an accepted connection and
// resumes it once the connection ends, however it ends.
func (p *puncher) track(qc *quic.Conn) {
	p.mu.Lock()
	p.live++
	if p.stop != nil {
		p.stop()
		p.stop = nil
		log.Printf("punching paused while %s is connected", qc.RemoteAddr())
	}
	p.mu.Unlock()
	go func() {
		<-qc.Context().Done()
		p.mu.Lock()
		p.live--
		p.mu.Unlock()
		p.resume()
	}()
}

// attachment is the one client currently driving the session.
type attachment struct {
	w    *proto.Writer
	rwc  io.ReadWriteCloser
	done chan struct{} // closed when the client's handler returns
}

type server struct {
	bin        string
	args       []string
	restart    bool // -restart: start the program again for the next client after it exits
	done       chan int
	closeGrace time.Duration // see closeGraceEnv

	mu       sync.Mutex
	cmd      *exec.Cmd
	ptmx     *os.File
	client   *attachment // nil when no client is connected
	stopping bool        // the server is on its way out; refuses new clients
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

func (s *server) acceptQUIC(ctx context.Context, ln *quic.Listener, punch *puncher) {
	for {
		qc, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		// The handshake verified the client's fingerprint; its keepalives
		// hold the NAT mapping open from here until it leaves.
		if punch != nil {
			punch.track(qc)
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

	// Pump program output to whichever client is connected. This goroutine
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
		s.programExited(code)
	}()
	return nil
}

// programExited runs once the program is gone. It releases the pty, tells
// the connected client, and reports the exit to the main loop. Without
// -restart the server is now on its way out and admits no new client.
func (s *server) programExited(code int) {
	s.mu.Lock()
	c := s.client
	ptmx := s.ptmx
	s.cmd, s.ptmx = nil, nil
	if !s.restart {
		s.stopping = true
	}
	s.mu.Unlock()
	if ptmx != nil {
		_ = ptmx.Close()
	}
	if c != nil {
		_ = c.w.WriteExit(code)
		_ = c.rwc.Close() // graceful end of stream after the exit frame
	}
	s.done <- code
}

// beginShutdown marks the server as exiting: no new client is admitted and
// the next program exit is final even with -restart.
func (s *server) beginShutdown() {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
}

// willRestart reports whether a program exit should be followed by waiting
// for the next client instead of exiting the server.
func (s *server) willRestart() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restart && !s.stopping
}

// waitForClient gives the connected client's handler up to d to finish, so
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
// is running.
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

// detach drops c if it is the connected client.
func (s *server) detach(c *attachment) {
	s.mu.Lock()
	if s.client == c {
		s.client = nil
		log.Printf("client disconnected")
	}
	s.mu.Unlock()
}

// program returns the pty and process that att may drive, or nils once att
// is no longer the connected client or the program has exited. Handlers go
// through this so a lingering client can never reach a program started for
// its successor.
func (s *server) program(att *attachment) (*os.File, *exec.Cmd) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != att {
		return nil, nil
	}
	return s.ptmx, s.cmd
}

// resizePty applies a new window size and nudges the program to redraw even
// if the size is unchanged (most full-screen programs only repaint on an
// actual change).
func resizePty(ptmx *os.File, cmd *exec.Cmd, sz proto.Size, force bool) {
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
	if s.stopping {
		s.mu.Unlock()
		_ = w.WriteError("server shutting down")
		log.Printf("rejected %s: shutting down", remote)
		return
	}
	// A client whose program has already exited but which has not hung up
	// yet no longer holds the session; the new client takes it over.
	if s.client != nil && s.cmd != nil {
		s.mu.Unlock()
		_ = w.WriteError("session busy: another client is connected")
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
	log.Printf("client connected (%dx%d)", hello.Size.Cols, hello.Size.Rows)
	defer close(att.done)
	defer s.detach(att)

	if !fresh {
		if ptmx, cmd := s.program(att); ptmx != nil {
			resizePty(ptmx, cmd, hello.Size, true)
		}
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
			ptmx, _ := s.program(att)
			if ptmx == nil {
				return
			}
			if _, err := ptmx.Write(f.Payload); err != nil {
				return
			}
		case proto.TypeResize:
			sz, err := proto.ParseSize(f.Payload)
			if err != nil {
				break
			}
			ptmx, cmd := s.program(att)
			if ptmx == nil {
				return
			}
			resizePty(ptmx, cmd, sz, false)
		default:
			log.Printf("ignoring frame type %d", f.Type)
		}
	}
}
