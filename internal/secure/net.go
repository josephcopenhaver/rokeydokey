package secure

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
)

// punchPayload is sent toward the peer to open a NAT mapping. Its first byte
// has bits 6 and 7 clear (< 0x40) so quic-go rejects it immediately as a
// non-QUIC packet instead of queuing it for processing.
const punchPayload = "\x07rkpunch"

// Interactive sessions notice a dead peer faster than a bulk transfer
// would want to.
const (
	idleTimeout     = 15 * time.Second
	keepAlivePeriod = 5 * time.Second
)

// ValidNetwork verifies a -network flag value before any I/O starts.
func ValidNetwork(network string) error {
	switch network {
	case "udp4", "udp6", "udp":
		return nil
	}
	return fmt.Errorf("invalid -network %q: must be udp4, udp6, or udp", network)
}

// resolveUDPAddr exists because net.ResolveUDPAddr does not take a context.
func resolveUDPAddr(ctx context.Context, network, remoteAddr string) (*net.UDPAddr, error) {
	resolver := net.DefaultResolver

	host, service, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, err
	}
	port, err := resolver.LookupPort(ctx, network, service)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return &net.UDPAddr{Port: port}, nil
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if ip := net.IP(addr.AsSlice()).To16(); ip != nil {
			// mirrors net.ipv4only and net.ipv6only, which reject IPv4-mapped
			switch network {
			case "udp4":
				if ip.To4() == nil {
					return nil, &net.AddrError{Err: "no suitable address found", Addr: host}
				}
			case "udp6":
				if ip.To4() != nil {
					return nil, &net.AddrError{Err: "no suitable address found", Addr: host}
				}
			}
			return &net.UDPAddr{IP: ip, Port: port, Zone: addr.Zone()}, nil
		}
	}

	var ipNet string
	switch network {
	case "udp4":
		ipNet = "ip4"
	case "udp6":
		ipNet = "ip6"
	default:
		ipNet = "ip"
	}

	ipAddrs, err := resolver.LookupNetIP(ctx, ipNet, host)
	if err != nil {
		return nil, err
	}
	if len(ipAddrs) == 0 {
		return nil, &net.AddrError{Err: "no suitable address found", Addr: host}
	}

	// net.ResolveUDPAddr prefers IPv4 when the network is "udp" and the host
	// is not an IPv6 literal. LookupNetIP returns RFC 6724 order instead, so
	// keep the old preference so the punch target matches the family that
	// the peer dials.
	ipAddr := ipAddrs[0].Unmap()
	if ipNet == "ip" && !ipAddr.Is4() {
		for _, v := range ipAddrs[1:] {
			v = v.Unmap()
			if v.Is4() {
				ipAddr = v
				break
			}
		}
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ipAddr, uint16(port))), nil
}

// Transport is a UDP socket wrapped by a QUIC transport. One Transport can
// listen, dial, and punch, all from the same port, so the NAT mapping a
// punch opens is the one the session flows through.
type Transport struct {
	conn *net.UDPConn
	tr   *quic.Transport
}

// NewTransport binds a UDP socket on the given network and local port
// (0 picks a random port).
func NewTransport(network string, localPort int) (*Transport, error) {
	if err := ValidNetwork(network); err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: localPort})
	if err != nil {
		return nil, fmt.Errorf("bind UDP port %d: %w", localPort, err)
	}
	return &Transport{conn: conn, tr: &quic.Transport{Conn: conn}}, nil
}

// LocalPort returns the bound UDP port.
func (t *Transport) LocalPort() int {
	return t.conn.LocalAddr().(*net.UDPAddr).Port
}

// Close shuts down the transport and its socket.
func (t *Transport) Close() error {
	err := t.tr.Close()
	if cerr := t.conn.Close(); err == nil {
		err = cerr
	}
	return err
}

// StartPunch sends a small non-QUIC datagram toward remoteAddr every 200ms
// until the returned function is called. Both peers must use fixed ports
// and know each other's public address.
func (t *Transport) StartPunch(ctx context.Context, network, remoteAddr string) (stop func(), err error) {
	target, err := resolveUDPAddr(ctx, network, remoteAddr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = t.tr.WriteTo([]byte(punchPayload), target)
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}, nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  idleTimeout,
		KeepAlivePeriod: keepAlivePeriod,
	}
}

func baseTLSConfig(key *ecdsa.PrivateKey, expectedPeerFP string) (*tls.Config, error) {
	cert, err := makeTLSCert(key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // the only PQ-hybrid Go ships today
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerFingerprint(rawCerts, expectedPeerFP)
		},
		NextProtos: []string{AppName},
		MinVersion: tls.VersionTLS13,
	}, nil
}

// Listen starts a QUIC listener that requires a client certificate and
// accepts only a client whose fingerprint equals expectedPeerFP.
func (t *Transport) Listen(key *ecdsa.PrivateKey, expectedPeerFP string) (*quic.Listener, error) {
	tlsConf, err := baseTLSConfig(key, expectedPeerFP)
	if err != nil {
		return nil, err
	}
	tlsConf.ClientAuth = tls.RequireAnyClientCert
	return t.tr.Listen(tlsConf, quicConfig())
}

// Dial connects to remoteAddr, presenting key as the client identity and
// accepting only a server whose fingerprint equals expectedPeerFP.
func (t *Transport) Dial(ctx context.Context, timeout time.Duration, network, remoteAddr string, key *ecdsa.PrivateKey, expectedPeerFP string) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tlsConf, err := baseTLSConfig(key, expectedPeerFP)
	if err != nil {
		return nil, err
	}
	tlsConf.InsecureSkipVerify = true // self-signed; verified via fingerprint above

	addr, err := resolveUDPAddr(ctx, network, remoteAddr)
	if err != nil {
		return nil, err
	}
	return t.tr.Dial(ctx, addr, tlsConf, quicConfig())
}
