// Package secure provides the identity and transport layer shared by the
// rokey serve and attach commands: ECDSA P-384 identity keys, SPKI fingerprints,
// mutual TLS 1.3 configs that pin the peer's fingerprint, and QUIC
// listen/dial with optional UDP hole punching.
//
// Adapted from github.com/josephcopenhaver/bareshare (MIT, see LICENSE in
// this directory).
package secure

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// AppName names the key directory (~/.<AppName>) and the ALPN protocol.
const AppName = "rokey"

// KeyDir returns the directory holding the persistent key pair.
func KeyDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "."+AppName)
}

// KeyPath returns the path of the persistent key pair.
func KeyPath() string {
	return filepath.Join(KeyDir(), "key.pem")
}

// GenerateEphemeralKey creates a new P-384 key pair in memory without
// persisting it.
func GenerateEphemeralKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral P-384 key: %w", err)
	}
	return key, nil
}

// LoadKeyFromFile loads a P-384 private key from the given PEM file.
func LoadKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}
	return parseKey(data, path)
}

func parseKey(data []byte, path string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM in %s", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w", path, err)
	}
	if key.Curve != elliptic.P384() {
		return nil, fmt.Errorf("key %s is not P-384: got %s", path, key.Curve.Params().Name)
	}
	return key, nil
}

// LoadOrCreateKey loads the persistent P-384 key pair from KeyPath,
// generating a new one if it doesn't exist.
func LoadOrCreateKey() (*ecdsa.PrivateKey, error) {
	path := KeyPath()

	if data, err := os.ReadFile(path); err == nil {
		key, err := parseKey(data, path)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "Used existing P-384 key pair in %s\n", path)
		return key, nil
	}

	key, err := writeNewKey()
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Generated new P-384 key pair in %s\n", path)
	return key, nil
}

// RotateKey generates a new P-384 key pair, replacing the existing one.
// It returns the new key and the old fingerprint (empty if there was no
// prior key).
func RotateKey() (newKey *ecdsa.PrivateKey, oldFP string, err error) {
	if data, err := os.ReadFile(KeyPath()); err == nil {
		if old, err := parseKey(data, KeyPath()); err == nil {
			oldFP = Fingerprint(&old.PublicKey)
		}
	}
	key, err := writeNewKey()
	if err != nil {
		return nil, "", err
	}
	return key, oldFP, nil
}

func writeNewKey() (*ecdsa.PrivateKey, error) {
	dir := KeyDir()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate P-384 key: %w", err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := secureKeyDir(dir); err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := writeKeyFile(filepath.Join(dir, "key.pem"), pemData); err != nil {
		return nil, err
	}
	return key, nil
}

// LoadKey resolves the -key-file flag convention shared by both commands:
//
//	""      generate an ephemeral key for this process only
//	"."     use (or create) the persistent key at KeyPath
//	<path>  load the key at that path
func LoadKey(keyFile string) (*ecdsa.PrivateKey, error) {
	switch keyFile {
	case "":
		key, err := GenerateEphemeralKey()
		if err != nil {
			return nil, err
		}
		fmt.Fprintln(os.Stderr, "Using ephemeral key pair (this process only)")
		return key, nil
	case ".":
		return LoadOrCreateKey()
	default:
		return LoadKeyFromFile(keyFile)
	}
}

// Fingerprint returns the base64url (no padding) encoded SHA-256 digest of
// the SPKI-encoded public key.
func Fingerprint(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(fmt.Errorf("marshal public key: %w", err))
	}
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// makeTLSCert creates an ephemeral self-signed certificate from the EC key.
func makeTLSCert(key *ecdsa.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// verifyPeerFingerprint checks that the peer's certificate contains the
// expected public key by comparing SHA-256 fingerprints of the SPKI encoding.
func verifyPeerFingerprint(rawCerts [][]byte, expectedFP string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("peer presented no certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse peer certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("peer key is not ECDSA P-384")
	}
	if pub.Curve != elliptic.P384() {
		return fmt.Errorf("peer key is ECDSA but not P-384: got curve %s", pub.Curve.Params().Name)
	}
	if fp := Fingerprint(pub); fp != expectedFP {
		return fmt.Errorf("peer fingerprint MISMATCH\n  expected: %s\n  got:      %s", expectedFP, fp)
	}
	return nil
}
