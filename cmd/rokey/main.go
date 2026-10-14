// Command rokey is a keyed remote terminal: `rokey serve` runs one terminal
// program inside a pseudo-terminal and lets exactly one client, identified
// by a pinned public key, connect to it with `rokey connect`. The program
// outlives the client; detach and reconnect at will.
//
//	rokey serve   [-peer-key <fp>] [-port N] [-restart] [-cmd program] [-- args...]
//	rokey connect [-peer-addr host:port] [-peer-key <fp>]
//	rokey show-key
//	rokey rotate-key
//	rokey version
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/josephcopenhaver/rokeydokey/internal/secure"
)

const (
	projectName = "rokeydokey"
)

func usage() {
	fmt.Fprintf(os.Stderr, `%s - a keyed remote terminal
(%s)

Usage:
  rokey serve      Host a terminal program and wait for one pinned client
  rokey connect    Connect this terminal to a rokey server
  rokey show-key   Print your persistent public key fingerprint
  rokey rotate-key Generate a new persistent key pair, replacing the old one
  rokey version    Print the version

Run "rokey serve -h" or "rokey connect -h" for flags.

Security:
  - ECDSA P-384 key pair for identity, stored in ~/.rokey/
  - Mutual TLS 1.3 over QUIC (UDP) with peer fingerprint verification
  - Key agreement pinned to X25519MLKEM768
  - NAT traversal with bilateral UDP hole punching
`, projectName, version)
}

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "serve":
		cmdServe(args)
	case "connect":
		cmdConnect(args)
	case "show-key":
		cmdShowKey()
	case "rotate-key":
		cmdRotateKey()
	case "version":
		fmt.Println(version)
	case "help", "-h", "-help", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "rokey: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func cmdShowKey() {
	key, err := secure.LoadOrCreateKey()
	if err != nil {
		fatal("load key: %v", err)
	}
	fmt.Printf("Your public key fingerprint:\n%s\n", secure.Fingerprint(&key.PublicKey))
}

func cmdRotateKey() {
	key, oldFP, err := secure.RotateKey()
	if err != nil {
		fatal("rotate key: %v", err)
	}
	if oldFP != "" {
		fmt.Printf("Old fingerprint: %s\n", oldFP)
	}
	fmt.Printf("New fingerprint: %s\nKey pair rotated. Share the new fingerprint with your peers.\n", secure.Fingerprint(&key.PublicKey))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rokey: "+format+"\n", args...)
	os.Exit(1)
}
