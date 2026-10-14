# rokeydokey

A keyed remote terminal. `rokey serve` runs one terminal program inside a
pseudo-terminal and lets exactly one client, identified by a pinned public
key, connect to it with `rokey connect`. The program outlives the client:
detach, reconnect, pick up where you left off. The server exits when the
program exits, unless `-restart` tells it to wait for the next client and
start the program again.

Think of it as the pty channel of SSH on its own, with [dtach][dtach]-style
detach and reconnect, carried over QUIC with mutual TLS 1.3 and ECDSA P-384
identity pinning borrowed from [bareshare][bareshare]. No user accounts, no
shell integration, no port forwarding, no multiplexing yet. Point it at a
shell, tmux, an editor, or anything else that runs in a terminal.

```
┌───────────────┐  keystrokes, resize   ┌─────────────┐  pty   ┌───────────┐
│ rokey connect │ ────────────────────▶ │ rokey serve │ ─────▶ │  program  │
│  (raw tty)    │ ◀──────────────────── │             │ ◀───── │ shell,tmux│
└───────────────┘    screen bytes       └─────────────┘        └───────────┘
               QUIC + mutual TLS (or plain TCP)
```

[dtach]: https://github.com/crigler/dtach
[bareshare]: https://github.com/josephcopenhaver/bareshare

## Layout

- `cmd/rokey` — the one binary. `serve.go` binds UDP (or TCP), starts the
  program on first connect, and bridges the pty to the one connected client.
  `connect.go` puts the local terminal in raw mode, forwards keys and
  window-size changes, and writes the program's output to the screen.
- `internal/secure` — identity keys, fingerprints, pinned mutual-TLS configs,
  QUIC listen/dial, and UDP hole punching. Adapted from bareshare (MIT).
- `internal/proto` — the framing on the wire (type byte, length, payload).
- `tools/` — end-to-end tests for both transports, driving `/bin/sh`.

## Build

Requires Go 1.27. `mise.toml` pins the toolchain; with [mise](https://mise.jdx.dev)
installed, `mise install` fetches it and the commands below pick it up.

```
make build        # bin/rokey
make e2e          # end-to-end tests: tcp (python) and quic (go test -tags e2e)
```

## Quick start (QUIC, the default)

Both sides identify themselves with a P-384 key pair. Before connecting, each
side needs the other's fingerprint (SHA-256 of the SPKI public key,
base64url). Exchange them out of band. A mismatch on either side aborts the
handshake.

**On the viewer's machine**, print the client's persistent fingerprint:

```
rokey show-key
```

**On the host**, start the server pinned to that client. With no `-cmd` it
hosts your `$SHELL`:

```
rokey serve -port 7000 -peer-key <client-fingerprint>
```

It prints its own fingerprint. By default the server key is ephemeral, so
this fingerprint is fresh each run. Send it to the viewer.

**Back on the viewer's machine:**

```
rokey connect -peer-addr host:7000 -peer-key <server-fingerprint>
```

`Ctrl-]` detaches and leaves the program running; connecting again picks the
session back up. Change the detach key with `-detach-key 0x1c` (any byte) or
disable it with `-detach-key none`.

Ctrl-C on the server sends the program SIGTERM and exits the server once the
program is gone, `-restart` or not; a second Ctrl-C kills the program.

## Hosting a program

`-cmd` names the program; anything after `--` is passed to it as arguments.
A bare name is looked up on `$PATH`.

```
rokey serve -peer-key <fp> -restart -cmd tmux -- new-session -A -s main
rokey serve -peer-key <fp> -cmd micro -- notes.txt
rokey serve -peer-key <fp> -cmd htop
rokey serve -peer-key <fp> -cmd /bin/zsh -- -l
```

tmux is the natural pairing, and the reason `-restart` exists. tmux's own
detach (`Ctrl-b d`) ends the tmux client, which is the hosted program, so
without `-restart` the server would exit with it. With `-restart` the server
keeps listening, and the next `rokey connect` starts a fresh tmux client that
`new-session -A` re-attaches to your windows. The tmux server and everything
in it keeps running in between.

Prefer `Ctrl-b d` over `Ctrl-]` with tmux. A fresh tmux client initializes
your terminal from scratch for the `TERM` and size you connect with:
alternate screen, keypad and mouse modes, a full redraw. Reconnecting to a
tmux client that is still running only nudges it with a size change, which
redraws content but does not replay that terminal setup, so a viewer on a
different terminal than the first one can see glitches until something
forces a full redraw. The viewer's machine does not need tmux installed; the
host needs a terminfo entry for the viewer's `TERM`.

Full-screen programs (tmux, editors, htop) repaint on reconnect because the
server nudges them with a window-size change. A plain shell doesn't repaint;
press Enter for a fresh prompt.

## Plain TCP, same machine

For a local or already-tunneled link, skip the keys:

```
rokey serve   -transport tcp -listen 127.0.0.1:7000 -cmd tmux -- new-session -A -s main
rokey connect -transport tcp -peer-addr 127.0.0.1:7000
```

There is no authentication or encryption on this path.

## Key management

The persistent key pair lives in `~/.rokey/key.pem` (mode `0600`, owner-only
ACL on Windows) and is created on first use.

```
rokey show-key      # print the persistent fingerprint
rokey rotate-key    # new key pair; old fingerprint printed for reference
```

`serve` and `connect` take `-key-file` with bareshare's convention:

| Value | Behavior |
|---|---|
| `""` | Ephemeral key for this process only. Never written to disk. |
| `.` | Persistent key from `~/.rokey/key.pem`. |
| `<path>` | Key at that path. |

Defaults differ by role. **serve** defaults to ephemeral: its fingerprint is
fresh per run, so a viewer must obtain it right before connecting and nothing
persists afterwards. **connect** defaults to persistent, so a server can be
pinned to it once. Pass `-key-file .` to `serve` if you want a stable server
fingerprint across restarts.

## NAT traversal

For peers behind NAT, use bilateral UDP hole punching. Both sides must use a
fixed port and know each other's public address. Each side names the other
with `-peer-addr`.

Server:

```
rokey serve -port 7000 -peer-addr <client-public-ip:7001> -peer-key <fp>
```

Client:

```
rokey connect -port 7001 -peer-addr <server-public-ip:7000> -peer-key <fp>
```

The server punches toward the client from the same UDP socket QUIC uses, so
the NAT mapping it opens is the one the session flows through. Punching
pauses while a client is connected, since the session's own keepalives hold
the mapping open, and resumes as soon as the connection ends so the client
can come back after its NAT has forgotten the previous session.

## Network selection

`-network` on either side picks the address family: `udp4` (default), `udp6`,
or `udp` for dual-stack. Any other value is rejected at startup. Both peers
must be reachable over the family in use.

## Flags

| command | flag | default | meaning |
|---|---|---|---|
| both | `-transport` | `quic` | `quic` (mutual TLS over UDP) or `tcp` (plaintext) |
| both | `-network` | `udp4` | `udp4`, `udp6`, or `udp` |
| both | `-peer-key` | | expected peer fingerprint; required for quic |
| both | `-key-file` | serve `""`, connect `.` | ephemeral, persistent, or a path |
| both | `-port` | `0` (random) | serve: UDP port to listen on; connect: local UDP port. Fix both for punching |
| serve | `-cmd` | `$SHELL`, else `/bin/sh` | program to host; its args follow `--` |
| serve | `-restart` | off | keep serving after the program exits; the next client starts it again |
| serve | `-peer-addr` | | client's public `host:port` to punch toward |
| serve | `-listen` | `127.0.0.1:7000` | tcp bind address |
| connect | `-peer-addr` | `127.0.0.1:7000` | server `host:port` |
| connect | `-detach-key` | `0x1d` (Ctrl-]) | byte that detaches |

## Environment

| variable | default | meaning |
|---|---|---|
| `ROKEY_CLOSE_GRACE` | `3s` | How long `serve` waits for a departing client to read its final frame (busy, error, or exit) and hang up before closing the connection. QUIC discards unsent stream data on close, so `0` risks losing that frame. Also bounds how long the server lingers after the program exits when it is not restarting. Any Go duration, e.g. `500ms`. |

## Security model

- **Identity:** ECDSA P-384 key pair. Fingerprint is SHA-256 of the SPKI
  encoding, base64url without padding.
- **Authentication:** mutual TLS certificate pinning. Each side verifies the
  other's fingerprint during the handshake. No CA, no trust-on-first-use.
- **Encryption:** TLS 1.3 over QUIC, key agreement pinned to X25519MLKEM768.
  Session keys are ephemeral, so recorded traffic stays unreadable even if a
  long-term key leaks later.
- **Trust anchor:** the out-of-band channel you exchange fingerprints over.
- **What the key grants:** the hosted program, running as the user who
  started the server, with that user's environment. A detached session is a
  live program waiting for whoever holds the pinned client key. With
  `-restart`, so is a server whose program has exited. Treat the client key
  like an SSH private key.

A client with the wrong key completes its half of the TLS 1.3 handshake
before the server checks its certificate, so the rejection shows up as the
connection dying immediately afterwards rather than as a dial error.

## Protocol

Every message on the stream is `type:u8 length:u32be payload`.

| type | dir | payload |
|---|---|---|
| 0 Data | both | raw terminal bytes |
| 1 Hello | client→server | `cols:u16 rows:u16 TERM` |
| 2 Resize | client→server | `cols:u16 rows:u16` |
| 3 Exit | server→client | `code:i32` |
| 4 Error | server→client | message |

Over QUIC this rides one bidirectional stream per connection. Idle timeout is
15s with 5s keepalives, so a vanished client frees the session for the next
one within that window.

## Notes

- The pty master is switched to blocking mode before use. Go's kqueue-based
  poller does not reliably wake for pty masters on macOS.
- On reconnect the server sets the pty one column narrower, then back, with a
  SIGWINCH each time. Most full-screen programs only repaint on an actual
  size change.
- The client sends its `TERM`; the host needs a terminfo entry for it. The
  program is started with the `TERM` of the client that starts it; later
  clients inherit that choice until the program exits.
