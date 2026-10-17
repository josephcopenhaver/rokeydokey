// Shell completion.
//
// All of the "what can go here?" logic lives in this file, in Go, behind the
// hidden `rokey --complete <shell> <cword> -- <word>...` protocol. The bash and
// zsh scripts printed by `rokey completion <shell>` are thin adapters: they
// hand rokey the words the user has typed and translate the answer into their
// own completion system. That is deliberate — a second copy of the argument
// grammar written in shell would drift from this one, and could only be tested
// through a shell.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// completeKind is the answer to "what does the word under the cursor accept?".
// It is the first line of --complete's output; the adapters switch on it.
type completeKind uint8

const _completeKindEncodedValues = "nonewordsfilescommands"

const (
	completeNone completeKind = iota // "none" - nothing can be offered

	completeWords    // "words" - the candidate lines that follow
	completeFiles    // "files" - whatever the shell calls a file
	completeCommands // "commands" - programs on PATH
)

func (k completeKind) String() string {

	switch k {
	case completeNone:
		return _completeKindEncodedValues[:4]
	case completeWords:
		return _completeKindEncodedValues[4:9]
	case completeFiles:
		return _completeKindEncodedValues[9:14]
	case completeCommands:
		return _completeKindEncodedValues[14:]
	}

	panic("completeKind.String: unknown kind")
}

// valueKind is what a flag's value, or a command's positional argument, accepts.
type valueKind uint8

const (
	valNothing valueKind = iota

	valWords   // one of a fixed set of words
	valFile    // a path
	valProgram // a program to run
	valShell   // a shell name for `rokey completion`
)

// candidate is one offered word and, for shells that show them, its description.
type candidate struct{ word, desc string }

// flagSpec is one flag of a command: its name without the dash, what its value
// accepts, and the one-line description zsh shows beside it.
type flagSpec struct {
	name    string
	desc    string    // no ':' (see completionCommands)
	boolean bool      // takes no value
	value   valueKind // what the value accepts, when there is one
	words   []string  // the choices when value is valWords
}

// commandSpec is one rokey command.
type commandSpec struct {
	name  string
	desc  string     // no ':' (see completionCommands)
	flags []flagSpec // nil for a command that takes no flags
	arg   valueKind  // what the single positional argument accepts, when there is one
	// passthrough marks a command whose words after `--`, or after the first
	// word that is not a flag, belong to the hosted program.
	passthrough bool
}

var (
	transportNames = []string{"quic", "tcp"}
	networkNames   = []string{"udp4", "udp6", "udp"}
)

// sharedFlags are the flags serve and connect define identically.
var sharedFlags = map[string]flagSpec{
	"transport": {name: "transport", desc: "quic (mutual TLS over UDP) or tcp (plaintext)", value: valWords, words: transportNames},
	"network":   {name: "network", desc: "quic bind network", value: valWords, words: networkNames},
	"key-file":  {name: "key-file", desc: "key file path ('.' is the persistent user key, '' ephemeral)", value: valFile},
}

// completionCommands is the catalogue --complete answers from: every command,
// every flag with what its value accepts, and the one-line description zsh
// shows beside each.
//
// Descriptions must not contain ':' — zsh's _describe uses it to separate a
// completion from its description. TestCompletionCatalogue_MatchesTheCommands
// enforces that, and that this catalogue, the help menu and the real flag
// sets all list the same commands and flags.
var completionCommands = []commandSpec{
	{name: "serve", desc: "host a terminal program and wait for one pinned client", passthrough: true, flags: []flagSpec{
		sharedFlags["transport"],
		{name: "listen", desc: "tcp address to listen on"},
		{name: "port", desc: "quic UDP port to listen on (0 = random)"},
		sharedFlags["network"],
		{name: "peer-key", desc: "expected client fingerprint"},
		sharedFlags["key-file"],
		{name: "peer-addr", desc: "client's public host and port to hole punch toward"},
		{name: "restart", desc: "keep serving after the program exits", boolean: true},
		{name: "cmd", desc: "program to host (its arguments follow --)", value: valProgram},
	}},
	{name: "connect", desc: "connect this terminal to a rokey server", flags: []flagSpec{
		sharedFlags["transport"],
		{name: "peer-addr", desc: "server host and port"},
		{name: "port", desc: "quic local UDP port (0 = random, fix it for punching)"},
		sharedFlags["network"],
		{name: "peer-key", desc: "expected server fingerprint"},
		sharedFlags["key-file"],
		{name: "detach-key", desc: "byte that detaches the client, or none"},
	}},
	{name: "show-key", desc: "print your persistent public key fingerprint"},
	{name: "rotate-key", desc: "generate a new persistent key pair, replacing the old one"},
	{name: "version", desc: "print the version"},
	{name: "completion", desc: "print tab completion for bash or zsh", arg: valShell},
}

// supportedShells are the shells `rokey completion` can actually emit an
// integration for. Order is the order they are offered in.
var supportedShells = []string{"bash", "zsh"}

// knownShells are shell names recognised well enough to be named back to the
// user in the "not supported" message.
//
// WHY: that message is printed as shell code the caller will eval, so the only
// caller-derived text it may ever contain is one of these fixed literals.
// Echoing the argument itself would let `rokey completion '"; rm -rf ~ #'`
// smuggle commands straight into the user's eval.
var knownShells = map[string]struct{}{
	"ash": {}, "bash": {}, "csh": {}, "dash": {}, "elvish": {}, "fish": {},
	"ksh": {}, "ksh93": {}, "mksh": {}, "nu": {}, "nushell": {}, "oil": {},
	"osh": {}, "powershell": {}, "pwsh": {}, "sh": {}, "tcsh": {}, "xonsh": {},
	"yash": {}, "zsh": {},
}

// errSilent marks a failure that has already been reported to the caller and
// needs nothing from main but the non-zero exit status.
var errSilent = errors.New("reported")

// cmdCompletion writes the shell integration for shell to stdout.
//
// An unsupported or missing shell still writes shell code, because the caller's
// `eval "$(rokey completion X)"` swallows stdout: emitting the complaint as
// code is the only way it reaches the terminal exactly once and leaves $?
// non-zero in the calling shell.
// WHY: everything printed for eval stays 7-bit ASCII. A stray multibyte
// character in text a shell is about to parse is a hazard that buys nothing.
func cmdCompletion(shell string) error {
	switch shell {
	case "bash":
		_, err := os.Stdout.WriteString(bashAdapter)
		return err
	case "zsh":
		// WHY: stripped rather than written without them, so that a comment
		// added to the script later cannot leak into the zsh output.
		_, err := os.Stdout.WriteString(stripComments(zshAdapter))
		return err
	}
	msg := "no shell specified"
	if shell != "" {
		msg = "unknown shell specified"
		if _, ok := knownShells[shell]; ok {
			msg = shell + " not supported"
		}
	}
	// WHY: `&& false`, never `&& exit 1`. This line is eval'd by the user's
	// interactive shell, where `exit` would close their terminal (or abort the
	// rest of a .bashrc). `false` leaves $? non-zero without either.
	if _, err := fmt.Fprintf(os.Stdout, ">&2 echo %q && false\n", msg); err != nil {
		return err
	}
	// WHY: errSilent, not errors.New(msg) — the eval'd echo above already
	// printed it, and rokey's own stderr line would show it to the user twice.
	return errSilent
}

// cmdComplete answers one completion request. args is
// `<shell> <cword> -- <word>...`: the words the user has typed and the index of
// the one under the cursor. Output is the completeKind on the first line
// followed by the candidates, one per line, as `word` or `word\tdescription`.
//
// Candidates are NOT filtered against the word under the cursor: both shells
// match the prefix themselves, and zsh's matching is the user's to configure.
func cmdComplete(args []string) error {
	if len(args) < 3 || args[2] != "--" {
		return fmt.Errorf("usage: %s --complete <shell> <cword> -- <word>...", toolName)
	}
	shell, words := args[0], args[3:]
	cword, err := strconv.Atoi(args[1])
	if err != nil || cword < 0 {
		return fmt.Errorf("invalid cursor word index %q", args[1])
	}
	// WHY: a shell that drops an empty trailing word still means "the cursor is
	// on a word that is not there yet".
	for len(words) <= cword {
		words = append(words, "")
	}

	kind, cands := completeAt(words, cword)
	var out bytes.Buffer
	out.WriteString(kind.String())
	out.WriteByte('\n')
	for _, c := range cands {
		out.WriteString(c.word)
		// Only zsh renders descriptions; bash would offer them as words.
		if c.desc != "" && shell == "zsh" {
			out.WriteByte('\t')
			out.WriteString(c.desc)
		}
		out.WriteByte('\n')
	}
	_, err = os.Stdout.Write(out.Bytes())
	return err
}

// completeAt decides what the word at index cword of words accepts. words is
// the whole command line as the shell split it, words[0] being the tool itself.
func completeAt(words []string, cword int) (completeKind, []candidate) {
	// WHY: bash splits words on COMP_WORDBREAKS, so `-key-file=PATH` arrives as
	// the three words `-key-file`, `=`, `PATH`. Dropping the bare `=` restores
	// the plain `-key-file PATH` shape this parser expects.
	typed := make([]string, 0, cword+1)
	for _, w := range words[:cword] {
		if w != "=" {
			typed = append(typed, w)
		}
	}
	// WHY: zsh does not split, so there the cursor can sit on the whole
	// `-key-file=PA`. Treating the flag half as already typed puts the cursor
	// on the value, exactly as if a space had been typed instead of the `=`;
	// the zsh adapter strips that prefix before it offers anything.
	if cur := words[cword]; strings.HasPrefix(cur, "-") {
		if i := strings.IndexByte(cur, '='); i > 0 {
			typed = append(typed, cur[:i])
		}
	}

	if len(typed) <= 1 {
		return completeWords, commandCandidates()
	}
	spec := specFor(typed[1])
	if spec == nil {
		return completeNone, nil
	}
	if spec.flags != nil {
		return spec.completeFlags(typed[2:])
	}
	// A command without flags takes at most one positional argument.
	if len(typed) == 2 {
		return valueCompletion(spec.arg, nil)
	}
	return completeNone, nil
}

// completeFlags decides what the cursor accepts after a flag command, given the
// words typed after the command name. It follows the standard library's flag
// parser: `-name value`, `-name=value` and `--name` all spell a flag, a bool
// flag takes no value, and parsing stops at `--` or the first non-flag word.
func (c *commandSpec) completeFlags(rest []string) (completeKind, []candidate) {
	used := map[string]bool{}
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		if w == "--" || w == "-" || !strings.HasPrefix(w, "-") {
			// Flag parsing is over. What follows is the hosted program's own
			// arguments for serve; connect accepts nothing there.
			if c.passthrough {
				return completeFiles, nil
			}
			return completeNone, nil
		}
		name, _, inline := strings.Cut(strings.TrimLeft(w, "-"), "=")
		f := c.flag(name)
		if f == nil {
			// The flag package would reject this line; guessing past it would
			// only suggest an invocation rokey rejects.
			return completeNone, nil
		}
		used[f.name] = true
		if f.boolean || inline {
			continue
		}
		if i == len(rest)-1 {
			// The cursor is on this flag's value.
			return valueCompletion(f.value, f.words)
		}
		i++ // skip the value, whatever it looks like
	}

	// The cursor is on a flag position: offer the flags not yet given.
	var cands []candidate
	for _, f := range c.flags {
		if !used[f.name] {
			cands = append(cands, candidate{"-" + f.name, f.desc})
		}
	}
	if c.passthrough {
		cands = append(cands, candidate{"--", "arguments for the hosted program follow"})
	}
	return completeWords, cands
}

func (c *commandSpec) flag(name string) *flagSpec {
	for i := range c.flags {
		if c.flags[i].name == name {
			return &c.flags[i]
		}
	}
	return nil
}

// valueCompletion translates what a value accepts into a directive.
func valueCompletion(kind valueKind, words []string) (completeKind, []candidate) {
	switch kind {
	case valWords:
		return completeWords, wordCandidates(words)
	case valFile:
		return completeFiles, nil
	case valProgram:
		return completeCommands, nil
	case valShell:
		return completeWords, wordCandidates(supportedShells)
	}
	// valNothing: a port, an address, a fingerprint. Offering nothing is the
	// honest answer.
	return completeNone, nil
}

func wordCandidates(words []string) []candidate {
	cands := make([]candidate, 0, len(words))
	for _, w := range words {
		cands = append(cands, candidate{w, ""})
	}
	return cands
}

func specFor(name string) *commandSpec {
	for i := range completionCommands {
		if completionCommands[i].name == name {
			return &completionCommands[i]
		}
	}
	return nil
}

// commandCandidates is every command, in catalogue order.
func commandCandidates() []candidate {
	out := make([]candidate, 0, len(completionCommands))
	for _, c := range completionCommands {
		out = append(out, candidate{c.name, c.desc})
	}
	return out
}

// stripComments removes whole-line shell comments and collapses the runs of
// blank lines they leave behind. A '#' that is part of the shell code — the
// ${reply#*...} of a parameter expansion — is never touched, because only a
// line whose first non-blank character is '#' is a comment.
func stripComments(src string) string {
	var out strings.Builder
	blank := true // WHY: seeded true so leading blank lines go too
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "" {
			if blank {
				continue
			}
			blank = true
		} else {
			blank = false
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return strings.TrimRight(out.String(), "\n") + "\n"
}

// bashAdapter asks rokey what fits at the cursor and feeds the answer to
// readline. Written for bash 3.2, the newest bash Apple ships, and assuming
// nothing from the bash-completion package beyond using it where it is loaded.
const bashAdapter = `# rokey tab completion. Install with:
#
#     eval "$(rokey completion bash)"
#
# or, better, in ~/.bashrc:
#
#     . <(rokey completion bash)

_rokey_filedir () {
    if declare -F _filedir >/dev/null 2>&1; then
        _filedir "$@"
        return
    fi
    COMPREPLY=( $(compgen -f -- "$cur") )
    # compopt is bash 4+; on bash 3.2 the error is discarded and the
    # completions are merely shown with their full path.
    compopt -o filenames 2>/dev/null || true
}

_rokey () {
    local cur reply directive cands
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    # bash splits words on COMP_WORDBREAKS, so the cursor can land on the bare
    # "=" of "-key-file=PATH"; that is a prefix of nothing, not a word to match.
    if [ "$cur" = "=" ]; then
        cur=""
    fi

    # stderr is dropped so a failure can never scribble over the prompt.
    reply=$(rokey --complete bash "$COMP_CWORD" -- "${COMP_WORDS[@]}" 2>/dev/null) || return
    directive=${reply%%$'\n'*}
    cands=${reply#*$'\n'}
    if [ "$cands" = "$reply" ]; then
        cands=""
    fi

    case $directive in
        words)    COMPREPLY=( $(compgen -W "$cands" -- "$cur") );;
        commands) COMPREPLY=( $(compgen -c -- "$cur") );;
        files)    _rokey_filedir;;
    esac
}

complete -F _rokey rokey
`

// zshAdapter is the same question asked from zsh, answered through the zsh
// completion system so candidates keep their descriptions and the user's own
// matcher and menu settings apply.
const zshAdapter = `
_rokey () {
    local cur directive
    local -a reply cands

    cur=${words[CURRENT]}

    # stderr is dropped so a failure can never scribble over the prompt.
    # CURRENT is 1-based, cword is not.
    reply=( ${(f)"$(rokey --complete zsh $(( CURRENT - 1 )) -- "${words[@]}" 2>/dev/null)"} )
    (( $#reply )) || return 1
    directive=$reply[1]
    cands=( ${reply[2,-1]//$'\t'/:} )

    # zsh keeps "-key-file=PATH" as one word; rokey has answered for the value,
    # so match and insert only the part after the "=".
    if [[ $cur == -*=* ]]; then
        compset -P '-*='
    fi

    case $directive in
        words)    _describe -t rokey rokey cands ;;
        commands) _command_names -e ;;
        files)    _files ;;
        # WHY: a plain "return 1" here would leave zsh to report a bare "no
        # matches"; saying so out loud distinguishes "rokey has nothing to
        # offer at this position" from "your prefix matched nothing".
        none)     _message -e rokey "no completion here" ; return 1 ;;
        *)        return 1 ;;
    esac
}

if (( $+functions[compdef] )); then
    compdef _rokey rokey
else
    >&2 echo "rokey: completion needs compinit; source this after compinit in ~/.zshrc"
fi
`
