package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"iter"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"

	tbdd "github.com/josephcopenhaver/tbdd-go"
)

// These tests drive the completion commands end to end. They are serial by
// necessity: every test pins HOME with t.Setenv and captureStdout swaps the
// process-wide os.Stdout.

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// realHome is $HOME as the process started, before any test swapped it. The Go
// toolchain keeps its module and build caches under it.
var realHome = os.Getenv("HOME")

// captureStdout runs fn with os.Stdout redirected and returns what was written.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		io.Copy(&b, r)
		done <- b.String()
	}()
	runErr := fn()
	w.Close()
	os.Stdout = orig
	return <-done, runErr
}

// isolatedHome points HOME at a scratch directory and returns the key
// directory rokey would use under it, so a test can prove completion never
// touched it. Completion must never create or read a key: a tab press that
// generated ~/.rokey/key.pem would be a surprising side effect.
func isolatedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return filepath.Join(home, ".rokey")
}

// completeLines asks rokey what fits at word cword of words and returns the
// directive and the candidate lines, exactly as a shell adapter would see them.
func completeLines(t *testing.T, shell string, cword int, words ...string) (string, []string) {
	t.Helper()
	args := append([]string{shell, strconv.Itoa(cword), "--"}, words...)
	out, err := captureStdout(t, func() error { return cmdComplete(args) })
	if err != nil {
		t.Fatalf("--complete %v: %v", words, err)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("--complete %v produced no directive: %q", words, out)
	}
	return lines[0], lines[1:]
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// shellPath locates a shell, skipping the test where there is none.
func shellPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not on PATH", name)
	}
	return p
}

// syntaxCheck fails the test if the named shell will not parse src.
func syntaxCheck(t *testing.T, shell, src string) {
	t.Helper()
	sh := shellPath(t, shell)
	f := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sh, "-n", f).CombinedOutput(); err != nil {
		t.Errorf("%s rejected the emitted script: %v\n%s\n--- script ---\n%s", shell, err, out, src)
	}
}

// buildRokey compiles this package into a temp directory and returns the
// binary's directory, so a shell adapter under test can call the real tool.
func buildRokey(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}
	dir := t.TempDir()
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, toolName), ".")
	// WHY: the surrounding test has pointed HOME at a scratch directory; left
	// alone the toolchain would rebuild a whole read-only module cache inside
	// it, which is slow and then impossible to clean up.
	cmd.Env = append(os.Environ(), "HOME="+realHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return dir
}

// fileMarker is the only file in the directory the adapters are driven from,
// so a "files" directive has exactly one right answer.
const fileMarker = "marker-file.txt"

// driveShell writes the integration for shell plus a driver script that fakes
// the shell's completion state, runs it, and returns what the adapter offered.
func driveShell(t *testing.T, shell, binDir, driver string, args []string) []string {
	t.Helper()
	sh := shellPath(t, shell)
	script, err := captureStdout(t, func() error { return cmdCompletion(shell) })
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	scriptPath := filepath.Join(tmp, "integration")
	driverPath := filepath.Join(tmp, "driver")
	for p, body := range map[string]string{scriptPath: script, driverPath: driver} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(sh, append([]string{driverPath, scriptPath}, args...)...)
	// WHY: the "files" directive completes the working directory, so the test
	// needs one whose contents it chose.
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, fileMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd.Dir = cwd
	cmd.Env = []string{
		"PATH=" + binDir + string(os.PathListSeparator) + "/usr/bin:/bin",
		"HOME=" + os.Getenv("HOME"),
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("driving %s over %q: %v", shell, args, err)
	}
	s := strings.TrimSuffix(string(out), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// ---------------------------------------------------------------------------
// the catalogue
// ---------------------------------------------------------------------------

// TestCompletionCatalogue_MatchesTheCommands keeps the completion catalogue
// from drifting away from the program: every command it offers is in the help
// menu, and for serve and connect its flags are exactly the flags the real
// flag.FlagSet defines.
func TestCompletionCatalogue_MatchesTheCommands(t *testing.T) {
	type R struct {
		menu     string
		flagSets map[string]map[string]bool // command -> flag names the program defines
	}

	tbdd.GWT(
		struct{}{},
		"the help menu, the flag sets and the completion catalogue as they are compiled in",
		func(t *testing.T, tc *struct{}) {},
		"the commands and flags are collected from the program",
		func(t *testing.T, tc struct{}) R {
			var menu bytes.Buffer
			usageTo(&menu)
			r := R{menu.String(), map[string]map[string]bool{}}
			serveFS, _ := serveFlagSet()
			connectFS, _ := connectFlagSet()
			for name, fs := range map[string]*flag.FlagSet{"serve": serveFS, "connect": connectFS} {
				r.flagSets[name] = map[string]bool{}
				fs.VisitAll(func(f *flag.Flag) { r.flagSets[name][f.Name] = true })
			}
			return r
		},
		"every command is documented, every flag completes, every completable flag exists, and descriptions are zsh-safe",
		func(t *testing.T, tc struct{}, r R) {
			for _, c := range completionCommands {
				if !strings.Contains(r.menu, "\n  "+toolName+" "+c.name+" ") {
					t.Errorf("command %q can be completed but is not in the help menu", c.name)
				}
				// WHY: zsh's _describe splits a candidate from its description
				// on the first ':', so one in the text would truncate it.
				if strings.Contains(c.desc, ":") {
					t.Errorf("description of %s contains a colon: %q", c.name, c.desc)
				}
				if c.desc == "" {
					t.Errorf("%s has no description", c.name)
				}
				defined, hasFlags := r.flagSets[c.name]
				if hasFlags != (c.flags != nil) {
					t.Errorf("%s: the program defines flags = %v, the catalogue has flags = %v", c.name, hasFlags, c.flags != nil)
				}
				for _, f := range c.flags {
					if !defined[f.name] {
						t.Errorf("%s -%s can be completed but the program does not define it", c.name, f.name)
					}
					if strings.Contains(f.desc, ":") {
						t.Errorf("description of %s -%s contains a colon: %q", c.name, f.name, f.desc)
					}
					if f.desc == "" {
						t.Errorf("%s -%s has no description", c.name, f.name)
					}
					if f.value == valWords && len(f.words) == 0 {
						t.Errorf("%s -%s offers a fixed set of words but names none", c.name, f.name)
					}
				}
				for name := range defined {
					if c.flag(name) == nil {
						t.Errorf("%s -%s exists but cannot be completed", c.name, name)
					}
				}
			}
			for _, name := range []string{"serve", "connect"} {
				if specFor(name) == nil {
					t.Errorf("%s is missing from the catalogue", name)
				}
			}
		},
	).Run(t)
}

// ---------------------------------------------------------------------------
// the emitted scripts
// ---------------------------------------------------------------------------

// TestCompletionScript_InstallsCompletion: for each supported shell, the
// emitted integration parses in that shell and registers the completion the
// way that shell expects, without touching the key directory.
func TestCompletionScript_InstallsCompletion(t *testing.T) {
	type TC struct {
		keyDir string
		shell  string
		wants  []string
		// comments records whether this shell's integration may carry them.
		// zsh's must not: it is eval'd, and a shell that does not treat '#' as
		// a comment there parses the lines as code instead, which can leave
		// _rokey undefined and tab completion silently dead.
		comments bool
	}
	type R struct {
		stdout string
		err    error
	}

	b := tbdd.GWT(
		TC{
			shell:    "bash",
			wants:    []string{"complete -F _rokey rokey", `--complete bash "$COMP_CWORD"`},
			comments: true,
		},
		"a home directory with no key in it",
		func(t *testing.T, tc *TC) { tc.keyDir = isolatedHome(t) },
		"the integration for that shell is printed",
		func(t *testing.T, tc TC) R {
			out, err := captureStdout(t, func() error { return cmdCompletion(tc.shell) })
			return R{out, err}
		},
		"it parses, installs the completion, and creates nothing",
		func(t *testing.T, tc TC, r R) {
			if r.err != nil {
				t.Fatal(r.err)
			}
			for _, want := range append([]string{"_" + toolName + " () {"}, tc.wants...) {
				if !strings.Contains(r.stdout, want) {
					t.Errorf("%s integration is missing %q", tc.shell, want)
				}
			}
			// WHY: this is eval'd by an interactive shell; an `exit` anywhere
			// in it would close the user's terminal.
			if strings.Contains(r.stdout, "exit") {
				t.Errorf("%s integration contains an exit", tc.shell)
			}
			if _, err := os.Lstat(tc.keyDir); err == nil {
				t.Errorf("completion %s created the key directory", tc.shell)
			}
			for i, line := range strings.Split(r.stdout, "\n") {
				if !tc.comments && strings.HasPrefix(strings.TrimSpace(line), "#") {
					t.Errorf("%s integration line %d is a comment: %q", tc.shell, i+1, line)
				}
				// WHY: this text is about to be parsed by a shell; a stray
				// multibyte character there is a hazard that buys nothing.
				for _, r := range line {
					if r > unicode.MaxASCII {
						t.Errorf("%s integration line %d is not ASCII: %q", tc.shell, i+1, line)
						break
					}
				}
			}
			syntaxCheck(t, tc.shell, r.stdout)
		},
	)
	b.Variants = func(t *testing.T, tc TC) iter.Seq[tbdd.TestVariant[TC]] {
		return func(yield func(tbdd.TestVariant[TC]) bool) {
			v := tc
			v.shell, v.comments = "zsh", false
			v.wants = []string{"compdef _rokey rokey", `--complete zsh $(( CURRENT - 1 ))`, "compinit"}
			yield(tbdd.TestVariant[TC]{TC: v, Kind: "zsh"})
		}
	}
	b.Run(t)
}

// TestCompletion_UnsupportedShellIsEvalSafe: every input but a supported shell
// writes its complaint as shell code — so `eval "$(...)"` shows it once and
// leaves $? non-zero — and never emits an `exit`, which would close the
// caller's shell. The name is echoed back only when rokey recognises it as a
// shell, so a hostile argument cannot smuggle itself into the eval.
func TestCompletion_UnsupportedShellIsEvalSafe(t *testing.T) {
	type TC struct {
		keyDir string
		shell  string
		want   string
	}
	type R struct {
		stdout string
		err    error
	}

	b := tbdd.GWT(
		TC{shell: "fish", want: "fish not supported"},
		"a home directory with no key in it",
		func(t *testing.T, tc *TC) { tc.keyDir = isolatedHome(t) },
		"the integration is asked for in that shell",
		func(t *testing.T, tc TC) R {
			out, err := captureStdout(t, func() error { return cmdCompletion(tc.shell) })
			return R{out, err}
		},
		"stdout is an eval-safe complaint, the command fails silently, and nothing is created",
		func(t *testing.T, tc TC, r R) {
			if r.err != errSilent {
				t.Fatalf("error: got %v, want errSilent", r.err)
			}
			if want := fmt.Sprintf(">&2 echo %q && false\n", tc.want); r.stdout != want {
				t.Errorf("stdout mismatch:\n got: %q\nwant: %q", r.stdout, want)
			}
			if strings.Contains(r.stdout, "exit") {
				t.Errorf("an unsupported shell emitted an exit: %q", r.stdout)
			}
			if strings.Contains(r.stdout, "rm ") {
				t.Errorf("the argument reached the emitted shell code: %q", r.stdout)
			}
			if _, err := os.Lstat(tc.keyDir); err == nil {
				t.Errorf("completion %q created the key directory", tc.shell)
			}
			syntaxCheck(t, "bash", r.stdout)
		},
	)
	b.Variants = func(t *testing.T, tc TC) iter.Seq[tbdd.TestVariant[TC]] {
		cases := []struct{ kind, shell, want string }{
			{"no shell given", "", "no shell specified"},
			{"a real shell with no integration yet", "csh", "csh not supported"},
			{"a name that is not a shell at all", "frobnicate", "unknown shell specified"},
			{"an argument trying to inject shell code", `"; rm -rf ~ #`, "unknown shell specified"},
			{"a supported shell spelled with the wrong case", "ZSH", "unknown shell specified"},
		}
		return func(yield func(tbdd.TestVariant[TC]) bool) {
			for _, c := range cases {
				v := tc
				v.shell, v.want = c.shell, c.want
				if !yield(tbdd.TestVariant[TC]{TC: v, Kind: c.kind}) {
					return
				}
			}
		}
	}
	b.Run(t)
}

// ---------------------------------------------------------------------------
// the grammar, in Go
// ---------------------------------------------------------------------------

// TestComplete_AnswersEachPosition exercises the whole argument grammar through
// the --complete protocol both shell adapters read. It is the shell-independent
// half of the coverage: the adapter tests below only have to prove that each
// directive is translated into the right completion call.
func TestComplete_AnswersEachPosition(t *testing.T) {
	type TC struct {
		keyDir string
		words  []string
		cword  int
		want   string
		check  func(t *testing.T, cands []string)
	}
	type R struct {
		directive string
		cands     []string
	}

	exactly := func(want ...string) func(*testing.T, []string) {
		return func(t *testing.T, got []string) {
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("candidates mismatch:\n got: %q\nwant: %q", got, want)
			}
		}
	}
	holds := func(want ...string) func(*testing.T, []string) {
		return func(t *testing.T, got []string) {
			for _, w := range want {
				if !containsString(got, w) {
					t.Errorf("candidates %q are missing %q", got, w)
				}
			}
		}
	}
	lacks := func(unwanted ...string) func(*testing.T, []string) {
		return func(t *testing.T, got []string) {
			for _, u := range unwanted {
				if containsString(got, u) {
					t.Errorf("candidates %q must not offer %q", got, u)
				}
			}
		}
	}
	all := func(fns ...func(*testing.T, []string)) func(*testing.T, []string) {
		return func(t *testing.T, got []string) {
			for _, fn := range fns {
				fn(t, got)
			}
		}
	}
	none := func(t *testing.T, got []string) {
		if len(got) != 0 {
			t.Errorf("expected no candidates, got %q", got)
		}
	}

	b := tbdd.GWT(
		TC{
			words: []string{"rokey", ""}, cword: 1,
			want: "words", check: exactly("serve", "connect", "show-key", "rotate-key", "version", "completion"),
		},
		"a home directory with no key in it",
		func(t *testing.T, tc *TC) { tc.keyDir = isolatedHome(t) },
		"rokey is asked what fits under the cursor",
		func(t *testing.T, tc TC) R {
			d, c := completeLines(t, "bash", tc.cword, tc.words...)
			return R{d, c}
		},
		"the directive and the candidates are what that position allows, and no key was created",
		func(t *testing.T, tc TC, r R) {
			if r.directive != tc.want {
				t.Errorf("directive: got %q, want %q", r.directive, tc.want)
			}
			tc.check(t, r.cands)
			if _, err := os.Lstat(tc.keyDir); err == nil {
				t.Errorf("--complete created the key directory")
			}
		},
	)
	b.Variants = func(t *testing.T, tc TC) iter.Seq[tbdd.TestVariant[TC]] {
		cases := []struct {
			kind  string
			words []string
			cword int
			want  string
			check func(*testing.T, []string)
		}{
			{"candidates are left unfiltered for the shell to match",
				[]string{"rokey", "se"}, 1, "words", holds("serve", "connect", "version")},
			{"the hidden --complete command is never offered",
				[]string{"rokey", ""}, 1, "words", lacks("--complete", "-h", "--help")},
			{"serve offers its flags and the -- separator",
				[]string{"rokey", "serve", ""}, 2, "words",
				all(holds("-transport", "-listen", "-port", "-network", "-peer-key", "-key-file", "-peer-addr", "-restart", "-cmd", "--"), lacks("-detach-key"))},
			{"connect offers its flags and no separator",
				[]string{"rokey", "connect", ""}, 2, "words",
				all(holds("-transport", "-peer-addr", "-port", "-network", "-peer-key", "-key-file", "-detach-key"), lacks("--", "-listen", "-cmd", "-restart"))},
			{"a flag already given is not offered again",
				[]string{"rokey", "serve", "-restart", "-port", "7000", ""}, 5, "words",
				all(holds("-transport", "-cmd"), lacks("-restart", "-port"))},
			{"the cursor sitting on a partly typed flag still offers all flags",
				[]string{"rokey", "serve", "-tra"}, 2, "words", holds("-transport", "-listen")},
			{"-transport offers exactly the transports",
				[]string{"rokey", "serve", "-transport", ""}, 3, "words", exactly("quic", "tcp")},
			{"--transport, two dashes, is the same flag",
				[]string{"rokey", "connect", "--transport", ""}, 3, "words", exactly("quic", "tcp")},
			{"-network offers exactly the networks",
				[]string{"rokey", "connect", "-network", ""}, 3, "words", exactly("udp4", "udp6", "udp")},
			{"-key-file takes a file",
				[]string{"rokey", "serve", "-key-file", ""}, 3, "files", none},
			{"-cmd takes a program",
				[]string{"rokey", "serve", "-cmd", ""}, 3, "commands", none},
			{"-restart is a switch, so the word after it is another flag",
				[]string{"rokey", "serve", "-restart", ""}, 3, "words", holds("-cmd", "--")},
			{"-restart=false with an inline value is still a switch",
				[]string{"rokey", "serve", "-restart=false", ""}, 3, "words", holds("-cmd")},
			{"a flag value that looks like a flag is still consumed as the value",
				[]string{"rokey", "connect", "-detach-key", "-", ""}, 4, "words", holds("-peer-addr")},
			{"after serve's -- the words are the hosted program's own",
				[]string{"rokey", "serve", "-cmd", "tmux", "--", ""}, 5, "files", none},
			{"past the first program argument they still are",
				[]string{"rokey", "serve", "--", "new-session", ""}, 4, "files", none},
			{"a non-flag word ends serve's flags the way the flag package does",
				[]string{"rokey", "serve", "tmux", ""}, 3, "files", none},
			{"connect takes nothing after --",
				[]string{"rokey", "connect", "--", ""}, 3, "none", none},
			{"connect takes nothing after a non-flag word",
				[]string{"rokey", "connect", "stray", ""}, 3, "none", none},
			{"the COMP_WORDBREAKS split of -transport=VALUE is understood",
				[]string{"rokey", "serve", "-transport", "=", ""}, 4, "words", exactly("quic", "tcp")},
			{"the cursor on the bare = of that split is the value position",
				[]string{"rokey", "serve", "-key-file", "="}, 3, "files", none},
			{"the joined -network=VALUE zsh leaves intact is understood",
				[]string{"rokey", "connect", "-network=ud"}, 2, "words", exactly("udp4", "udp6", "udp")},
			{"a joined -key-file=PATH is a file position",
				[]string{"rokey", "serve", "-key-file=~/k"}, 2, "files", none},
			{"completion offers exactly the shells that are implemented",
				[]string{"rokey", "completion", ""}, 2, "words", exactly(supportedShells...)},
			{"completion takes one argument only",
				[]string{"rokey", "completion", "bash", ""}, 3, "none", none},
			// WHY: the negative paths. A port, an address or a fingerprint is
			// only known to the user, and a command with no arguments must not
			// invent some.
			{"-port offers nothing",
				[]string{"rokey", "serve", "-port", ""}, 3, "none", none},
			{"-peer-key offers nothing",
				[]string{"rokey", "connect", "-peer-key", ""}, 3, "none", none},
			{"-peer-addr offers nothing",
				[]string{"rokey", "connect", "-peer-addr", ""}, 3, "none", none},
			{"-listen offers nothing",
				[]string{"rokey", "serve", "-listen", ""}, 3, "none", none},
			{"-detach-key offers nothing",
				[]string{"rokey", "connect", "-detach-key", ""}, 3, "none", none},
			{"show-key takes no arguments",
				[]string{"rokey", "show-key", ""}, 2, "none", none},
			{"rotate-key takes no arguments",
				[]string{"rokey", "rotate-key", ""}, 2, "none", none},
			{"version takes no arguments",
				[]string{"rokey", "version", ""}, 2, "none", none},
			{"an unknown command offers nothing",
				[]string{"rokey", "frobnicate", ""}, 2, "none", none},
			{"an unknown flag offers nothing past it",
				[]string{"rokey", "serve", "-frobnicate", ""}, 3, "none", none},
			{"a cursor past the end of the typed words is still answered",
				[]string{"rokey", "serve"}, 2, "words", holds("-transport")},
		}
		return func(yield func(tbdd.TestVariant[TC]) bool) {
			for _, c := range cases {
				v := tc
				v.words, v.cword, v.want, v.check = c.words, c.cword, c.want, c.check
				if !yield(tbdd.TestVariant[TC]{TC: v, Kind: c.kind}) {
					return
				}
			}
		}
	}
	b.Run(t)
}

// TestComplete_DescriptionsOnlyForZsh: bash would offer a description as if it
// were a word, so it must only ever see the words themselves.
func TestComplete_DescriptionsOnlyForZsh(t *testing.T) {
	type TC struct{ words []string }
	type R struct{ bash, zsh []string }

	b := tbdd.GWT(
		TC{words: []string{"rokey", ""}},
		"a home directory with no key in it",
		func(t *testing.T, tc *TC) { isolatedHome(t) },
		"the position is completed for each shell",
		func(t *testing.T, tc TC) R {
			_, bashCands := completeLines(t, "bash", len(tc.words)-1, tc.words...)
			_, zshCands := completeLines(t, "zsh", len(tc.words)-1, tc.words...)
			return R{bashCands, zshCands}
		},
		"bash gets bare words and zsh gets each word with its description",
		func(t *testing.T, tc TC, r R) {
			if len(r.bash) != len(r.zsh) || len(r.bash) == 0 {
				t.Fatalf("shells were offered different candidates: %d vs %d", len(r.bash), len(r.zsh))
			}
			for _, c := range r.bash {
				if strings.Contains(c, "\t") {
					t.Errorf("bash candidate carries a description: %q", c)
				}
			}
			for i, c := range r.zsh {
				word, desc, ok := strings.Cut(c, "\t")
				if !ok || desc == "" {
					t.Errorf("zsh candidate has no description: %q", c)
				}
				if word != r.bash[i] {
					t.Errorf("candidate %d differs between shells: %q vs %q", i, word, r.bash[i])
				}
			}
		},
	)
	b.Variants = func(t *testing.T, tc TC) iter.Seq[tbdd.TestVariant[TC]] {
		return func(yield func(tbdd.TestVariant[TC]) bool) {
			v := tc
			v.words = []string{"rokey", "serve", ""}
			yield(tbdd.TestVariant[TC]{TC: v, Kind: "the flag position"})
		}
	}
	b.Run(t)
}

// TestComplete_RejectsAMalformedRequest: the protocol is internal, but a
// mangled request must fail rather than guess.
func TestComplete_RejectsAMalformedRequest(t *testing.T) {
	type TC struct{ args []string }
	type R struct {
		stdout string
		err    error
	}

	b := tbdd.GWT(
		TC{args: nil},
		"a home directory with no key in it",
		func(t *testing.T, tc *TC) { isolatedHome(t) },
		"a malformed completion request runs",
		func(t *testing.T, tc TC) R {
			out, err := captureStdout(t, func() error { return cmdComplete(tc.args) })
			return R{out, err}
		},
		"it errors and writes nothing to stdout",
		func(t *testing.T, tc TC, r R) {
			if r.err == nil {
				t.Fatal("expected an error")
			}
			if r.stdout != "" {
				t.Errorf("stdout not empty: %q", r.stdout)
			}
		},
	)
	b.Variants = func(t *testing.T, tc TC) iter.Seq[tbdd.TestVariant[TC]] {
		cases := []struct {
			kind string
			args []string
		}{
			{"missing the -- separator", []string{"bash", "1", "rokey"}},
			{"a cursor index that is not a number", []string{"bash", "x", "--", "rokey"}},
			{"a negative cursor index", []string{"bash", "-1", "--", "rokey"}},
		}
		return func(yield func(tbdd.TestVariant[TC]) bool) {
			for _, c := range cases {
				v := tc
				v.args = c.args
				if !yield(tbdd.TestVariant[TC]{TC: v, Kind: c.kind}) {
					return
				}
			}
		}
	}
	b.Run(t)
}

// ---------------------------------------------------------------------------
// the adapters, in their real shells
// ---------------------------------------------------------------------------

// bashDriver sources the integration, fakes readline's completion state from
// the remaining arguments, runs _rokey and prints COMPREPLY.
const bashDriver = `source "$1"; shift
COMP_CWORD=$1; shift
COMP_WORDS=( "$@" )
_rokey
if [ ${#COMPREPLY[@]} -gt 0 ]; then printf '%s\n' "${COMPREPLY[@]}"; fi
`

// zshDriver sources the integration and then replaces the pieces of the zsh
// completion system the adapter calls, so what it asked for is observable
// without driving an interactive shell.
const zshDriver = `emulate -L zsh
compdef() { : }
source "$1"; shift
CURRENT=$1; shift
words=( "$@" )
_describe() { print -rl -- ${(P)${@[-1]}} }
_files() { print -r -- '<files>' }
_command_names() { print -r -- '<commands>' }
_message() { print -r -- '<message>' }
compset() { print -r -- "<compset $*>" }
# A completion function returns non-zero to mean "no matches"; that is an
# answer, not a driver failure.
_rokey || true
`

// TestShellAdapters_TranslateEveryDirective drives the emitted bash and zsh
// functions in their real shells against a real rokey binary. The grammar is
// already covered above; what this proves is that each shell asks the right
// question and turns every directive into the right completion.
func TestShellAdapters_TranslateEveryDirective(t *testing.T) {
	type TC struct {
		bin    string
		shell  string
		driver string
		// cursor is the index of the word under the cursor, in that shell's
		// own convention: 0-based for bash's COMP_CWORD, 1-based for zsh's
		// CURRENT.
		cursor int
		words  []string
		check  func(t *testing.T, got []string)
	}

	exactly := func(want ...string) func(*testing.T, []string) {
		return func(t *testing.T, got []string) {
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("offered mismatch:\n got: %q\nwant: %q", got, want)
			}
		}
	}
	holds := func(want ...string) func(*testing.T, []string) {
		return func(t *testing.T, got []string) {
			for _, w := range want {
				if !containsString(got, w) {
					t.Errorf("offered %q is missing %q", got, w)
				}
			}
		}
	}

	b := tbdd.GWT(
		TC{
			shell: "bash", driver: bashDriver, cursor: 3,
			words: []string{"rokey", "serve", "-transport", ""},
			check: exactly("quic", "tcp"),
		},
		"a rokey binary and a home directory with no key in it",
		func(t *testing.T, tc *TC) {
			isolatedHome(t)
			tc.bin = buildRokey(t)
		},
		"that shell's completion function runs over the command line",
		func(t *testing.T, tc TC) []string {
			args := append([]string{strconv.Itoa(tc.cursor)}, tc.words...)
			return driveShell(t, tc.shell, tc.bin, tc.driver, args)
		},
		"it offers what the directive called for",
		func(t *testing.T, tc TC, got []string) { tc.check(t, got) },
	)
	b.Variants = func(t *testing.T, tc TC) iter.Seq[tbdd.TestVariant[TC]] {
		// The same lines for both shells; the cursor index differs only by the
		// shells' own 0- vs 1-based convention.
		cases := []struct {
			kind  string
			words []string
			bash  func(*testing.T, []string)
			zsh   func(*testing.T, []string)
		}{
			{"the command position offers every command",
				[]string{"rokey", ""},
				holds("serve", "connect", "completion"),
				holds("serve:host a terminal program and wait for one pinned client", "version:print the version")},
			{"a partial word is matched by the shell, not by rokey",
				[]string{"rokey", "s"},
				exactly("serve", "show-key"),
				// zsh's own matcher runs inside the real _describe, which this
				// driver replaces, so it sees the unfiltered list.
				holds("serve:host a terminal program and wait for one pinned client")},
			{"the flag position after serve",
				[]string{"rokey", "serve", "-re"},
				exactly("-restart"),
				holds("-restart:keep serving after the program exits", "--:arguments for the hosted program follow")},
			{"the commands directive becomes a program completion",
				[]string{"rokey", "serve", "-cmd", "ech"},
				holds("echo"),
				exactly("<commands>")},
			{"the files directive becomes a file completion",
				[]string{"rokey", "serve", "-key-file", ""},
				exactly(fileMarker),
				exactly("<files>")},
			{"the files directive after -- lists the program's arguments",
				[]string{"rokey", "serve", "--", ""},
				exactly(fileMarker),
				exactly("<files>")},
			{"the none directive offers nothing at all",
				[]string{"rokey", "connect", "-peer-key", ""},
				exactly(),
				exactly("<message>")},
			{"bash's COMP_WORDBREAKS split of -network=VALUE",
				[]string{"rokey", "connect", "-network", "=", "udp"},
				exactly("udp4", "udp6", "udp"),
				nil},
			{"the cursor on bash's bare = after -transport",
				[]string{"rokey", "connect", "-transport", "="},
				exactly("quic", "tcp"),
				nil},
			{"zsh's joined -network=VALUE strips the flag before matching",
				[]string{"rokey", "connect", "-network=ud"},
				nil,
				exactly("<compset -P -*=>", "udp4", "udp6", "udp")},
		}
		return func(yield func(tbdd.TestVariant[TC]) bool) {
			for _, c := range cases {
				for _, shell := range []string{"bash", "zsh"} {
					check, driver, cursor := c.bash, bashDriver, len(c.words)-1
					if shell == "zsh" {
						check, driver, cursor = c.zsh, zshDriver, len(c.words)
					}
					if check == nil {
						continue
					}
					v := tc
					v.shell, v.driver, v.cursor, v.words, v.check = shell, driver, cursor, c.words, check
					if !yield(tbdd.TestVariant[TC]{TC: v, Kind: shell + ": " + c.kind}) {
						return
					}
				}
			}
		}
	}
	b.Run(t)
}

// TestZshCompletion_RegistersWithCompsys: the zsh integration must actually
// bind _rokey to rokey once the completion system is loaded, and must say so
// on stderr when it is not.
func TestZshCompletion_RegistersWithCompsys(t *testing.T) {
	type TC struct {
		bin      string
		compinit bool
	}
	type R struct {
		stdout, stderr string
	}

	b := tbdd.GWT(
		TC{compinit: true},
		"a rokey binary and a zsh with the completion system available",
		func(t *testing.T, tc *TC) {
			isolatedHome(t)
			tc.bin = buildRokey(t)
		},
		"a zsh evaluates the integration and reports what it bound",
		func(t *testing.T, tc TC) R {
			script := `autoload -Uz compinit; compinit -u -D` + "\n"
			if !tc.compinit {
				script = ""
			}
			script += `eval "$(rokey completion zsh)"
(( $+_comps[rokey] )) && print -r -- "bound:$_comps[rokey]"
print -r -- "function:$(whence -w _rokey)"
`
			f := filepath.Join(t.TempDir(), "rc.zsh")
			if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(shellPath(t, "zsh"), "-f", f)
			cmd.Env = []string{
				"PATH=" + tc.bin + string(os.PathListSeparator) + "/usr/bin:/bin",
				"HOME=" + os.Getenv("HOME"),
			}
			var errBuf strings.Builder
			cmd.Stderr = &errBuf
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("zsh: %v\n%s", err, errBuf.String())
			}
			return R{string(out), errBuf.String()}
		},
		"the function is always defined, and the completion is bound exactly when compinit ran",
		func(t *testing.T, tc TC, r R) {
			if !strings.Contains(r.stdout, "function:_rokey: function") {
				t.Errorf("_rokey was not defined: %q", r.stdout)
			}
			bound := strings.Contains(r.stdout, "bound:_rokey")
			if bound != tc.compinit {
				t.Errorf("completion bound = %v, want %v (stdout %q)", bound, tc.compinit, r.stdout)
			}
			if !tc.compinit && !strings.Contains(r.stderr, "compinit") {
				t.Errorf("no hint about compinit on stderr: %q", r.stderr)
			}
		},
	)
	b.Variants = func(t *testing.T, tc TC) iter.Seq[tbdd.TestVariant[TC]] {
		return func(yield func(tbdd.TestVariant[TC]) bool) {
			v := tc
			v.compinit = false
			yield(tbdd.TestVariant[TC]{TC: v, Kind: "the eval placed before compinit"})
		}
	}
	b.Run(t)
}
