//go:build darwin

// Tests for install.sh, the one-liner every customer runs to get
// AgentGuard. The script in this repo is the one they actually fetch, so
// this is where its tests belong.
//
// The script is deliberately thin, but "thin" is not "trivial": it decides
// what to download, refuses anything that is not signed by Jozu, and can
// escalate to sudo. Driving it from Go rather than from bash buys
// table-driven cases, a real HTTP server serving crafted releases, per-case
// temp dirs, and one place where the pinned Team ID is compared against the
// Go constant that `agentguard update` enforces.
//
// Everything here is offline: the httptest server stands in for the release
// mirror via AGENTGUARD_BASE_URL. The one case these tests structurally
// cannot cover is the happy path, because it needs a binary carrying Jozu's
// real Developer ID signature, which no test can forge and no CI runner
// holds. That path is covered against the actual published release by the
// verify-install job in release.yml.
package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// expectedTeamID is Jozu's Apple Developer ID team. The development repo
// asserts this same value against pkg/selfupdate.ExpectedTeamID, which gates
// `agentguard update`, so the two paths by which a binary reaches a user
// machine cannot come to trust different certificates.
const expectedTeamID = "PMHBCVV9C2"

func installScript(t *testing.T) string {
	t.Helper()
	p := filepath.Join(repoRoot(t), "scripts", "install.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("install.sh not found at %s: %v", p, err)
	}
	return p
}

// mirror serves a directory of release assets the way an internal re-host
// would, so the script can be pointed at it with AGENTGUARD_BASE_URL.
func mirror(t *testing.T, files map[string][]byte) string {
	t.Helper()
	mux := http.NewServeMux()
	for name, body := range files {
		mux.HandleFunc("/"+name, func(w http.ResponseWriter, _ *http.Request) {
			w.Write(body) //nolint:errcheck
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// checksumsFor builds a SHA256SUMS-style body for the given asset bytes.
func checksumsFor(agentguard []byte) []byte {
	return []byte(fmt.Sprintf("%s  agentguard\n", sha256Hex(agentguard)))
}

// adHocSigned returns a path to a real Mach-O binary carrying a valid
// ad-hoc signature. This is the interesting negative: a bare `codesign -v`
// accepts it, so only the Apple-anchored team requirement rejects it.
func adHocSigned(t *testing.T) []byte {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "adhoc")
	src, err := os.ReadFile("/bin/echo")
	if err != nil {
		t.Fatalf("read /bin/echo: %v", err)
	}
	if err := os.WriteFile(dst, src, 0o755); err != nil {
		t.Fatalf("write adhoc binary: %v", err)
	}
	if out, err := exec.Command("codesign", "-s", "-", "--force", dst).CombinedOutput(); err != nil {
		t.Fatalf("ad-hoc sign: %v: %s", err, out)
	}
	if out, err := exec.Command("codesign", "--verify", "--strict", dst).CombinedOutput(); err != nil {
		t.Fatalf("ad-hoc signature should satisfy a bare codesign -v, the check this script replaced: %v: %s", err, out)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read signed binary: %v", err)
	}
	return b
}

type runResult struct {
	exitCode int
	output   string
}

// runInstall executes the script with an isolated TMPDIR and PATH, and
// reports the combined output. env entries are appended as KEY=VALUE.
func runInstall(t *testing.T, installDir string, env ...string) runResult {
	t.Helper()

	tmp := t.TempDir()
	cmd := exec.Command("/bin/bash", installScript(t))

	// Explicit environment rather than os.Environ(): an exported
	// AGENTGUARD_BASE_URL or VERSION in the developer's shell -- entirely
	// plausible for anyone exercising the internal-mirror path -- would
	// silently redirect these cases and make them pass or fail for the
	// wrong reason.
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"INSTALL_DIR=" + installDir,
		// Private TMPDIR: the cleanup assertion inspects what the script
		// leaves behind, and a shared temp makes that depend on whatever
		// else is running on the machine.
		"TMPDIR=" + tmp,
	}, env...)

	// Detach the controlling terminal. Go's exec does not call setsid, so
	// without this the child inherits the terminal of whoever ran `go
	// test`, and any case that depends on sudo having nowhere to prompt
	// would behave one way on CI and another way on a developer's machine.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run install.sh: %v", err)
	}

	// Nothing the script downloads may outlive it, whatever the outcome.
	// The pattern has to match the script's mktemp template: BSD mktemp
	// ignores $TMPDIR when called without one, so an earlier version of
	// this assertion silently matched nothing on every run.
	leftovers, _ := filepath.Glob(filepath.Join(tmp, "agentguard.*"))
	if len(leftovers) > 0 {
		t.Errorf("install.sh left temp directories behind: %v\noutput:\n%s", leftovers, out)
	}
	return runResult{exitCode: code, output: string(out)}
}

// repoRoot walks up to the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the working directory")
		}
		dir = parent
	}
}

// TestInstallScriptPinsSigningIdentity keeps the signature gate pinned to
// Jozu's team. Losing or loosening this turns the installer into one that
// accepts any validly signed binary, including a self-signed one.
func TestInstallScriptPinsSigningIdentity(t *testing.T) {
	body, err := os.ReadFile(installScript(t))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`EXPECTED_TEAM_ID="([A-Z0-9]+)"`).FindSubmatch(body)
	if m == nil {
		t.Fatal("install.sh does not pin EXPECTED_TEAM_ID")
	}
	if got := string(m[1]); got != expectedTeamID {
		t.Errorf("install.sh pins Team ID %q, want %q", got, expectedTeamID)
	}
}

// TestInstallScriptNeedsNoGitHubCLI guards the property this script exists
// for: a prospect with no org access and no gh CLI can install.
func TestInstallScriptNeedsNoGitHubCLI(t *testing.T) {
	body, err := os.ReadFile(installScript(t))
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(body), "\n") {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "#") {
			continue
		}
		if regexp.MustCompile(`(^|[^\w-])gh\s`).MatchString(code) {
			t.Errorf("line %d shells out to the GitHub CLI: %s", i+1, code)
		}
		if strings.Contains(code, "jozu-ai/agentguard") {
			t.Errorf("line %d downloads from the private repo: %s", i+1, code)
		}
	}
}

func TestInstallScriptRefusesUnverifiedBinaries(t *testing.T) {
	genuine := adHocSigned(t)

	cases := []struct {
		name     string
		files    map[string][]byte
		wantExit int
		wantMsg  string
		reason   string
	}{
		{
			name: "checksum mismatch",
			files: map[string][]byte{
				"agentguard":    genuine,
				"checksums.txt": checksumsFor([]byte("something else entirely")),
			},
			wantExit: 1,
			wantMsg:  "Checksum mismatch",
			reason:   "the bytes that arrived are not the bytes the release published",
		},
		{
			name: "valid signature, wrong team",
			files: map[string][]byte{
				"agentguard":    genuine,
				"checksums.txt": checksumsFor(genuine),
			},
			wantExit: 1,
			wantMsg:  "not signed by an Apple-anchored Jozu certificate",
			reason:   "an ad-hoc signature passes a bare codesign -v; only the team pin rejects it",
		},
		{
			name: "not signed at all",
			files: map[string][]byte{
				"agentguard":    []byte("#!/bin/sh\necho pwned\n"),
				"checksums.txt": checksumsFor([]byte("#!/bin/sh\necho pwned\n")),
			},
			wantExit: 1,
			wantMsg:  "Refusing to install",
			reason:   "a hostile mirror controls checksums.txt too, so only the signature gate protects here",
		},
		{
			name: "no checksums published falls through to the signature gate",
			files: map[string][]byte{
				"agentguard": genuine,
			},
			wantExit: 1,
			wantMsg:  "not signed by an Apple-anchored Jozu certificate",
			reason:   "releases before v0.7.1 have no checksums.txt; that is tolerated, the signature gate is not optional",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installDir := filepath.Join(t.TempDir(), "bin")
			base := mirror(t, tc.files)

			got := runInstall(t, installDir, "AGENTGUARD_BASE_URL="+base)

			if got.exitCode != tc.wantExit {
				t.Errorf("exit code = %d, want %d (%s)\noutput:\n%s", got.exitCode, tc.wantExit, tc.reason, got.output)
			}
			if !strings.Contains(got.output, tc.wantMsg) {
				t.Errorf("output does not mention %q (%s)\noutput:\n%s", tc.wantMsg, tc.reason, got.output)
			}
			if _, err := os.Stat(filepath.Join(installDir, "agentguard")); err == nil {
				t.Errorf("a rejected binary was installed anyway (%s)", tc.reason)
			}
		})
	}
}

// TestInstallScriptRejectsPlaintextSource covers the downgrade vector: over
// plaintext, a network attacker cannot forge a signature but can choose
// which genuinely signed release you receive.
func TestInstallScriptRejectsPlaintextSource(t *testing.T) {
	installDir := filepath.Join(t.TempDir(), "bin")
	got := runInstall(t, installDir, "AGENTGUARD_BASE_URL=http://mirror.example.com/agentguard")

	if got.exitCode == 0 {
		t.Errorf("plaintext base URL was accepted\noutput:\n%s", got.output)
	}
	if !strings.Contains(got.output, "must use https") {
		t.Errorf("error does not explain the scheme requirement\noutput:\n%s", got.output)
	}
}

// TestInstallScriptReportsItsSource makes an install driven by a stale
// AGENTGUARD_BASE_URL in the environment visible rather than mysterious.
func TestInstallScriptReportsItsSource(t *testing.T) {
	base := mirror(t, map[string][]byte{"agentguard": []byte("not a binary")})
	got := runInstall(t, filepath.Join(t.TempDir(), "bin"), "AGENTGUARD_BASE_URL="+base)

	if !strings.Contains(got.output, "Source: "+base) {
		t.Errorf("output does not name the source it downloaded from\noutput:\n%s", got.output)
	}
	if !strings.Contains(got.output, "custom source") {
		t.Errorf("a custom source should warn that verification pins identity, not version\noutput:\n%s", got.output)
	}
}

func TestInstallScriptMissingRelease(t *testing.T) {
	// An empty mirror 404s every asset, which is what a nonexistent release
	// looks like. Pointing at github.com instead would make this gate on
	// the file every customer runs depend on GitHub being reachable from
	// the runner.
	base := mirror(t, map[string][]byte{})
	got := runInstall(t, filepath.Join(t.TempDir(), "bin"), "AGENTGUARD_BASE_URL="+base)

	if got.exitCode == 0 {
		t.Fatalf("installing a nonexistent version succeeded\noutput:\n%s", got.output)
	}
	// A curl exit code tells the user nothing; the releases page does.
	if !strings.Contains(got.output, "releases") {
		t.Errorf("error does not point at the releases page\noutput:\n%s", got.output)
	}
}

// TestInstallBinaryEscalatesOnlyWhenNecessary covers the placement logic
// directly, without a download. Getting this wrong is expensive in a very
// ordinary case: INSTALL_DIR=~/.local/bin on a machine that does not have
// that directory yet used to prompt for a sudo password nobody needed and
// leave a root-owned directory in the user's home.
func TestInstallBinaryEscalatesOnlyWhenNecessary(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(t *testing.T, root string) string // returns INSTALL_DIR
		wantSudo   bool
		wantReason string
	}{
		{
			name: "existing writable directory",
			setup: func(t *testing.T, root string) string {
				d := filepath.Join(root, "bin")
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
				return d
			},
			wantSudo:   false,
			wantReason: "the directory is already writable",
		},
		{
			name: "missing directory under a writable parent",
			setup: func(_ *testing.T, root string) string {
				return filepath.Join(root, "local", "bin")
			},
			wantSudo:   false,
			wantReason: "the user can create it themselves, as with a fresh ~/.local/bin",
		},
		{
			name: "unwritable parent",
			setup: func(t *testing.T, root string) string {
				d := filepath.Join(root, "readonly")
				if err := os.MkdirAll(d, 0o555); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Chmod(d, 0o755) }) //nolint:errcheck
				return filepath.Join(d, "bin")
			},
			wantSudo:   true,
			wantReason: "only root can write there",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			installDir := tc.setup(t, root)

			// A sudo shim that records that it was called and then runs the
			// command unprivileged, so the test needs no real escalation.
			shimDir := filepath.Join(root, "shim")
			if err := os.MkdirAll(shimDir, 0o755); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "sudo-was-called")
			// Stands in for real elevation, which a test cannot perform: record
			// the call, grant the write access root would have had over the
			// test's own tree, then run the command unprivileged.
			shim := fmt.Sprintf("#!/bin/bash\ntouch %q\nchmod -R u+w %q 2>/dev/null || true\nexec \"$@\"\n", marker, root)
			if err := os.WriteFile(filepath.Join(shimDir, "sudo"), []byte(shim), 0o755); err != nil {
				t.Fatal(err)
			}

			payload := filepath.Join(root, "payload")
			if err := os.WriteFile(payload, []byte("binary\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			// Source the script (its main is guarded) and call one function.
			// install_binary's own output goes to /dev/null: the sudo branch
			// prints a status line, and the assertion below is about what the
			// function *reports*, which must be the bare path.
			script := fmt.Sprintf(
				`source %q >/dev/null 2>&1; set +e; INSTALL_DIR=%q; install_binary %q >/dev/null 2>&1; printf '%%s' "$installed_path"`,
				installScript(t), installDir, payload)
			cmd := exec.Command("/bin/bash", "-c", script)
			cmd.Env = append(os.Environ(), "PATH="+shimDir+":"+os.Getenv("PATH"))
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("install_binary failed: %v", err)
			}

			wantPath := filepath.Join(installDir, "agentguard")
			// The reported path must be the path alone. The sudo branch also
			// prints a status line, and a previous version returned both
			// through stdout, splicing that line into the path.
			if got := string(out); got != wantPath {
				t.Errorf("installed_path = %q, want %q", got, wantPath)
			}
			if _, err := os.Stat(wantPath); err != nil {
				t.Errorf("binary not in place at %s: %v", wantPath, err)
			}

			_, sudoCalled := os.Stat(marker)
			if gotSudo := sudoCalled == nil; gotSudo != tc.wantSudo {
				t.Errorf("sudo invoked = %v, want %v (%s)", gotSudo, tc.wantSudo, tc.wantReason)
			}
		})
	}
}

// TestInstallScriptFailsFastWithoutEscalation covers the ordering that makes
// this failure expensive rather than merely annoying: escalation used to be
// discovered only after a 550MB download, and reported as a raw sudo error.
// Anything driving the installer non-interactively -- MDM, a provisioning
// script, a CI step -- has no terminal for sudo to prompt on.
//
// The two conditions are supplied rather than borrowed from the machine, so
// this runs everywhere instead of skipping: a sudo that reports a password
// is required (GitHub's macOS runners have passwordless sudo, which would
// otherwise skip this away), and no controlling terminal, which is already
// true of anything Go's exec starts.
func TestInstallScriptFailsFastWithoutEscalation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: every directory is writable, so escalation is never needed")
	}

	root := t.TempDir()

	// An install directory the user cannot create, because its parent is
	// not writable.
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) }) //nolint:errcheck
	installDir := filepath.Join(locked, "bin")

	// A sudo that always reports it needs a password, never escalating.
	shimDir := filepath.Join(root, "shim")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	shim := "#!/bin/bash\necho 'sudo: a password is required' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(shimDir, "sudo"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	got := runInstall(t, installDir, "PATH="+shimDir+":"+os.Getenv("PATH"))
	elapsed := time.Since(start)

	if got.exitCode == 0 {
		t.Fatalf("install reported success without being able to escalate\noutput:\n%s", got.output)
	}
	// Half a gigabyte takes far longer than this on any link, so a quick
	// failure is the evidence that it bailed out before transferring.
	if elapsed > 20*time.Second {
		t.Errorf("took %s to fail, so it downloaded before checking it could install", elapsed)
	}
	if strings.Contains(got.output, "Downloading") {
		t.Errorf("started the download before checking it could install\noutput:\n%s", got.output)
	}
	for _, want := range []string{"no terminal", "sudo", "INSTALL_DIR"} {
		if !strings.Contains(got.output, want) {
			t.Errorf("error message does not mention %q, so the reader cannot act on it\noutput:\n%s", want, got.output)
		}
	}
}

// TestDefaultInstallDir covers where the binary lands when the caller says
// nothing. Getting this wrong is either a password prompt nobody needed or,
// worse, an install the user cannot run: ~/.local/bin is not on macOS's
// stock PATH (see /etc/paths), so it is only a valid target when the caller
// already has it there.
// systemDirPlaceholder marks a case whose expected answer is the test's
// stand-in for /usr/local/bin, whose path is only known at run time.
const systemDirPlaceholder = "<system-dir>"

func TestDefaultInstallDir(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		home       string
		systemMode os.FileMode // mode of the stand-in for /usr/local/bin
		want       string      // systemDirPlaceholder means "the stand-in"
		why        string
	}{
		{
			name:       "system directory is writable",
			path:       "/usr/bin:/bin",
			home:       "/Users/someone",
			systemMode: 0o755,
			want:       systemDirPlaceholder,
			why:        "it is on the stock PATH and needs no password, so nothing beats it",
		},
		{
			name:       "root-owned system directory, stock PATH",
			path:       "/usr/bin:/bin:/usr/sbin:/sbin",
			home:       "/Users/someone",
			systemMode: 0o555,
			want:       systemDirPlaceholder,
			why:        "nothing else is guaranteed to be found, even though it costs a sudo prompt",
		},
		{
			name:       "root-owned system directory, ~/.local/bin on PATH",
			path:       "/Users/someone/.local/bin:/usr/bin:/bin",
			home:       "/Users/someone",
			systemMode: 0o555,
			want:       "/Users/someone/.local/bin",
			why:        "it will be found there, and installing needs no password",
		},
		{
			name:       "root-owned system directory, ~/.local/bin not on PATH",
			path:       "/usr/bin:/bin",
			home:       t.TempDir(),
			systemMode: 0o555,
			want:       systemDirPlaceholder,
			why:        "installing off PATH produces a binary the user's shell cannot find",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The ~/.local/bin-not-on-PATH case needs the directory to
			// exist, to prove existence alone is not enough.
			if strings.HasSuffix(tc.name, "not on PATH") {
				if err := os.MkdirAll(filepath.Join(tc.home, ".local", "bin"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// Stand in for /usr/local/bin with a directory this test
			// controls, so all three outcomes are exercised even where the
			// real one is writable (an Intel-Homebrew-migrated Mac, or a
			// GitHub runner). Skipping there left the no-password path --
			// the one most developers take -- untested on CI.
			systemDir := filepath.Join(t.TempDir(), "usr-local-bin")
			if err := os.MkdirAll(systemDir, tc.systemMode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(systemDir, 0o755) }) //nolint:errcheck

			want := tc.want
			if want == systemDirPlaceholder {
				want = systemDir
			}

			script := fmt.Sprintf(`source %q >/dev/null 2>&1; default_install_dir %q`, installScript(t), systemDir)
			cmd := exec.Command("/bin/bash", "-c", script)
			cmd.Env = []string{"PATH=" + tc.path, "HOME=" + tc.home}
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("default_install_dir: %v", err)
			}
			if got := strings.TrimSpace(string(out)); got != want {
				t.Errorf("default_install_dir = %q, want %q (%s)", got, want, tc.why)
			}
		})
	}
}

// unixWritable reports whether the current user can create a file in dir.
func unixWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".agentguard-probe")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()       //nolint:errcheck
	os.Remove(name) //nolint:errcheck
	return true
}

// TestRequireHTTPS pins which sources may be fetched over cleartext. The
// loopback exemption exists only so a mirror can be tested before its TLS
// is up; written as a prefix glob it also matched 127.0.0.1.evil.com and
// localhost.attacker.io, handing a remote attacker the downgrade the https
// requirement exists to prevent.
func TestRequireHTTPS(t *testing.T) {
	cases := []struct {
		url   string
		allow bool
	}{
		{"https://artifacts.example.com/agentguard", true},
		{"http://127.0.0.1:8799/x", true},
		{"http://localhost:8080/x", true},
		{"http://[::1]:9/x", true},
		{"http://127.0.0.1.evil.com/x", false},
		{"http://localhost.attacker.io/x", false},
		{"http://127.0.0.1@evil.com/x", false},
		{"http://127.0.0.1evil.com/x", false},
		{"http://evil.com/x", false},
		{"ftp://example.com/x", false},
	}

	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			script := fmt.Sprintf(`source %q >/dev/null 2>&1; require_https %q`, installScript(t), tc.url)
			cmd := exec.Command("/bin/bash", "-c", script)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
			err := cmd.Run()
			if allowed := err == nil; allowed != tc.allow {
				t.Errorf("require_https(%q) allowed=%v, want %v", tc.url, allowed, tc.allow)
			}
		})
	}
}

// TestVerifyChecksumNameForms covers the spellings a checksums.txt can carry.
// Exact equality on the raw second field turned a release-tooling change
// (sha256sum -b, or generating from a dist/ tree) into a silently skipped
// checksum rather than a failure.
func TestVerifyChecksumNameForms(t *testing.T) {
	tmpd := t.TempDir()
	payload := filepath.Join(tmpd, "agentguard")
	if err := os.WriteFile(payload, []byte("payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256Hex([]byte("payload\n"))

	cases := []struct {
		name    string
		line    string
		matched bool
	}{
		{"plain", sum + "  agentguard", true},
		{"binary mode prefix", sum + " *agentguard", true},
		{"generated from a dist tree", sum + "  dist/agentguard", true},
		{"a different asset entirely", sum + "  agentguard.zip", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sums := filepath.Join(tmpd, tc.name+".txt")
			if err := os.WriteFile(sums, []byte(tc.line+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			out := run_isolated(t, fmt.Sprintf("verify_checksum %q %q agentguard", payload, sums))
			// A matched entry reports the verification; an unmatched one
			// falls back to the signature gate with a warning.
			if tc.matched && !strings.Contains(out, "Checksum verified") {
				t.Errorf("entry %q was not matched, so the checksum was silently skipped\noutput: %s", tc.line, out)
			}
			if !tc.matched && !strings.Contains(out, "no entry for") {
				t.Errorf("entry %q should not have matched agentguard\noutput: %s", tc.line, out)
			}
		})
	}
}

// TestFailedInstallLeavesNoDirectory covers a promise the script makes about
// itself: a refused install touches nothing. Probing writability by calling
// mkdir -p meant every rejected download still created INSTALL_DIR.
func TestFailedInstallLeavesNoDirectory(t *testing.T) {
	root := t.TempDir()
	installDir := filepath.Join(root, "typo", "bin")
	base := mirror(t, map[string][]byte{}) // 404s everything

	got := runInstall(t, installDir, "AGENTGUARD_BASE_URL="+base)
	if got.exitCode == 0 {
		t.Fatalf("install of a nonexistent asset reported success\noutput:\n%s", got.output)
	}
	if _, err := os.Stat(filepath.Join(root, "typo")); err == nil {
		t.Errorf("a refused install created %s and left it behind", filepath.Join(root, "typo"))
	}
}

// run_isolated runs one snippet against the sourced script and returns its
// combined output.
func run_isolated(t *testing.T, snippet string) string {
	t.Helper()
	script := fmt.Sprintf(`source %q >/dev/null 2>&1; set +e; %s`, installScript(t), snippet)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// TestAssetURL pins the URL forms. The redirect endpoints below are chosen
// over the REST API because the API rate-limits unauthenticated callers to
// 60 requests/hour per IP, which a whole office behind one NAT would share.
func TestAssetURL(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		tag  string
		want string
	}{
		{
			name: "latest release",
			want: "https://github.com/jozu-ai/agent-guard/releases/latest/download/agentguard",
		},
		{
			name: "pinned tag",
			tag:  "v0.7.1",
			want: "https://github.com/jozu-ai/agent-guard/releases/download/v0.7.1/agentguard",
		},
		{
			name: "internal mirror, trailing slash trimmed",
			env:  []string{"AGENTGUARD_BASE_URL=https://artifacts.example.com/agentguard/v0.7.1/"},
			want: "https://artifacts.example.com/agentguard/v0.7.1/agentguard",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := fmt.Sprintf(`source %q >/dev/null 2>&1; TAG=%q; asset_url agentguard`, installScript(t), tc.tag)
			cmd := exec.Command("/bin/bash", "-c", script)
			cmd.Env = append(os.Environ(), tc.env...)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("asset_url: %v", err)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Errorf("asset_url = %q, want %q", got, tc.want)
			}
		})
	}
}
