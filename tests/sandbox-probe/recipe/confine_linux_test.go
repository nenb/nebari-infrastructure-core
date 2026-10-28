//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPolicyCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  Policy
		abi     int
		wantErr string
	}{
		{name: "proxy port at ABI 4", policy: Policy{WorkDir: "/w", TCP: TCPProxyPort, ProxyPort: 8080}, abi: 4},
		{name: "deny at ABI 6", policy: Policy{WorkDir: "/w", TCP: TCPDeny}, abi: 6},
		{name: "unrestricted at ABI 3", policy: Policy{WorkDir: "/w", TCP: TCPUnrestricted}, abi: 3},
		{name: "unrestricted with Unix sockets only at ABI 3", policy: Policy{WorkDir: "/w", TCP: TCPUnrestricted, UnixSocketsOnly: true}, abi: 3},
		{name: "proxy port at ABI 3", policy: Policy{WorkDir: "/w", TCP: TCPProxyPort, ProxyPort: 8080}, abi: 3, wantErr: "needs Landlock ABI 4"},
		{name: "deny at ABI 3", policy: Policy{WorkDir: "/w", TCP: TCPDeny}, abi: 3, wantErr: "needs Landlock ABI 4"},
		{name: "unrestricted at ABI 2", policy: Policy{WorkDir: "/w", TCP: TCPUnrestricted}, abi: 2, wantErr: "ABI 3 or newer"},
		{name: "Landlock absent", policy: Policy{WorkDir: "/w", TCP: TCPUnrestricted}, abi: 0, wantErr: "ABI 3 or newer"},
		{name: "TCP mode not stated", policy: Policy{WorkDir: "/w"}, abi: 6, wantErr: "tcp must be"},
		{name: "unknown TCP mode", policy: Policy{WorkDir: "/w", TCP: "none"}, abi: 6, wantErr: "tcp must be"},
		{name: "proxy port without a port", policy: Policy{WorkDir: "/w", TCP: TCPProxyPort}, abi: 6, wantErr: "proxyPort"},
		{name: "port with another mode", policy: Policy{WorkDir: "/w", TCP: TCPDeny, ProxyPort: 8080}, abi: 6, wantErr: "proxyPort"},
		{name: "no work directory", policy: Policy{TCP: TCPDeny}, abi: 6, wantErr: "workDir"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := test.policy.check(test.abi)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("check() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("check() error = %v, want one containing %q", err, test.wantErr)
			}
		})
	}
}

// TestHelperRefusesBeforeExecuting runs the helper (this test binary,
// re-executed) with landlockABI capped at a fixed value, and checks that a
// policy the ABI cannot enforce, or a malformed policy, stops the command
// from running at all.
func TestHelperRefusesBeforeExecuting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fakeABI int
		policy  string // JSON with WORK for the work directory and system paths
		runs    bool
	}{
		{name: "proxy port at ABI 3", fakeABI: 3, policy: `{WORK,"tcp":"proxy-port","proxyPort":8080}`},
		{name: "deny at ABI 3", fakeABI: 3, policy: `{WORK,"tcp":"deny"}`},
		{name: "unrestricted at ABI 2", fakeABI: 2, policy: `{WORK,"tcp":"unrestricted"}`},
		{name: "unrestricted without Landlock", fakeABI: 0, policy: `{WORK,"tcp":"unrestricted"}`},
		{name: "TCP mode not stated", fakeABI: 99, policy: `{WORK}`},
		{name: "unknown field (the retired NoInet)", fakeABI: 99, policy: `{WORK,"tcp":"deny","NoInet":true}`},
		// Positive control: the same helper does run the command when the
		// policy and the (real) kernel allow it, so a refusal is not vacuous.
		{name: "control: unrestricted at ABI 3", fakeABI: 3, policy: `{WORK,"tcp":"unrestricted"}`, runs: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if abi := landlockABI(); test.runs && abi < 3 {
				t.Skipf("positive control needs Landlock ABI 3 or newer on this kernel, have %d", abi)
			}
			work := t.TempDir()
			marker := filepath.Join(work, "ran")
			paths := `"workDir":"` + work + `","readOnly":["/usr","/bin","/lib","/lib64","/etc"]`
			policy := strings.Replace(test.policy, "WORK", paths, 1)
			cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", policy, "/bin/sh", "-c", ": > "+marker)
			cmd.Env = append(os.Environ(), "RECIPE_HELPER_FAKE_ABI="+strconv.Itoa(test.fakeABI))
			out, err := cmd.CombinedOutput()
			_, statErr := os.Stat(marker)
			if ran := statErr == nil; ran != test.runs {
				t.Fatalf("command ran = %t, want %t (err %v)\n%s", ran, test.runs, err, out)
			}
			var exit *exec.ExitError
			if !test.runs && (!errors.As(err, &exit) || exit.ExitCode() != 126) {
				t.Fatalf("helper error = %v, want exit status 126\n%s", err, out)
			}
		})
	}
}

// TestHelperProcess is the helper side for TestHelperRefusesBeforeExecuting;
// it does nothing in a normal test run.
func TestHelperProcess(t *testing.T) {
	fake := os.Getenv("RECIPE_HELPER_FAKE_ABI")
	if fake == "" {
		return
	}
	value, err := strconv.Atoi(fake)
	if err != nil {
		os.Exit(2)
	}
	real := landlockABI
	landlockABI = func() int { return min(value, real()) } // never claim more than the kernel has
	args := os.Args
	for index, arg := range args {
		if arg == "--" {
			args = args[index+1:]
			break
		}
	}
	err = confineAndExec(args[0], args[1:]) // returns only on failure
	os.Stderr.WriteString("confine: " + err.Error() + "\n")
	os.Exit(126)
}
