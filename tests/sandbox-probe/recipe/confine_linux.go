//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"unsafe"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// Policy is what a confined command may do. Every field is stated; nothing
// is inferred from what the kernel happens to support.
type Policy struct {
	WorkDir   string   `json:"workDir"`   // read, write, create, remove, move and link beneath it
	ReadOnly  []string `json:"readOnly"`  // read and execute beneath, e.g. /usr, /etc, /proc
	ReadWrite []string `json:"readWrite"` // read and write, e.g. /dev/null
	// TCP is "proxy-port" (connect to ProxyPort only, no bind), "deny" (no
	// connect or bind) or "unrestricted" (Landlock leaves TCP alone). The first
	// two need Landlock ABI 4; the command is refused on older kernels.
	TCP       string `json:"tcp"`
	ProxyPort uint16 `json:"proxyPort,omitempty"` // with "proxy-port" only
	// UnixSocketsOnly adds a seccomp filter under which socket() succeeds only
	// for AF_UNIX: no IP, packet, netlink, vsock or other sockets.
	UnixSocketsOnly bool `json:"unixSocketsOnly,omitempty"`
}

const (
	confineArg      = "__confine"
	TCPProxyPort    = "proxy-port"
	TCPDeny         = "deny"
	TCPUnrestricted = "unrestricted"
)

// Agent side: run argv under p in a fresh helper (this binary, re-executed),
// with a minimal environment and only stdin, stdout and stderr.
func confinedCommand(p Policy, argv ...string) (*exec.Cmd, error) {
	pj, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/proc/self/exe", append([]string{confineArg, string(pj)}, argv...)...)
	cmd.Dir = p.WorkDir
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + p.WorkDir,
		"TMPDIR=" + p.WorkDir, "LANG=C.UTF-8"}
	return cmd, nil
}

// Helper side, first thing in main:
//
//	if len(os.Args) > 2 && os.Args[1] == confineArg {
//		err := confineAndExec(os.Args[2], os.Args[3:]) // returns only on failure
//		fmt.Fprintln(os.Stderr, "confine:", err)
//		os.Exit(126)
//	}
func confineAndExec(policyJSON string, argv []string) error {
	var p Policy
	decoder := json.NewDecoder(bytes.NewReader([]byte(policyJSON)))
	decoder.DisallowUnknownFields() // a misspelt or retired field must not be ignored
	if err := decoder.Decode(&p); err != nil || len(argv) == 0 {
		return errors.Join(errors.New("bad policy or empty command"), err)
	}
	abi := landlockABI()
	if err := p.check(abi); err != nil {
		return err // refuse rather than run the command with less than the policy says
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	runtime.LockOSThread() // the seccomp filter applies to this thread, which then execs
	if err := applyLandlock(p, abi); err != nil {
		return err
	}
	if p.UnixSocketsOnly {
		if err := allowOnlyUnixSockets(); err != nil {
			return err
		}
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err // inherited descriptors must not reach the command
	}
	return unix.Exec(path, argv, os.Environ())
}

// check refuses a policy the running kernel cannot enforce in full.
func (p Policy) check(abi int) error {
	switch {
	case p.WorkDir == "":
		return errors.New("policy has no workDir")
	case p.TCP != TCPProxyPort && p.TCP != TCPDeny && p.TCP != TCPUnrestricted:
		return fmt.Errorf("policy tcp must be %q, %q or %q", TCPProxyPort, TCPDeny, TCPUnrestricted)
	case (p.TCP == TCPProxyPort) != (p.ProxyPort != 0):
		return errors.New("policy proxyPort is required with tcp proxy-port and invalid otherwise")
	case abi < 3:
		return fmt.Errorf("Landlock ABI 3 or newer is required, have %d", abi)
	case p.TCP != TCPUnrestricted && abi < 4:
		return fmt.Errorf("tcp %q needs Landlock ABI 4 or newer, have %d", p.TCP, abi)
	}
	return nil
}

// landlockABI returns the kernel's Landlock ABI, or 0 if Landlock is absent
// (ENOSYS) or not enabled at boot (EOPNOTSUPP). It is a variable so that a
// test can stand in for an older kernel.
var landlockABI = func() int {
	abi, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		return 0
	}
	return abi
}

// applyLandlock grants everything beneath the work directory, including moves
// and links within it (REFER) and connecting to Unix sockets there; read and
// execute beneath p.ReadOnly; read and write on p.ReadWrite; and, with
// "proxy-port", TCP connect to p.ProxyPort. It also sets no_new_privs.
//
// It restricts twice, and each restriction adds a stacked Landlock domain
// that can only take access away. The first is strict: the filesystem rights
// of ABI 3 and, unless TCP is unrestricted, TCP connect and bind of ABI 4; it
// fails rather than do less. The second, from ABI 5, is best effort with the
// same grants and adds whatever newer rights the kernel has: device ioctls
// (ABI 5), signals and abstract Unix sockets outside the sandbox (ABI 6),
// pathname Unix sockets outside the work directory (ABI 9) and, unless TCP
// is unrestricted, UDP (ABI 10).
func applyLandlock(p Policy, abi int) error {
	rules := []landlock.Rule{
		landlock.RWDirs(p.WorkDir).WithRefer().WithResolveUnix(),
		landlock.RODirs(p.ReadOnly...).IgnoreIfMissing(),
		landlock.RWFiles(p.ReadWrite...).IgnoreIfMissing(),
	}
	if p.TCP == TCPProxyPort {
		rules = append(rules, landlock.ConnectTCP(p.ProxyPort))
	}
	required, extra := landlock.V4, landlock.V11
	if p.TCP == TCPUnrestricted {
		required, extra.HandledAccessNet = landlock.V3, 0
	}
	if err := required.Restrict(rules...); err != nil {
		return err
	}
	if abi < 5 {
		return nil // nothing newer to add
	}
	return extra.BestEffort().Restrict(rules...)
}

// allowOnlyUnixSockets installs a seccomp filter under which socket() fails
// with EPERM for every address family except AF_UNIX. It also refuses
// io_uring, which can create sockets without calling socket(), and any
// syscall from a foreign or x32 ABI.
func allowOnlyUnixSockets() error {
	arch := map[string]uint32{"amd64": unix.AUDIT_ARCH_X86_64, "arm64": unix.AUDIT_ARCH_AARCH64}[runtime.GOARCH]
	const (
		ld, jeq, jge, ret = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, unix.BPF_RET | unix.BPF_K
		deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	)
	filter := []unix.SockFilter{
		{Code: ld, K: 4}, // seccomp_data.arch
		{Code: jeq, Jt: 1, K: arch},
		{Code: ret, K: deny},
		{Code: ld, K: 0},                  // seccomp_data.nr
		{Code: jge, Jt: 5, K: 0x40000000}, // x32
		{Code: jeq, Jt: 4, K: unix.SYS_IO_URING_SETUP},
		{Code: jeq, Jf: 2, K: unix.SYS_SOCKET},
		{Code: ld, K: 16}, // low 32 bits of args[0], the address family
		{Code: jeq, Jf: 1, K: unix.AF_UNIX},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		{Code: ret, K: deny},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	return unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0)
}
