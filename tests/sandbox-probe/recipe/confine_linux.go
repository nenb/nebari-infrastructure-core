//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"unsafe"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// Policy is what a confined command may do.
type Policy struct {
	WorkDir   string   // read, write, create, remove, move and link beneath it
	ReadOnly  []string // read and execute beneath, e.g. /usr, /etc, /proc
	ReadWrite []string // read and write, e.g. /dev/null
	ProxyPort uint16   // ABI 4+: the only TCP port connect may use; 0 for none
	NoInet    bool     // seccomp: no IP, packet or netlink sockets at all
}

const confineArg = "__confine"

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
	if err := json.Unmarshal([]byte(policyJSON), &p); err != nil || len(argv) == 0 {
		return errors.Join(errors.New("bad policy or empty command"), err)
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	if landlockABI() < 3 { // best effort would silently do less: refuse instead
		return errors.New("Landlock ABI 3 or newer is required")
	}
	runtime.LockOSThread() // the seccomp filter applies to this thread, which then execs
	if err := applyLandlock(p); err != nil {
		return err
	}
	if p.NoInet {
		if err := denyInetSockets(); err != nil {
			return err
		}
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err // inherited descriptors must not reach the command
	}
	return unix.Exec(path, argv, os.Environ())
}

// landlockABI returns the kernel's Landlock ABI, or 0 if Landlock is absent
// (ENOSYS) or not enabled at boot (EOPNOTSUPP).
func landlockABI() int {
	abi, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		return 0
	}
	return abi
}

// applyLandlock handles every right go-landlock knows (V11), degrading to what the
// running kernel supports, and grants: everything beneath the work directory,
// including moves and links within it (REFER) and connecting to Unix sockets
// there; read and execute beneath p.ReadOnly; read and write on p.ReadWrite;
// and, at ABI 4+, TCP connect to p.ProxyPort only. At ABI 6+ the command may
// not signal, or reach abstract Unix sockets of, processes outside the sandbox.
// It also sets no_new_privs.
func applyLandlock(p Policy) error {
	rules := []landlock.Rule{
		landlock.RWDirs(p.WorkDir).WithRefer().WithResolveUnix(),
		landlock.RODirs(p.ReadOnly...).IgnoreIfMissing(),
		landlock.RWFiles(p.ReadWrite...).IgnoreIfMissing(),
	}
	if p.ProxyPort != 0 {
		rules = append(rules, landlock.ConnectTCP(p.ProxyPort))
	}
	return landlock.V11.BestEffort().Restrict(rules...)
}

// denyInetSockets installs a seccomp filter that makes socket() fail with
// EPERM for AF_INET, AF_INET6, AF_PACKET and AF_NETLINK (AF_UNIX stays
// available, for example for a proxy socket in the work directory). It also
// refuses io_uring, which can create sockets without calling socket(), and
// any syscall from a foreign or x32 ABI.
func denyInetSockets() error {
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
		{Code: ld, K: 0}, // seccomp_data.nr
		{Code: jge, Jt: 8, K: 0x40000000}, // x32
		{Code: jeq, Jt: 7, K: unix.SYS_IO_URING_SETUP},
		{Code: jeq, Jf: 5, K: unix.SYS_SOCKET},
		{Code: ld, K: 16}, // low 32 bits of args[0], the address family
		{Code: jeq, Jt: 4, K: unix.AF_INET},
		{Code: jeq, Jt: 3, K: unix.AF_INET6},
		{Code: jeq, Jt: 2, K: unix.AF_PACKET},
		{Code: jeq, Jt: 1, K: unix.AF_NETLINK},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		{Code: ret, K: deny},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	return unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0)
}
