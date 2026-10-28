//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const landlockRuleNetPort = 2

type landlockNetPortAttr struct {
	AllowedAccess uint64
	Port          uint64
}

func landlockABI() (int, string, error) {
	value, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		unix.LANDLOCK_CREATE_RULESET_VERSION,
		0,
		0,
		0,
	)
	if errno == 0 {
		return int(value), "enabled", nil
	}
	switch errno {
	case unix.EOPNOTSUPP:
		return 0, "disabled", nil
	case unix.ENOSYS:
		return 0, "unsupported", nil
	default:
		return 0, "error", errno
	}
}

func runLandlockFSProbe(abi int) (landlockFSResult, error) {
	var result landlockFSResult
	if err := runJSONChild([]string{"--child=landlock-fs", strconv.Itoa(abi)}, &result); err != nil {
		return result, err
	}
	if result.Error != "" {
		message := result.Error
		result.Error = ""
		return result, errors.New(message)
	}
	return result, nil
}

func runLandlockFSChild(abi int) landlockFSResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	result := landlockFSResult{
		ControlAllowedWrite:   "not_run",
		ControlDeniedWrite:    "not_run",
		AllowedWrite:          "not_run",
		DeniedWrite:           "not_run",
		ControlDeniedTruncate: "not_applicable",
		DeniedTruncate:        "not_applicable",
	}

	base := "/tmp/psr-probe-landlock"
	allowedDir := base + "/allowed"
	deniedDir := base + "/denied"
	if err := os.RemoveAll(base); err != nil {
		result.Error = fmt.Sprintf("remove old test directory: %v", err)
		return result
	}
	if err := os.MkdirAll(allowedDir, 0o700); err != nil {
		result.Error = fmt.Sprintf("create allowed directory: %v", err)
		return result
	}
	if err := os.MkdirAll(deniedDir, 0o700); err != nil {
		result.Error = fmt.Sprintf("create denied directory: %v", err)
		return result
	}

	result.ControlAllowedWrite = outcome(os.WriteFile(allowedDir+"/control", []byte("control"), 0o600))
	result.ControlDeniedWrite = outcome(os.WriteFile(deniedDir+"/control", []byte("control"), 0o600))
	if abi >= 3 {
		truncatePath := deniedDir + "/truncate"
		if err := os.WriteFile(truncatePath, []byte("truncate-control"), 0o600); err != nil {
			result.ControlDeniedTruncate = outcome(err)
		} else {
			result.ControlDeniedTruncate = outcome(os.Truncate(truncatePath, 1))
			if err := os.WriteFile(truncatePath, []byte("truncate-denial"), 0o600); err != nil {
				result.Error = fmt.Sprintf("restore truncate test file: %v", err)
				return result
			}
		}
	}
	result.ControlOK = result.ControlAllowedWrite == "ok" &&
		result.ControlDeniedWrite == "ok" &&
		(abi < 3 || result.ControlDeniedTruncate == "ok")
	if !result.ControlOK {
		result.Error = "one or more filesystem positive controls failed"
		return result
	}

	if err := setNoNewPrivs(); err != nil {
		result.Error = fmt.Sprintf("set no_new_privs: %v", err)
		return result
	}

	handled := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE)
	if abi >= 3 {
		handled |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	rulesetFD, err := landlockCreateRuleset(unsafe.Pointer(&attr), unsafe.Sizeof(attr.Access_fs))
	if err != nil {
		result.Error = fmt.Sprintf("create filesystem ruleset: %v", err)
		return result
	}
	defer unix.Close(rulesetFD)

	allowedFD, err := unix.Open(allowedDir, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		result.Error = fmt.Sprintf("open allowed directory: %v", err)
		return result
	}
	pathRule := unix.LandlockPathBeneathAttr{
		Allowed_access: handled,
		Parent_fd:      int32(allowedFD),
	}
	err = landlockAddRule(rulesetFD, unix.LANDLOCK_RULE_PATH_BENEATH, unsafe.Pointer(&pathRule))
	_ = unix.Close(allowedFD)
	if err != nil {
		result.Error = fmt.Sprintf("add allowed path rule: %v", err)
		return result
	}
	if err := landlockRestrictSelf(rulesetFD); err != nil {
		result.Error = fmt.Sprintf("restrict filesystem access: %v", err)
		return result
	}

	result.AllowedWrite = outcome(os.WriteFile(allowedDir+"/after", []byte("allowed"), 0o600))
	result.DeniedWrite = outcome(os.WriteFile(deniedDir+"/after", []byte("denied"), 0o600))
	if abi >= 3 {
		result.DeniedTruncate = outcome(os.Truncate(deniedDir+"/truncate", 0))
	}
	return result
}

func runLandlockNetProbe() (landlockNetResult, error) {
	result := landlockNetResult{
		ControlAllowedConnect: "not_run",
		ControlDeniedConnect:  "not_run",
		ControlBind:           "not_run",
		AllowedConnect:        "not_run",
		DeniedConnect:         "not_run",
		Bind:                  "not_run",
		UDPSendto:             "not_run",
	}

	allowedListener, err := listenTCP()
	if err != nil {
		return result, fmt.Errorf("listen on allowed control port: %w", err)
	}
	defer allowedListener.Close()
	deniedListener, err := listenTCP()
	if err != nil {
		return result, fmt.Errorf("listen on denied control port: %w", err)
	}
	defer deniedListener.Close()
	acceptUntilClosed(allowedListener)
	acceptUntilClosed(deniedListener)

	bindListener, err := listenTCP()
	if err != nil {
		return result, fmt.Errorf("reserve bind control port: %w", err)
	}
	bindPort := bindListener.Addr().(*net.TCPAddr).Port
	if err := bindListener.Close(); err != nil {
		return result, fmt.Errorf("release bind control port: %w", err)
	}

	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return result, fmt.Errorf("listen for UDP control packet: %w", err)
	}
	defer udpListener.Close()
	udpPort := udpListener.LocalAddr().(*net.UDPAddr).Port
	udpReceived := make(chan bool, 1)
	go func() {
		_ = udpListener.SetReadDeadline(time.Now().Add(10 * time.Second))
		buffer := make([]byte, 32)
		count, _, readErr := udpListener.ReadFromUDP(buffer)
		udpReceived <- readErr == nil && string(buffer[:count]) == "landlock-udp"
	}()

	args := []string{
		"--child=landlock-net",
		strconv.Itoa(allowedListener.Addr().(*net.TCPAddr).Port),
		strconv.Itoa(deniedListener.Addr().(*net.TCPAddr).Port),
		strconv.Itoa(bindPort),
		strconv.Itoa(udpPort),
	}
	if err := runJSONChild(args, &result); err != nil {
		return result, err
	}
	result.UDPReceived = <-udpReceived
	if result.Error != "" {
		message := result.Error
		result.Error = ""
		return result, errors.New(message)
	}
	return result, nil
}

func runLandlockNetChild(allowedPort, deniedPort, bindPort, udpPort int) landlockNetResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	result := landlockNetResult{
		ControlAllowedConnect: outcome(tcpConnect(allowedPort)),
		ControlDeniedConnect:  outcome(tcpConnect(deniedPort)),
		ControlBind:           outcome(tcpBind(bindPort)),
		AllowedConnect:        "not_run",
		DeniedConnect:         "not_run",
		Bind:                  "not_run",
		UDPSendto:             "not_run",
	}
	result.ControlOK = result.ControlAllowedConnect == "ok" &&
		result.ControlDeniedConnect == "ok" &&
		result.ControlBind == "ok"
	if !result.ControlOK {
		result.Error = "one or more network positive controls failed"
		return result
	}
	if err := setNoNewPrivs(); err != nil {
		result.Error = fmt.Sprintf("set no_new_privs: %v", err)
		return result
	}

	handled := uint64(unix.LANDLOCK_ACCESS_NET_CONNECT_TCP | unix.LANDLOCK_ACCESS_NET_BIND_TCP)
	attr := unix.LandlockRulesetAttr{Access_net: handled}
	rulesetFD, err := landlockCreateRuleset(unsafe.Pointer(&attr), unsafe.Offsetof(attr.Scoped))
	if err != nil {
		result.Error = fmt.Sprintf("create network ruleset: %v", err)
		return result
	}
	defer unix.Close(rulesetFD)

	portRule := landlockNetPortAttr{
		AllowedAccess: unix.LANDLOCK_ACCESS_NET_CONNECT_TCP,
		Port:          uint64(allowedPort),
	}
	if err := landlockAddRule(rulesetFD, landlockRuleNetPort, unsafe.Pointer(&portRule)); err != nil {
		result.Error = fmt.Sprintf("add allowed TCP port rule: %v", err)
		return result
	}
	if err := landlockRestrictSelf(rulesetFD); err != nil {
		result.Error = fmt.Sprintf("restrict network access: %v", err)
		return result
	}

	result.AllowedConnect = outcome(tcpConnect(allowedPort))
	result.DeniedConnect = outcome(tcpConnect(deniedPort))
	result.Bind = outcome(tcpBind(bindPort))
	result.UDPSendto = outcome(udpSendto(udpPort))
	return result
}

func landlockCreateRuleset(attr unsafe.Pointer, size uintptr) (int, error) {
	value, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(attr), size, 0, 0, 0, 0)
	runtime.KeepAlive(attr)
	if errno != 0 {
		return -1, errno
	}
	return int(value), nil
}

func landlockAddRule(rulesetFD, ruleType int, attr unsafe.Pointer) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFD),
		uintptr(ruleType),
		uintptr(attr),
		0,
		0,
		0,
	)
	runtime.KeepAlive(attr)
	if errno != 0 {
		return errno
	}
	return nil
}

func landlockRestrictSelf(rulesetFD int) error {
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func setNoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

func tcpConnect(port int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
}

func tcpBind(port int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Bind(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
}

func udpSendto(port int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Sendto(fd, []byte("landlock-udp"), 0, &unix.SockaddrInet4{
		Port: port,
		Addr: [4]byte{127, 0, 0, 1},
	})
}

func listenTCP() (*net.TCPListener, error) {
	return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

func acceptUntilClosed(listener *net.TCPListener) {
	go func() {
		for {
			connection, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
}

func runJSONChild(args []string, target any) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate probe executable: %w", err)
	}
	command := exec.Command(executable, args...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("run child: %w: %s", err, stderr.String())
	}
	if err := json.Unmarshal(output, target); err != nil {
		return fmt.Errorf("decode child result %q: %w", string(output), err)
	}
	return nil
}

func outcome(err error) string {
	if err == nil {
		return "ok"
	}
	for _, candidate := range []struct {
		err  error
		name string
	}{
		{unix.EACCES, "EACCES"},
		{unix.EPERM, "EPERM"},
		{unix.ENOSYS, "ENOSYS"},
		{unix.EOPNOTSUPP, "EOPNOTSUPP"},
		{unix.ECONNREFUSED, "ECONNREFUSED"},
		{unix.ENOENT, "ENOENT"},
	} {
		if errors.Is(err, candidate.err) {
			return candidate.name
		}
	}
	return err.Error()
}
