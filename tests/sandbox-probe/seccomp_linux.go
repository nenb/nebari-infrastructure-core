//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const seccompTriggerPath = "/psr-probe-seccomp-trigger"

var seccompMarker = []byte("psr-addfd-marker")

type seccompData struct {
	Number             int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type seccompNotification struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompData
}

type seccompNotificationAddFD struct {
	ID         uint64
	Flags      uint32
	SourceFD   uint32
	NewFD      uint32
	NewFDFlags uint32
}

func runSeccompNotifyProbe() (result seccompNotifyResult, returnedErr error) {
	result = seccompNotifyResult{
		StackedFilters:       "not_run",
		ListenerTransfer:     "not_run",
		NotificationReceived: "not_run",
		AddfdSend:            "not_run",
		MarkerRead:           "not_run",
	}

	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return result, fmt.Errorf("create descriptor-transfer socket pair: %w", err)
	}
	parentSocket := sockets[0]
	childSocket := os.NewFile(uintptr(sockets[1]), "seccomp-child-socket")
	defer unix.Close(parentSocket)

	pipeFDs := []int{0, 0}
	if err := unix.Pipe2(pipeFDs, unix.O_CLOEXEC); err != nil {
		_ = childSocket.Close()
		return result, fmt.Errorf("create injection pipe: %w", err)
	}
	defer unix.Close(pipeFDs[0])
	if _, err := unix.Write(pipeFDs[1], seccompMarker); err != nil {
		_ = unix.Close(pipeFDs[1])
		_ = childSocket.Close()
		return result, fmt.Errorf("write injection marker: %w", err)
	}
	if err := unix.Close(pipeFDs[1]); err != nil {
		_ = childSocket.Close()
		return result, fmt.Errorf("close injection pipe writer: %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		_ = childSocket.Close()
		return result, fmt.Errorf("locate probe executable: %w", err)
	}
	command := exec.Command(executable, "--child=seccomp")
	command.ExtraFiles = []*os.File{childSocket}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		_ = childSocket.Close()
		return result, fmt.Errorf("start seccomp child: %w", err)
	}
	_ = childSocket.Close()
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()

	listenerFD, err := receiveFD(parentSocket, 10*time.Second)
	if err != nil {
		return result, fmt.Errorf("receive seccomp listener: %w", err)
	}
	defer unix.Close(listenerFD)
	result.ListenerTransfer = "ok"

	if err := waitReadable(listenerFD, 10*time.Second); err != nil {
		return result, fmt.Errorf("wait for seccomp notification: %w", err)
	}
	var notification seccompNotification
	if err := ioctlPointer(listenerFD, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&notification)); err != nil {
		return result, fmt.Errorf("receive seccomp notification: %w", err)
	}
	if notification.Data.Number != int32(unix.SYS_OPENAT) {
		return result, fmt.Errorf("received syscall %d, want openat (%d)", notification.Data.Number, unix.SYS_OPENAT)
	}
	result.NotificationReceived = "ok"

	addFD := seccompNotificationAddFD{
		ID:         notification.ID,
		Flags:      unix.SECCOMP_ADDFD_FLAG_SEND,
		SourceFD:   uint32(pipeFDs[0]),
		NewFDFlags: unix.O_CLOEXEC,
	}
	if err := ioctlPointer(listenerFD, unix.SECCOMP_IOCTL_NOTIF_ADDFD, unsafe.Pointer(&addFD)); err != nil {
		return result, fmt.Errorf("inject descriptor and send response: %w", err)
	}
	result.AddfdSend = "ok"

	if err := waitForCommand(command, 10*time.Second); err != nil {
		waited = true
		return result, fmt.Errorf("wait for seccomp child: %w: %s", err, stderr.String())
	}
	waited = true

	var childResult seccompNotifyResult
	if err := json.Unmarshal(stdout.Bytes(), &childResult); err != nil {
		return result, fmt.Errorf("decode seccomp child result %q: %w", stdout.String(), err)
	}
	childResult.NotificationReceived = result.NotificationReceived
	childResult.AddfdSend = result.AddfdSend
	if childResult.ListenerTransfer == "not_run" {
		childResult.ListenerTransfer = result.ListenerTransfer
	}
	if childResult.Error != "" {
		message := childResult.Error
		childResult.Error = ""
		return childResult, fmt.Errorf("child: %s", message)
	}
	return childResult, nil
}

func runSeccompNotifyChild(commFD int) seccompNotifyResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	result := seccompNotifyResult{
		StackedFilters:       "not_run",
		ListenerTransfer:     "not_run",
		NotificationReceived: "reported_by_parent",
		AddfdSend:            "reported_by_parent",
		MarkerRead:           "not_run",
	}
	if err := setNoNewPrivs(); err != nil {
		result.Error = fmt.Sprintf("set no_new_privs: %v", err)
		return result
	}

	allowFilter := []unix.SockFilter{{
		Code: uint16(unix.BPF_RET | unix.BPF_K),
		K:    unix.SECCOMP_RET_ALLOW,
	}}
	if _, err := installSeccompFilter(allowFilter, 0); err != nil {
		result.Error = fmt.Sprintf("install allow filter: %v", err)
		result.StackedFilters = outcome(err)
		return result
	}

	notifyFilter := []unix.SockFilter{
		{
			Code: uint16(unix.BPF_LD | unix.BPF_W | unix.BPF_ABS),
			K:    0,
		},
		{
			Code: uint16(unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K),
			Jf:   1,
			K:    uint32(unix.SYS_OPENAT),
		},
		{
			Code: uint16(unix.BPF_RET | unix.BPF_K),
			K:    unix.SECCOMP_RET_USER_NOTIF,
		},
		{
			Code: uint16(unix.BPF_RET | unix.BPF_K),
			K:    unix.SECCOMP_RET_ALLOW,
		},
	}
	listenerFD, err := installSeccompFilter(notifyFilter, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER)
	if err != nil {
		result.Error = fmt.Sprintf("install notification filter: %v", err)
		result.StackedFilters = outcome(err)
		return result
	}
	result.StackedFilters = "ok"

	if err := sendFD(commFD, listenerFD); err != nil {
		_ = unix.Close(listenerFD)
		result.Error = fmt.Sprintf("send listener descriptor: %v", err)
		result.ListenerTransfer = outcome(err)
		return result
	}
	_ = unix.Close(listenerFD)
	result.ListenerTransfer = "ok"

	path, err := unix.BytePtrFromString(seccompTriggerPath)
	if err != nil {
		result.Error = fmt.Sprintf("build trigger path: %v", err)
		return result
	}
	directoryFD := unix.AT_FDCWD
	value, _, errno := unix.RawSyscall6(
		unix.SYS_OPENAT,
		uintptr(directoryFD),
		uintptr(unsafe.Pointer(path)),
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
		0,
		0,
	)
	runtime.KeepAlive(path)
	if errno != 0 {
		result.MarkerRead = outcome(errno)
		result.Error = fmt.Sprintf("trigger syscall: %v", errno)
		return result
	}
	injectedFile := os.NewFile(value, "injected-marker")
	if injectedFile == nil {
		result.Error = "convert injected descriptor to file"
		return result
	}
	defer injectedFile.Close()
	marker := make([]byte, len(seccompMarker))
	if _, err := io.ReadFull(injectedFile, marker); err != nil {
		result.MarkerRead = outcome(err)
		result.Error = fmt.Sprintf("read injected descriptor: %v", err)
		return result
	}
	if !bytes.Equal(marker, seccompMarker) {
		result.MarkerRead = "wrong_marker"
		result.Error = fmt.Sprintf("read marker %q, want %q", marker, seccompMarker)
		return result
	}
	result.MarkerRead = "ok"
	return result
}

func installSeccompFilter(filters []unix.SockFilter, flags uintptr) (int, error) {
	program := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}
	value, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		flags,
		uintptr(unsafe.Pointer(&program)),
	)
	runtime.KeepAlive(filters)
	runtime.KeepAlive(program)
	if errno != 0 {
		return -1, errno
	}
	return int(value), nil
}

func sendFD(socketFD, descriptor int) error {
	return unix.Sendmsg(socketFD, []byte{1}, unix.UnixRights(descriptor), nil, 0)
}

func receiveFD(socketFD int, timeout time.Duration) (int, error) {
	if err := waitReadable(socketFD, timeout); err != nil {
		return -1, err
	}
	payload := make([]byte, 1)
	control := make([]byte, unix.CmsgSpace(4))
	count, controlCount, _, _, err := unix.Recvmsg(socketFD, payload, control, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return -1, err
	}
	if count != 1 {
		return -1, fmt.Errorf("received %d payload bytes, want 1", count)
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlCount])
	if err != nil {
		return -1, fmt.Errorf("parse control message: %w", err)
	}
	for index := range messages {
		descriptors, err := unix.ParseUnixRights(&messages[index])
		if err != nil {
			return -1, fmt.Errorf("parse descriptor rights: %w", err)
		}
		if len(descriptors) == 1 {
			return descriptors[0], nil
		}
	}
	return -1, fmt.Errorf("control message contained no descriptor")
}

func waitReadable(fd int, timeout time.Duration) error {
	pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("timed out after %s", timeout)
		}
		ready, err := unix.Poll(pollFDs, int(remaining.Milliseconds()))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 0 {
			return fmt.Errorf("timed out after %s", timeout)
		}
		if pollFDs[0].Revents&unix.POLLIN != 0 {
			return nil
		}
		return fmt.Errorf("descriptor poll returned events %#x", pollFDs[0].Revents)
	}
}

func ioctlPointer(fd int, request uint, pointer unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(pointer))
	runtime.KeepAlive(pointer)
	if errno != 0 {
		return errno
	}
	return nil
}

func waitForCommand(command *exec.Cmd, timeout time.Duration) error {
	waited := make(chan error, 1)
	go func() {
		waited <- command.Wait()
	}()
	select {
	case err := <-waited:
		return err
	case <-time.After(timeout):
		_ = command.Process.Kill()
		<-waited
		return fmt.Errorf("timed out after %s", timeout)
	}
}
