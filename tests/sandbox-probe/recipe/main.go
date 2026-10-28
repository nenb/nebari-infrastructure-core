//go:build linux

// Reference consumer for §20.8. confine_linux.go is the code in the design doc, verbatim;
// this file only wraps it.
//
//	recipe-test agent <policy-json> <leak-file> <cmd> [args...]   confined, via the helper
//	recipe-test control <leak-file> <cmd> [args...]               unconfined control
//
// In both modes the "agent" first puts a canary secret in its environment and
// leaks a writable, non-close-on-exec descriptor to <leak-file> as fd 9.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == confineArg {
		err := confineAndExec(os.Args[2], os.Args[3:]) // returns only on failure
		fmt.Fprintln(os.Stderr, "confine:", err)
		os.Exit(126)
	}
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: recipe-test agent <policy> <leak-file> cmd... | control <leak-file> cmd...")
		os.Exit(2)
	}
	os.Setenv("AGENT_SECRET", "canary-6f1c")
	var cmd *exec.Cmd
	var err error
	switch os.Args[1] {
	case "agent":
		leak(os.Args[3])
		var p Policy
		if err = json.Unmarshal([]byte(os.Args[2]), &p); err == nil {
			cmd, err = confinedCommand(p, os.Args[4:]...) // the documented agent side
		}
	case "control":
		leak(os.Args[2])
		cmd = exec.Command(os.Args[3], os.Args[4:]...)
		cmd.Env = os.Environ()
	default:
		err = errors.New("unknown mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func leak(path string) {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_APPEND, 0) // no O_CLOEXEC
	if err != nil {
		fmt.Fprintln(os.Stderr, "leak:", err)
		os.Exit(2)
	}
	if err := syscall.Dup3(fd, 9, 0); err != nil {
		fmt.Fprintln(os.Stderr, "leak:", err)
		os.Exit(2)
	}
}
