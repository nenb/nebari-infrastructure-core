//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func runProbe() probeResult {
	result := emptyProbeResult()
	result.Node = os.Getenv("NODE_NAME")
	result.Arch = runtime.GOARCH

	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("uname: %v", err))
	} else {
		result.Kernel = nulTerminatedString(uts.Release[:])
	}

	statusFile, err := os.Open("/proc/self/status")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("open /proc/self/status: %v", err))
	} else {
		status, parseErr := parseProcessStatus(statusFile)
		_ = statusFile.Close()
		if parseErr != nil {
			result.Errors = append(result.Errors, parseErr.Error())
		} else {
			result.SeccompMode = status.Seccomp
			result.SeccompFilters = status.SeccompFilters
			result.NoNewPrivs = status.NoNewPrivs
		}
	}

	abi, landlockStatus, err := landlockABI()
	result.Landlock.ABI = abi
	result.Landlock.Status = landlockStatus
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("query Landlock ABI: %v", err))
	}
	if landlockStatus == "enabled" {
		fs, fsErr := runLandlockFSProbe(abi)
		result.Landlock.FS = fs
		if fsErr != nil {
			result.Landlock.FS.Error = fsErr.Error()
			result.Errors = append(result.Errors, fmt.Sprintf("Landlock filesystem probe: %v", fsErr))
		}
		if abi >= 4 {
			network, networkErr := runLandlockNetProbe()
			result.Landlock.Net = network
			if networkErr != nil {
				result.Landlock.Net.Error = networkErr.Error()
				result.Errors = append(result.Errors, fmt.Sprintf("Landlock network probe: %v", networkErr))
			}
		} else {
			result.Landlock.Net = notApplicableNetResult()
		}
	}

	seccomp, err := runSeccompNotifyProbe()
	result.SeccompNotify = seccomp
	if err != nil {
		result.SeccompNotify.Error = err.Error()
		result.Errors = append(result.Errors, fmt.Sprintf("seccomp notification probe: %v", err))
	}

	result.Verdicts = deriveVerdicts(result)
	return result
}

func runChild(args []string) {
	switch args[0] {
	case "--child=landlock-fs":
		abi, err := requiredIntArg(args, 1, "Landlock ABI")
		if err != nil {
			emitChild(map[string]string{"error": err.Error()})
			return
		}
		emitChild(runLandlockFSChild(abi))
	case "--child=landlock-net":
		if len(args) != 5 {
			emitChild(map[string]string{"error": "landlock-net requires four port arguments"})
			return
		}
		ports := make([]int, 4)
		for index := range ports {
			value, err := requiredIntArg(args, index+1, "port")
			if err != nil {
				emitChild(map[string]string{"error": err.Error()})
				return
			}
			ports[index] = value
		}
		emitChild(runLandlockNetChild(ports[0], ports[1], ports[2], ports[3]))
	case "--child=seccomp":
		emitChild(runSeccompNotifyChild(3))
	default:
		emitChild(map[string]string{"error": "unknown child mode"})
	}
}

func emitChild(value any) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fmt.Fprintf(os.Stderr, "encode child result: %v\n", err)
	}
}

func requiredIntArg(args []string, index int, name string) (int, error) {
	if len(args) <= index {
		return 0, fmt.Errorf("missing %s", name)
	}
	value, err := strconv.Atoi(args[index])
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return value, nil
}

func nulTerminatedString(value []byte) string {
	if index := strings.IndexByte(string(value), 0); index >= 0 {
		value = value[:index]
	}
	return string(value)
}

func notApplicableNetResult() landlockNetResult {
	return landlockNetResult{
		ControlAllowedConnect: "not_applicable",
		ControlDeniedConnect:  "not_applicable",
		ControlBind:           "not_applicable",
		AllowedConnect:        "not_applicable",
		DeniedConnect:         "not_applicable",
		Bind:                  "not_applicable",
		UDPSendto:             "not_applicable",
	}
}
