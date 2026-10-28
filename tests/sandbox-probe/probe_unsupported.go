//go:build !linux

package main

import "runtime"

func execute(_ []string) (probeResult, bool) {
	result := emptyProbeResult()
	result.Arch = runtime.GOARCH
	result.Landlock.Status = "unsupported_os"
	result.Errors = append(result.Errors, "the sandbox probe must run on Linux")
	return result, true
}
