//go:build !linux

package main

import (
	"fmt"
	"os"
	"runtime"
)

func runProbe() probeResult {
	return unsupportedOSResult(runtime.GOARCH)
}

func runChild(_ []string) {
	fmt.Fprintln(os.Stderr, "probe child modes run only on Linux")
}
