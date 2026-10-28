//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestEndToEnd builds this reference consumer and runs test.sh against it:
// every case confined through the helper and as an unconfined control.
// It needs Linux and python3, and runs only when NIC_RECIPE_E2E=1 because it
// starts local servers. Below Landlock ABI 3 only the refusal rows can run,
// and the test is skipped (unsupported), never reported as passed.
func TestEndToEnd(t *testing.T) {
	if os.Getenv("NIC_RECIPE_E2E") != "1" {
		t.Skip("set NIC_RECIPE_E2E=1 to run")
	}
	bin := filepath.Join(t.TempDir(), "recipe-test")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command("bash", "test.sh", bin).CombinedOutput()
	t.Logf("%s", out)
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit) && exit.ExitCode() == 3:
		t.Skipf("UNSUPPORTED: Landlock ABI %d is below 3 on this kernel; the launcher refused every policy as it should, but no confinement was tested", landlockABI())
	default:
		t.Fatalf("test.sh: %v", err)
	}
}
