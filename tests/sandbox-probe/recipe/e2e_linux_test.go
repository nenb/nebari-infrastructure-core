//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestEndToEnd builds this reference consumer and runs test.sh against it:
// every case confined through the helper and as an unconfined control.
// It needs Linux with Landlock ABI 3+ and python3, and runs only when
// NIC_RECIPE_E2E=1 because it starts local servers.
func TestEndToEnd(t *testing.T) {
	if os.Getenv("NIC_RECIPE_E2E") != "1" {
		t.Skip("set NIC_RECIPE_E2E=1 to run")
	}
	if landlockABI() < 3 {
		t.Skip("Landlock ABI 3 or newer is not available")
	}
	bin := filepath.Join(t.TempDir(), "recipe-test")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command("bash", "test.sh", bin).CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("test.sh: %v", err)
	}
}
