package main

import (
	"strings"
	"testing"
)

func TestParseProcessStatus(t *testing.T) {
	t.Parallel()

	status, err := parseProcessStatus(strings.NewReader(`Name:	psr-probe
NoNewPrivs:	1
Seccomp:	2
Seccomp_filters:	3
`))
	if err != nil {
		t.Fatalf("parseProcessStatus() error = %v", err)
	}
	if status.Seccomp != 2 {
		t.Errorf("Seccomp = %d, want 2", status.Seccomp)
	}
	if status.SeccompFilters != 3 {
		t.Errorf("SeccompFilters = %d, want 3", status.SeccompFilters)
	}
	if !status.NoNewPrivs {
		t.Error("NoNewPrivs = false, want true")
	}
}

func TestParseProcessStatusRequiresFacts(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		input string
	}{
		{name: "missing seccomp", input: "NoNewPrivs: 1\n"},
		{name: "missing no new privileges", input: "Seccomp: 2\n"},
		{name: "invalid value", input: "Seccomp: filtered\nNoNewPrivs: 1\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseProcessStatus(strings.NewReader(test.input)); err == nil {
				t.Fatal("parseProcessStatus() error = nil, want an error")
			}
		})
	}
}

func TestCapabilityPass(t *testing.T) {
	t.Parallel()

	passing := emptyProbeResult()
	passing.Landlock.Status = "enabled"
	passing.Landlock.ABI = 3
	passing.Landlock.FS = landlockFSResult{
		ControlOK:      true,
		AllowedWrite:   "ok",
		DeniedWrite:    "EACCES",
		DeniedTruncate: "EACCES",
	}
	passing.SeccompNotify = seccompNotifyResult{
		StackedFilters:       "ok",
		ListenerTransfer:     "ok",
		NotificationReceived: "ok",
		AddfdSend:            "ok",
		MarkerRead:           "ok",
	}

	tests := []struct {
		name   string
		mutate func(*probeResult)
		want   bool
	}{
		{name: "all required checks pass", mutate: func(*probeResult) {}, want: true},
		{name: "ABI below floor", mutate: func(result *probeResult) { result.Landlock.ABI = 2 }},
		{name: "positive control fails", mutate: func(result *probeResult) { result.Landlock.FS.ControlOK = false }},
		{name: "write not denied", mutate: func(result *probeResult) { result.Landlock.FS.DeniedWrite = "ok" }},
		{name: "truncate not denied", mutate: func(result *probeResult) { result.Landlock.FS.DeniedTruncate = "ok" }},
		{name: "descriptor marker missing", mutate: func(result *probeResult) { result.SeccompNotify.MarkerRead = "EOF" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := passing
			test.mutate(&result)
			if got := capabilityPass(result); got != test.want {
				t.Errorf("capabilityPass() = %t, want %t", got, test.want)
			}
		})
	}
}
