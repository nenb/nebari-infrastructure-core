package main

import (
	"bytes"
	"encoding/json"
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

func passingResult(abi int) probeResult {
	result := emptyProbeResult()
	result.Landlock.Status = "enabled"
	result.Landlock.ABI = abi
	result.Landlock.FS = landlockFSResult{
		ControlOK:      true,
		AllowedWrite:   "ok",
		DeniedWrite:    "EACCES",
		DeniedTruncate: "EACCES",
	}
	if abi >= 4 {
		result.Landlock.Net = landlockNetResult{
			ControlOK:      true,
			AllowedConnect: "ok",
			DeniedConnect:  "EACCES",
			Bind:           "EACCES",
			UDPSendto:      "ok",
			UDPReceived:    true,
		}
	} else {
		result.Landlock.Net = landlockNetResult{
			AllowedConnect: "not_applicable",
			DeniedConnect:  "not_applicable",
			Bind:           "not_applicable",
		}
	}
	result.SeccompNotify = seccompNotifyResult{
		StackedFilters:       "ok",
		ListenerTransfer:     "ok",
		NotificationReceived: "ok",
		AddfdSend:            "ok",
		MarkerRead:           "ok",
	}
	return result
}

func TestDeriveVerdicts(t *testing.T) {
	t.Parallel()

	const pass, fail, na = verdictPass, verdictFail, verdictNotApplicable
	tests := []struct {
		name   string
		abi    int
		mutate func(*probeResult)
		want   verdicts
	}{
		{name: "ABI 4, everything passes", abi: 4, mutate: func(*probeResult) {},
			want: verdicts{pass, pass, pass, pass}},
		{name: "ABI 3: TCP not applicable", abi: 3, mutate: func(*probeResult) {},
			want: verdicts{pass, na, pass, pass}},
		{name: "forbidden TCP connect succeeded", abi: 6,
			mutate: func(r *probeResult) { r.Landlock.Net.DeniedConnect = "ok" },
			want:   verdicts{pass, fail, pass, fail}},
		{name: "forbidden TCP bind succeeded", abi: 6,
			mutate: func(r *probeResult) { r.Landlock.Net.Bind = "ok" },
			want:   verdicts{pass, fail, pass, fail}},
		{name: "network probe error", abi: 4,
			mutate: func(r *probeResult) { r.Landlock.Net.Error = "listen on allowed control port: EADDRINUSE" },
			want:   verdicts{pass, fail, pass, fail}},
		{name: "network probe never ran at ABI 4", abi: 4,
			mutate: func(r *probeResult) { r.Landlock.Net = emptyProbeResult().Landlock.Net },
			want:   verdicts{pass, fail, pass, fail}},
		{name: "network positive control failed", abi: 4,
			mutate: func(r *probeResult) { r.Landlock.Net.ControlOK = false },
			want:   verdicts{pass, fail, pass, fail}},
		{name: "seccomp notification unavailable, Landlock fine", abi: 4,
			mutate: func(r *probeResult) {
				r.SeccompNotify = emptyProbeResult().SeccompNotify
				r.SeccompNotify.StackedFilters = "EACCES"
				r.SeccompNotify.Error = "install notification filter: permission denied"
			},
			want: verdicts{pass, pass, fail, pass}},
		{name: "seccomp descriptor marker missing", abi: 6,
			mutate: func(r *probeResult) { r.SeccompNotify.MarkerRead = "EOF" },
			want:   verdicts{pass, pass, fail, pass}},
		{name: "ABI below floor", abi: 2, mutate: func(*probeResult) {},
			want: verdicts{fail, na, pass, fail}},
		{name: "filesystem positive control failed", abi: 4,
			mutate: func(r *probeResult) { r.Landlock.FS.ControlOK = false },
			want:   verdicts{fail, pass, pass, fail}},
		{name: "write not denied", abi: 4,
			mutate: func(r *probeResult) { r.Landlock.FS.DeniedWrite = "ok" },
			want:   verdicts{fail, pass, pass, fail}},
		{name: "truncate not denied", abi: 4,
			mutate: func(r *probeResult) { r.Landlock.FS.DeniedTruncate = "ok" },
			want:   verdicts{fail, pass, pass, fail}},
		{name: "filesystem probe error", abi: 4,
			mutate: func(r *probeResult) { r.Landlock.FS.Error = "create filesystem ruleset: EPERM" },
			want:   verdicts{fail, pass, pass, fail}},
		{name: "Landlock disabled at boot", abi: 0,
			mutate: func(r *probeResult) { r.Landlock.Status = "disabled" },
			want:   verdicts{fail, fail, pass, fail}},
		{name: "unsupported OS", abi: 0,
			mutate: func(r *probeResult) { *r = unsupportedOSResult("arm64") },
			want:   verdicts{fail, fail, fail, fail}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := passingResult(test.abi)
			test.mutate(&result)
			if got := deriveVerdicts(result); got != test.want {
				t.Errorf("deriveVerdicts() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestRunExitCode(t *testing.T) {
	t.Parallel()

	noSeccomp := passingResult(4)
	noSeccomp.SeccompNotify.MarkerRead = "EOF"
	tcpLeak := passingResult(4)
	tcpLeak.Landlock.Net.DeniedConnect = "ok"
	unsupported := func() probeResult { return unsupportedOSResult("arm64") }
	finished := func(result probeResult) func() probeResult {
		return func() probeResult {
			result.Verdicts = deriveVerdicts(result)
			return result
		}
	}

	tests := []struct {
		name  string
		args  []string
		probe func() probeResult
		want  int
	}{
		{name: "qualification passes", probe: finished(passingResult(4)), want: exitQualified},
		{name: "unsupported OS fails qualification", probe: unsupported, want: exitFailed},
		{name: "unsupported OS in diagnostic mode", args: []string{"--diagnostic"}, probe: unsupported, want: exitQualified},
		{name: "TCP leak fails qualification", probe: finished(tcpLeak), want: exitFailed},
		{name: "TCP leak in diagnostic mode", args: []string{"--diagnostic"}, probe: finished(tcpLeak), want: exitQualified},
		{name: "no seccomp notification: Landlock still qualifies", probe: finished(noSeccomp), want: exitQualified},
		{name: "no seccomp notification when qualifying it", args: []string{"--qualify", "seccomp-user-notification"},
			probe: finished(noSeccomp), want: exitFailed},
		{name: "both properties", args: []string{"--qualify", "process-self-restriction,seccomp-user-notification"},
			probe: finished(passingResult(6)), want: exitQualified},
		{name: "unknown property", args: []string{"--qualify", "landlock"}, probe: finished(passingResult(4)), want: exitUsage},
		{name: "stray argument", args: []string{"extra"}, probe: finished(passingResult(4)), want: exitUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			got := run(test.args, strings.NewReader(""), &stdout, &stderr, test.probe)
			if got != test.want {
				t.Fatalf("run() = %d, want %d\nstderr: %s", got, test.want, stderr.String())
			}
			if got != exitUsage && !json.Valid(stdout.Bytes()) {
				t.Fatalf("stdout is not one JSON object: %q", stdout.String())
			}
		})
	}
}

func TestRederive(t *testing.T) {
	t.Parallel()

	recorded := `{"probe_version":"0.1.0","landlock":{"status":"enabled","abi":4,` +
		`"fs":{"allowed_write":"ok","denied_write":"EACCES","denied_truncate":"EACCES","control_ok":true},` +
		`"net":{"allowed_connect":"ok","denied_connect":"ok","bind":"EACCES","control_ok":true}},` +
		`"seccomp_notify":{"stacked_filters":"ok","listener_transfer":"ok","notification_received":"ok","addfd_send":"ok","marker_read":"ok"},` +
		`"capability_verdict":"pass","errors":[]}`
	var stdout, stderr bytes.Buffer
	code := run([]string{"--rederive"}, strings.NewReader(recorded), &stdout, &stderr, nil)
	if code != exitFailed {
		t.Fatalf("run() = %d, want %d (a forbidden connect succeeded)", code, exitFailed)
	}
	var result probeResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	want := verdicts{verdictPass, verdictFail, verdictPass, verdictFail}
	if result.Verdicts != want || result.ProbeVersion != "0.1.0" || result.VerdictsDerivedBy != probeVersion {
		t.Fatalf("rederived = %+v (probe %s, derived by %s), want %+v", result.Verdicts, result.ProbeVersion, result.VerdictsDerivedBy, want)
	}
	if strings.Contains(stdout.String(), "capability_verdict") {
		t.Fatal("the retired capability_verdict field was carried over")
	}
}
