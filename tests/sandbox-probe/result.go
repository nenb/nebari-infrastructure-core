package main

const probeVersion = "0.2.0"

type probeResult struct {
	ProbeVersion   string              `json:"probe_version"`
	Node           string              `json:"node"`
	Kernel         string              `json:"kernel"`
	Arch           string              `json:"arch"`
	SeccompMode    int                 `json:"seccomp_mode"`
	SeccompFilters int                 `json:"seccomp_filters"`
	NoNewPrivs     bool                `json:"no_new_privs"`
	Landlock       landlockResult      `json:"landlock"`
	SeccompNotify  seccompNotifyResult `json:"seccomp_notify"`
	Verdicts       verdicts            `json:"verdicts"`
	// VerdictsDerivedBy is set when the verdicts were recomputed from a
	// recorded result's raw fields by a later probe version (--rederive).
	VerdictsDerivedBy string   `json:"verdicts_derived_by,omitempty"`
	Errors            []string `json:"errors"`
}

// Verdict values.
const (
	verdictPass          = "pass"
	verdictFail          = "fail"
	verdictNotApplicable = "not_applicable"
)

// verdicts are evaluated separately, so one property failing never hides or
// decides another.
type verdicts struct {
	// LandlockFS: filesystem restriction at ABI 3 or newer, with controls.
	LandlockFS string `json:"landlock_fs"`
	// LandlockTCP: TCP connect and bind restriction. Evaluated at ABI 4 or
	// newer, where the record advertises TCP confinement; not_applicable below.
	LandlockTCP string `json:"landlock_tcp"`
	// SeccompUserNotification: the separate, reserved capability.
	SeccompUserNotification string `json:"seccomp_user_notification"`
	// ProcessSelfRestriction: landlock_fs passes and landlock_tcp does not
	// fail. It does not depend on seccomp user notification.
	ProcessSelfRestriction string `json:"process_self_restriction"`
}

type landlockResult struct {
	Status string            `json:"status"`
	ABI    int               `json:"abi"`
	FS     landlockFSResult  `json:"fs"`
	Net    landlockNetResult `json:"net"`
}

type landlockFSResult struct {
	Error                 string `json:"error,omitempty"`
	ControlAllowedWrite   string `json:"control_allowed_write"`
	ControlDeniedWrite    string `json:"control_denied_write"`
	AllowedWrite          string `json:"allowed_write"`
	DeniedWrite           string `json:"denied_write"`
	ControlDeniedTruncate string `json:"control_denied_truncate"`
	DeniedTruncate        string `json:"denied_truncate"`
	ControlOK             bool   `json:"control_ok"`
}

type landlockNetResult struct {
	Error                 string `json:"error,omitempty"`
	ControlAllowedConnect string `json:"control_allowed_connect"`
	ControlDeniedConnect  string `json:"control_denied_connect"`
	ControlBind           string `json:"control_bind"`
	AllowedConnect        string `json:"allowed_connect"`
	DeniedConnect         string `json:"denied_connect"`
	Bind                  string `json:"bind"`
	UDPSendto             string `json:"udp_sendto"`
	UDPReceived           bool   `json:"udp_received"`
	ControlOK             bool   `json:"control_ok"`
}

type seccompNotifyResult struct {
	Error                string `json:"error,omitempty"`
	StackedFilters       string `json:"stacked_filters"`
	ListenerTransfer     string `json:"listener_transfer"`
	NotificationReceived string `json:"notification_received"`
	AddfdSend            string `json:"addfd_send"`
	MarkerRead           string `json:"marker_read"`
}

func emptyProbeResult() probeResult {
	return probeResult{
		ProbeVersion: probeVersion,
		Errors:       []string{},
		Landlock: landlockResult{
			Status: "not_checked",
			FS: landlockFSResult{
				ControlAllowedWrite:   "not_run",
				ControlDeniedWrite:    "not_run",
				AllowedWrite:          "not_run",
				DeniedWrite:           "not_run",
				ControlDeniedTruncate: "not_run",
				DeniedTruncate:        "not_run",
			},
			Net: landlockNetResult{
				ControlAllowedConnect: "not_run",
				ControlDeniedConnect:  "not_run",
				ControlBind:           "not_run",
				AllowedConnect:        "not_run",
				DeniedConnect:         "not_run",
				Bind:                  "not_run",
				UDPSendto:             "not_run",
			},
		},
		SeccompNotify: seccompNotifyResult{
			StackedFilters:       "not_run",
			ListenerTransfer:     "not_run",
			NotificationReceived: "not_run",
			AddfdSend:            "not_run",
			MarkerRead:           "not_run",
		},
		Verdicts: verdicts{
			LandlockFS:              verdictFail,
			LandlockTCP:             verdictFail,
			SeccompUserNotification: verdictFail,
			ProcessSelfRestriction:  verdictFail,
		},
	}
}

func unsupportedOSResult(arch string) probeResult {
	result := emptyProbeResult()
	result.Arch = arch
	result.Landlock.Status = "unsupported_os"
	result.Errors = append(result.Errors, "the sandbox probe must run on Linux")
	result.Verdicts = deriveVerdicts(result)
	return result
}

func verdict(pass bool) string {
	if pass {
		return verdictPass
	}
	return verdictFail
}

// deriveVerdicts computes every verdict from the raw fields alone, so a
// recorded result can be re-evaluated deterministically.
func deriveVerdicts(result probeResult) verdicts {
	landlock := result.Landlock
	fs := landlock.FS
	net := landlock.Net
	seccomp := result.SeccompNotify
	enabled := landlock.Status == "enabled"

	var out verdicts
	out.LandlockFS = verdict(enabled &&
		landlock.ABI >= 3 &&
		fs.Error == "" &&
		fs.ControlOK &&
		fs.AllowedWrite == "ok" &&
		fs.DeniedWrite == "EACCES" &&
		fs.DeniedTruncate == "EACCES")
	if enabled && landlock.ABI < 4 {
		out.LandlockTCP = verdictNotApplicable
	} else {
		// A forbidden connect or bind that succeeded, a probe error or a
		// check that never ran all fail.
		out.LandlockTCP = verdict(enabled &&
			net.Error == "" &&
			net.ControlOK &&
			net.AllowedConnect == "ok" &&
			net.DeniedConnect == "EACCES" &&
			net.Bind == "EACCES")
	}
	out.SeccompUserNotification = verdict(seccomp.Error == "" &&
		seccomp.StackedFilters == "ok" &&
		seccomp.ListenerTransfer == "ok" &&
		seccomp.NotificationReceived == "ok" &&
		seccomp.AddfdSend == "ok" &&
		seccomp.MarkerRead == "ok")
	out.ProcessSelfRestriction = verdict(out.LandlockFS == verdictPass &&
		out.LandlockTCP != verdictFail)
	return out
}
