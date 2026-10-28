package main

const probeVersion = "0.1.0"

type probeResult struct {
	ProbeVersion      string              `json:"probe_version"`
	Node              string              `json:"node"`
	Kernel            string              `json:"kernel"`
	Arch              string              `json:"arch"`
	SeccompMode       int                 `json:"seccomp_mode"`
	SeccompFilters    int                 `json:"seccomp_filters"`
	NoNewPrivs        bool                `json:"no_new_privs"`
	Landlock          landlockResult      `json:"landlock"`
	SeccompNotify     seccompNotifyResult `json:"seccomp_notify"`
	CapabilityVerdict string              `json:"capability_verdict"`
	Errors            []string            `json:"errors"`
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
		CapabilityVerdict: "fail",
	}
}

func capabilityPass(result probeResult) bool {
	fs := result.Landlock.FS
	seccomp := result.SeccompNotify
	return result.Landlock.Status == "enabled" &&
		result.Landlock.ABI >= 3 &&
		fs.ControlOK &&
		fs.AllowedWrite == "ok" &&
		fs.DeniedWrite == "EACCES" &&
		fs.DeniedTruncate == "EACCES" &&
		seccomp.StackedFilters == "ok" &&
		seccomp.ListenerTransfer == "ok" &&
		seccomp.NotificationReceived == "ok" &&
		seccomp.AddfdSend == "ok" &&
		seccomp.MarkerRead == "ok"
}
