package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// Exit codes.
const (
	exitQualified = 0 // every qualified property passed, or --diagnostic
	exitFailed    = 1 // a qualified property failed
	exitUsage     = 2
)

// Properties --qualify accepts.
const (
	propertyProcessSelfRestriction  = "process-self-restriction"
	propertySeccompUserNotification = "seccomp-user-notification"
)

type options struct {
	qualify    []string
	diagnostic bool
	rederive   bool
}

func main() {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "--child=") {
		runChild(os.Args[1:])
		return
	}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, runProbe))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, probe func() probeResult) int {
	opts, err := parseOptions(args, stderr)
	if err != nil {
		return exitUsage
	}

	var result probeResult
	if opts.rederive {
		if err := json.NewDecoder(stdin).Decode(&result); err != nil {
			fmt.Fprintf(stderr, "decode recorded result: %v\n", err)
			return exitUsage
		}
		result.Verdicts = deriveVerdicts(result)
		result.VerdictsDerivedBy = probeVersion
	} else {
		result = probe()
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode probe result: %v\n", err)
		return exitFailed
	}
	return exitCode(result, opts, stderr)
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var opts options
	var qualify string
	flags := flag.NewFlagSet("psr-probe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&qualify, "qualify", propertyProcessSelfRestriction,
		"comma-separated properties to qualify: "+propertyProcessSelfRestriction+", "+propertySeccompUserNotification+
			"; the exit status is non-zero if any of them fails")
	flags.BoolVar(&opts.diagnostic, "diagnostic", false,
		"diagnostic only, NOT a qualification gate: print the result and always exit 0")
	flags.BoolVar(&opts.rederive, "rederive", false,
		"read a recorded result on stdin and recompute its verdicts from the raw fields")
	if err := flags.Parse(args); err != nil {
		return opts, err
	}
	if flags.NArg() != 0 {
		err := fmt.Errorf("unexpected arguments: %v", flags.Args())
		fmt.Fprintln(stderr, err)
		return opts, err
	}
	for _, property := range strings.Split(qualify, ",") {
		property = strings.TrimSpace(property)
		if property != propertyProcessSelfRestriction && property != propertySeccompUserNotification {
			err := fmt.Errorf("unknown property %q for --qualify", property)
			fmt.Fprintln(stderr, err)
			return opts, err
		}
		if !slices.Contains(opts.qualify, property) {
			opts.qualify = append(opts.qualify, property)
		}
	}
	return opts, nil
}

// exitCode is non-zero when a property being qualified did not pass, unless
// the run is diagnostic.
func exitCode(result probeResult, opts options, stderr io.Writer) int {
	if opts.diagnostic {
		fmt.Fprintln(stderr, "diagnostic run: not a qualification; exit status ignores the verdicts")
		return exitQualified
	}
	code := exitQualified
	for _, property := range opts.qualify {
		got := result.Verdicts.ProcessSelfRestriction
		if property == propertySeccompUserNotification {
			got = result.Verdicts.SeccompUserNotification
		}
		if got != verdictPass {
			fmt.Fprintf(stderr, "%s: %s\n", property, got)
			code = exitFailed
		}
	}
	return code
}
