package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type processStatus struct {
	Seccomp        int
	SeccompFilters int
	NoNewPrivs     bool
}

func parseProcessStatus(reader io.Reader) (processStatus, error) {
	values := make(map[string]int)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		switch key {
		case "Seccomp", "Seccomp_filters", "NoNewPrivs":
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return processStatus{}, fmt.Errorf("parse %s: %w", key, err)
			}
			values[key] = parsed
		}
	}
	if err := scanner.Err(); err != nil {
		return processStatus{}, fmt.Errorf("scan process status: %w", err)
	}
	if _, ok := values["Seccomp"]; !ok {
		return processStatus{}, fmt.Errorf("Seccomp is absent from process status")
	}
	if _, ok := values["NoNewPrivs"]; !ok {
		return processStatus{}, fmt.Errorf("NoNewPrivs is absent from process status")
	}
	return processStatus{
		Seccomp:        values["Seccomp"],
		SeccompFilters: values["Seccomp_filters"],
		NoNewPrivs:     values["NoNewPrivs"] == 1,
	}, nil
}
