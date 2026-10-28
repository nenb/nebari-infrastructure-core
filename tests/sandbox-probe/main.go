package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	result, emit := execute(os.Args[1:])
	if !emit {
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode probe result: %v\n", err)
		os.Exit(1)
	}
}
