//go:build !(js && wasm)

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// main runs one scenario and prints its outcome as JSON, the same answer the
// browser gets: writ-playground SCENARIO [LIMIT_CENTS].
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: writ-playground %v [limit in cents]\n", Scenarios)
		os.Exit(2)
	}
	limit := int64(60000)
	if len(os.Args) > 2 {
		n, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		limit = n
	}
	o, err := Play(os.Args[1], limit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(o)
}
