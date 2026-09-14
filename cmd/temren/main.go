// Package main is the entry point for TemrenSec scanner
package main

import (
	"fmt"
	"os"

	"github.com/temren/cmd/temren/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
