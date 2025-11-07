package main

import (
	"fmt"
	"os"

	"github.com/enclaive/vmgrab/cmd"
)

// Version information (set by build flags)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Pass version info to cmd package
	cmd.SetVersion(Version, Commit, BuildTime)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
