package main

import (
	"github.com/MikkoParkkola/nowifi/internal/cli"
)

// version is set via -ldflags at build time.
var version = "dev"

func main() {
	cli.SetVersion(version)
	cli.Execute()
}
