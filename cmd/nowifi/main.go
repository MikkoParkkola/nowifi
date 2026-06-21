// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

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
