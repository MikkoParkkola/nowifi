// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package main

import (
	"runtime/debug"

	"github.com/MikkoParkkola/nowifi/internal/cli"
)

// version is set via -ldflags at build time (`make build`). `go install`
// doesn't run the Makefile, so fall back to the module version recorded in
// the build info — that way go-installed binaries report the real release
// version instead of "dev".
var version = "dev"

func main() {
	cli.SetVersion(resolveVersion())
	cli.Execute()
}

func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}
