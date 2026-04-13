package main

import (
	"runtime/debug"
	"strings"
)

const defaultVersion = "dev"

// version is intended to be set at build time, for example:
// go build -ldflags="-X main.version=$(git describe --tags --always --dirty)"
var version string

func Version() string {
	if v := strings.TrimSpace(version); v != "" {
		return v
	}

	info, ok := debug.ReadBuildInfo()
	if ok {
		if v := strings.TrimSpace(info.Main.Version); v != "" && v != "(devel)" {
			return v
		}
	}

	return defaultVersion
}
