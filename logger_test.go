package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestInitGlobalLogger(t *testing.T) {
	original := zap.L()
	t.Cleanup(func() {
		zap.ReplaceGlobals(original)
	})

	if err := initGlobalLogger("debug"); err != nil {
		t.Fatalf("initGlobalLogger(debug) error = %v", err)
	}
	if !zap.L().Core().Enabled(zap.DebugLevel) {
		t.Fatal("global logger should enable debug level")
	}

	if err := initGlobalLogger("trace"); err == nil {
		t.Fatal("initGlobalLogger(trace) expected error")
	}
}

func TestInitGlobalLoggerCLIModeUsesMessageAndKeyValues(t *testing.T) {
	original := zap.L()
	t.Cleanup(func() {
		zap.ReplaceGlobals(original)
	})

	var out bytes.Buffer
	if err := initGlobalLoggerWithOptions("debug", true, zapcore.AddSync(&out)); err != nil {
		t.Fatalf("initGlobalLoggerWithOptions() error = %v", err)
	}

	zap.L().Info("starting cert-renewer",
		zap.String("config", "./config-gitlab.yaml"),
		zap.Bool("runOnce", false),
		zap.Duration("checkInterval", time.Hour),
		zap.String("reason", "permission denied"))

	got := out.String()
	want := "starting cert-renewer config=./config-gitlab.yaml runOnce=false checkInterval=1h0m0s reason=\"permission denied\"\n"
	if got != want {
		t.Fatalf("cli log output = %q, want %q", got, want)
	}
	for _, forbidden := range []string{"\tinfo\t", "logger.go", "{\""} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("cli log output = %q, should not contain %q", got, forbidden)
		}
	}
}
