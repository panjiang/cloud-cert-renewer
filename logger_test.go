package main

import (
	"testing"

	"go.uber.org/zap"
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
