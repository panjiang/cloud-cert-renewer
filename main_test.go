package main

import (
	"io"
	"os"
	"testing"
)

type fakeUpdaterRunner struct {
	runCalls     int
	runOnceCalls int
	lastOptions  CheckOptions
	result       CheckResult
}

func (u *fakeUpdaterRunner) Run() {
	u.runCalls++
}

func (u *fakeUpdaterRunner) RunOnce(options CheckOptions) CheckResult {
	u.runOnceCalls++
	u.lastOptions = options
	return u.result
}

func TestExecuteRunDefaultMode(t *testing.T) {
	updater := &fakeUpdaterRunner{}

	exitCode := executeRun(updater, false)
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if updater.runCalls != 1 {
		t.Fatalf("runCalls = %d, want 1", updater.runCalls)
	}
	if updater.runOnceCalls != 0 {
		t.Fatalf("runOnceCalls = %d, want 0", updater.runOnceCalls)
	}
}

func TestExecuteRunForceModeSuccess(t *testing.T) {
	updater := &fakeUpdaterRunner{
		result: CheckResult{},
	}

	exitCode := executeRun(updater, true)
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if updater.runCalls != 0 {
		t.Fatalf("runCalls = %d, want 0", updater.runCalls)
	}
	if updater.runOnceCalls != 1 {
		t.Fatalf("runOnceCalls = %d, want 1", updater.runOnceCalls)
	}
	if !updater.lastOptions.Force {
		t.Fatal("CheckOptions.Force = false, want true")
	}
}

func TestExecuteRunForceModeFailure(t *testing.T) {
	updater := &fakeUpdaterRunner{
		result: CheckResult{Failures: 1},
	}

	exitCode := executeRun(updater, true)
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if updater.runOnceCalls != 1 {
		t.Fatalf("runOnceCalls = %d, want 1", updater.runOnceCalls)
	}
}

func TestVersionReturnsInjectedValue(t *testing.T) {
	originalVersion := version
	t.Cleanup(func() {
		version = originalVersion
	})

	version = "v1.2.3"

	if got := Version(); got != "v1.2.3" {
		t.Fatalf("Version() = %q, want %q", got, "v1.2.3")
	}
}

func TestVersionFallsBackToDefault(t *testing.T) {
	originalVersion := version
	t.Cleanup(func() {
		version = originalVersion
	})

	version = ""

	got := Version()
	if got == "" {
		t.Fatal("Version() returned empty string")
	}
}

func TestRunWithVersionFlagSkipsConfigLoading(t *testing.T) {
	originalShowVersion := showVersion
	originalConfigFilePath := configFilePath
	originalVersion := version
	t.Cleanup(func() {
		showVersion = originalShowVersion
		configFilePath = originalConfigFilePath
		version = originalVersion
	})

	showVersion = true
	configFilePath = "/nonexistent/config.yaml"
	version = "v9.9.9"

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	defer stdoutReader.Close()

	originalStdout := os.Stdout
	os.Stdout = stdoutWriter
	t.Cleanup(func() {
		os.Stdout = originalStdout
	})

	exitCode := run()

	_ = stdoutWriter.Close()

	output, readErr := io.ReadAll(stdoutReader)
	if readErr != nil {
		t.Fatalf("stdout read error = %v", readErr)
	}

	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if got := string(output); got != "v9.9.9\n" {
		t.Fatalf("stdout = %q, want %q", got, "v9.9.9\n")
	}
}
