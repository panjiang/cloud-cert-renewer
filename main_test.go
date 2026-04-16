package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	providerpkg "github.com/panjiang/cert-renewer/provider"
)

type failingReader struct{}

func (failingReader) Read(_ []byte) (int, error) {
	return 0, errors.New("read failed")
}

type fakeUpdaterRunner struct {
	runCalls                   int
	runOnceCalls               int
	cleanupUnusedCalls         int
	cleanupExpiredCalls        int
	buildCleanupPlanCalls      int
	deleteCleanupCandidateCall int
	lastOptions                CheckOptions
	result                     CheckResult
	cleanupUnusedErr           error
	cleanupExpiredErr          error
	cleanupCandidates          []providerpkg.CleanupCandidate
	buildCleanupPlanErr        error
	deleteCleanupCandidatesErr error
	lastCleanupUnused          bool
	lastCleanupExpired         bool
	lastDeletedCandidates      []providerpkg.CleanupCandidate
}

func (u *fakeUpdaterRunner) Run() {
	u.runCalls++
}

func (u *fakeUpdaterRunner) RunOnce(options CheckOptions) CheckResult {
	u.runOnceCalls++
	u.lastOptions = options
	return u.result
}

func (u *fakeUpdaterRunner) CleanupUnusedOldCertificates() error {
	u.cleanupUnusedCalls++
	return u.cleanupUnusedErr
}

func (u *fakeUpdaterRunner) CleanupExpiredCertificates() error {
	u.cleanupExpiredCalls++
	return u.cleanupExpiredErr
}

func (u *fakeUpdaterRunner) BuildCleanupPlan(cleanupUnused, cleanupExpired bool) ([]providerpkg.CleanupCandidate, error) {
	u.buildCleanupPlanCalls++
	u.lastCleanupUnused = cleanupUnused
	u.lastCleanupExpired = cleanupExpired
	if u.buildCleanupPlanErr != nil {
		return nil, u.buildCleanupPlanErr
	}
	return append([]providerpkg.CleanupCandidate(nil), u.cleanupCandidates...), nil
}

func (u *fakeUpdaterRunner) DeleteCleanupCandidates(candidates []providerpkg.CleanupCandidate) error {
	u.deleteCleanupCandidateCall++
	u.lastDeletedCandidates = append([]providerpkg.CleanupCandidate(nil), candidates...)
	return u.deleteCleanupCandidatesErr
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

func TestExecuteRunOnceModeSuccess(t *testing.T) {
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
	if updater.lastOptions.Force {
		t.Fatal("CheckOptions.Force = true, want false")
	}
}

func TestExecuteRunOnceModeFailure(t *testing.T) {
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

func TestExecuteCleanupConfirmsAndDeletes(t *testing.T) {
	expiresAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	currentExpiresAt := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	updater := &fakeUpdaterRunner{
		cleanupCandidates: []providerpkg.CleanupCandidate{{
			Provider:           ProviderTencentCloud,
			CleanupType:        providerpkg.CleanupTypeConfiguredOld,
			Domain:             "doc.example.com",
			CertificateID:      "cert-1",
			CertificateDomains: []string{"doc.example.com"},
			NotAfter:           expiresAt,
			CurrentNotAfter:    currentExpiresAt,
		}},
	}
	var output bytes.Buffer

	exitCode := executeCleanupWithIO(updater, true, false, strings.NewReader("Y\n"), &output)
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if updater.buildCleanupPlanCalls != 1 {
		t.Fatalf("buildCleanupPlanCalls = %d, want 1", updater.buildCleanupPlanCalls)
	}
	if !updater.lastCleanupUnused || updater.lastCleanupExpired {
		t.Fatalf("cleanup flags = (%v, %v), want (true, false)", updater.lastCleanupUnused, updater.lastCleanupExpired)
	}
	if updater.deleteCleanupCandidateCall != 1 {
		t.Fatalf("deleteCleanupCandidateCall = %d, want 1", updater.deleteCleanupCandidateCall)
	}
	if len(updater.lastDeletedCandidates) != 1 || updater.lastDeletedCandidates[0].CertificateID != "cert-1" {
		t.Fatalf("lastDeletedCandidates = %#v, want cert-1", updater.lastDeletedCandidates)
	}
	gotOutput := output.String()
	for _, want := range []string{
		"TYPE | PROVIDER | CERT_DOMAINS | CERT_ID | EXPIRES_AT | CURRENT_EXPIRES_AT",
		"configured-old | tencentcloud | doc.example.com | cert-1 | 2026-01-02 | 2026-02-03",
		"Type Y to delete these certificates:",
		"Deleted 1 certificate(s).",
	} {
		if !strings.Contains(gotOutput, want) {
			t.Fatalf("output = %q, want to contain %q", gotOutput, want)
		}
	}
	if strings.Contains(gotOutput, "CONFIG_DOMAIN") {
		t.Fatalf("output = %q, should not contain CONFIG_DOMAIN", gotOutput)
	}
}

func TestExecuteCleanupCancelsWithoutUppercaseY(t *testing.T) {
	for _, input := range []string{"n\n", "\n", "y\n", ""} {
		t.Run(fmt.Sprintf("input=%q", input), func(t *testing.T) {
			updater := &fakeUpdaterRunner{
				cleanupCandidates: []providerpkg.CleanupCandidate{{
					Provider:      ProviderTencentCloud,
					CleanupType:   providerpkg.CleanupTypeAllExpired,
					CertificateID: "cert-1",
				}},
			}
			var output bytes.Buffer

			exitCode := executeCleanupWithIO(updater, false, true, strings.NewReader(input), &output)
			if exitCode != 0 {
				t.Fatalf("exitCode = %d, want 0", exitCode)
			}
			if updater.deleteCleanupCandidateCall != 0 {
				t.Fatalf("deleteCleanupCandidateCall = %d, want 0", updater.deleteCleanupCandidateCall)
			}
			if !strings.Contains(output.String(), "Cleanup cancelled; no certificates deleted.") {
				t.Fatalf("output = %q, want cancellation message", output.String())
			}
		})
	}
}

func TestExecuteCleanupNoCandidates(t *testing.T) {
	updater := &fakeUpdaterRunner{}
	var output bytes.Buffer

	exitCode := executeCleanupWithIO(updater, true, true, strings.NewReader("Y\n"), &output)
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if updater.deleteCleanupCandidateCall != 0 {
		t.Fatalf("deleteCleanupCandidateCall = %d, want 0", updater.deleteCleanupCandidateCall)
	}
	gotOutput := output.String()
	if !strings.Contains(gotOutput, "No cleanup candidates found.") {
		t.Fatalf("output = %q, want no-candidates message", gotOutput)
	}
	if strings.Contains(gotOutput, "Type Y") {
		t.Fatalf("output = %q, want no confirmation prompt", gotOutput)
	}
}

func TestExecuteCleanupBuildFailure(t *testing.T) {
	updater := &fakeUpdaterRunner{buildCleanupPlanErr: io.EOF}
	var output bytes.Buffer

	exitCode := executeCleanupWithIO(updater, true, true, strings.NewReader("Y\n"), &output)
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if updater.deleteCleanupCandidateCall != 0 {
		t.Fatalf("deleteCleanupCandidateCall = %d, want 0 after failure", updater.deleteCleanupCandidateCall)
	}
}

func TestExecuteCleanupReadFailure(t *testing.T) {
	updater := &fakeUpdaterRunner{
		cleanupCandidates: []providerpkg.CleanupCandidate{{
			Provider:      ProviderTencentCloud,
			CleanupType:   providerpkg.CleanupTypeAllExpired,
			CertificateID: "cert-1",
		}},
	}
	var output bytes.Buffer

	exitCode := executeCleanupWithIO(updater, true, true, failingReader{}, &output)
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if updater.deleteCleanupCandidateCall != 0 {
		t.Fatalf("deleteCleanupCandidateCall = %d, want 0 after read failure", updater.deleteCleanupCandidateCall)
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

func TestAcquireLockPreventsConcurrentRuns(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "cert-renewer.lock")

	firstLock, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("acquireLock() first error = %v", err)
	}

	secondLock, err := acquireLock(lockPath)
	if err == nil {
		releaseLock(secondLock)
		t.Fatal("acquireLock() second expected error")
	}

	releaseLock(firstLock)

	thirdLock, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("acquireLock() third error = %v", err)
	}
	releaseLock(thirdLock)
}
