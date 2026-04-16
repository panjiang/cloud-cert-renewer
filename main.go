package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	providerpkg "github.com/panjiang/cert-renewer/provider"
	"go.uber.org/zap"
)

var configFilePath string
var runOnceMode bool
var cleanupConfiguredOldMode bool
var cleanupAllExpiredMode bool
var showVersion bool

const processLockPath = "/run/cert-renewer/cert-renewer.lock"

func init() {
	flag.StringVar(&configFilePath, "config", "config.yaml", "Config file path")
	flag.BoolVar(&runOnceMode, "run-once", false, "Run one normal check/update round and exit")
	flag.BoolVar(&cleanupConfiguredOldMode, "cleanup-configured-old", false, "Delete old certificates for all configured domains and exit")
	flag.BoolVar(&cleanupAllExpiredMode, "cleanup-all-expired", false, "Delete all expired Tencent Cloud certificates and exit")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
}

func main() {
	flag.Parse()
	os.Exit(run())
}

type updaterRunner interface {
	Run()
	RunOnce(options CheckOptions) CheckResult
	CleanupUnusedOldCertificates() error
	CleanupExpiredCertificates() error
	BuildCleanupPlan(cleanupUnused, cleanupExpired bool) ([]providerpkg.CleanupCandidate, error)
	DeleteCleanupCandidates(candidates []providerpkg.CleanupCandidate) error
}

func run() int {
	if showVersion {
		_, _ = fmt.Fprintln(os.Stdout, Version())
		return 0
	}

	if err := initGlobalLogger("info"); err != nil {
		_, _ = os.Stderr.WriteString("init logger: " + err.Error() + "\n")
		return 1
	}
	defer func() {
		syncLoggerBestEffort(zap.L())
	}()

	zap.L().Info("starting cert-renewer",
		zap.String("config", configFilePath),
		zap.Bool("runOnce", runOnceMode),
		zap.Bool("cleanupConfiguredOld", cleanupConfiguredOldMode),
		zap.Bool("cleanupAllExpired", cleanupAllExpiredMode))

	lockFile, err := acquireProcessLock()
	if err != nil {
		zap.L().Error("acquire process lock failed", zap.Error(err), zap.String("lockPath", processLockPath))
		return 1
	}
	defer releaseLock(lockFile)

	cfg, err := LoadConfig(configFilePath)
	if err != nil {
		zap.L().Error("load config failed", zap.Error(err), zap.String("config", configFilePath))
		return 1
	}
	if err := initGlobalLogger(cfg.Log.Level); err != nil {
		zap.L().Error("reconfigure logger failed", zap.Error(err), zap.String("level", cfg.Log.Level))
		return 1
	}

	notifier := NewNotifier(cfg.Alert.NotifyURL)
	updater, stop, err := NewUpdater(cfg, notifier)
	if err != nil {
		zap.L().Error("init updater failed", zap.Error(err))
		return 1
	}

	handleShutdown(stop)

	zap.L().Info("config loaded",
		zap.String("config", configFilePath),
		zap.Int("domains", len(cfg.Domains)),
		zap.String("defaultProvider", cfg.DefaultProvider),
		zap.Duration("beforeExpired", cfg.Alert.BeforeExpired),
		zap.Duration("checkInterval", cfg.Alert.CheckInterval),
		zap.String("logLevel", cfg.Log.Level),
		zap.Bool("runOnce", runOnceMode),
		zap.Bool("cleanupConfiguredOld", cleanupConfiguredOldMode),
		zap.Bool("cleanupAllExpired", cleanupAllExpiredMode))

	if runOnceMode && (cleanupConfiguredOldMode || cleanupAllExpiredMode) {
		zap.L().Error("invalid flags: -run-once cannot be combined with cleanup flags")
		return 1
	}
	if cleanupConfiguredOldMode || cleanupAllExpiredMode {
		return executeCleanup(updater, cleanupConfiguredOldMode, cleanupAllExpiredMode)
	}
	return executeRun(updater, runOnceMode)
}

func executeRun(updater updaterRunner, runOnce bool) int {
	if !runOnce {
		updater.Run()
		return 0
	}

	result := updater.RunOnce(CheckOptions{})
	if result.Failures > 0 {
		return 1
	}
	return 0
}

func executeCleanup(updater updaterRunner, cleanupUnused, cleanupExpired bool) int {
	return executeCleanupWithIO(updater, cleanupUnused, cleanupExpired, os.Stdin, os.Stdout)
}

func executeCleanupWithIO(updater updaterRunner, cleanupUnused, cleanupExpired bool, input io.Reader, output io.Writer) int {
	candidates, err := updater.BuildCleanupPlan(cleanupUnused, cleanupExpired)
	if err != nil {
		zap.L().Error("build cleanup plan failed", zap.Error(err))
		return 1
	}
	if len(candidates) == 0 {
		_, _ = fmt.Fprintln(output, "No cleanup candidates found.")
		return 0
	}

	printCleanupCandidates(output, candidates)
	_, _ = fmt.Fprint(output, "Type Y to delete these certificates: ")
	confirmed, err := readCleanupConfirmation(input)
	if err != nil {
		zap.L().Error("read cleanup confirmation failed", zap.Error(err))
		return 1
	}
	if !confirmed {
		_, _ = fmt.Fprintln(output, "Cleanup cancelled; no certificates deleted.")
		return 0
	}

	if err := updater.DeleteCleanupCandidates(candidates); err != nil {
		zap.L().Error("delete cleanup candidates failed", zap.Error(err))
		return 1
	}
	_, _ = fmt.Fprintf(output, "Deleted %d certificate(s).\n", len(candidates))
	return 0
}

func readCleanupConfirmation(input io.Reader) (bool, error) {
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return strings.TrimSpace(line) == "Y", nil
}

func printCleanupCandidates(output io.Writer, candidates []providerpkg.CleanupCandidate) {
	candidates = sortedCleanupCandidates(candidates)
	_, _ = fmt.Fprintln(output, "TYPE | PROVIDER | CERT_DOMAINS | CERT_ID | EXPIRES_AT | CURRENT_EXPIRES_AT")
	for _, candidate := range candidates {
		_, _ = fmt.Fprintf(output, "%s | %s | %s | %s | %s | %s\n",
			cleanupDisplayValue(candidate.CleanupType),
			cleanupDisplayValue(candidate.Provider),
			cleanupDisplayDomains(candidate.CertificateDomains),
			cleanupDisplayValue(candidate.CertificateID),
			cleanupDisplayTime(candidate.NotAfter),
			cleanupDisplayTime(candidate.CurrentNotAfter))
	}
}

func sortedCleanupCandidates(candidates []providerpkg.CleanupCandidate) []providerpkg.CleanupCandidate {
	sorted := append([]providerpkg.CleanupCandidate(nil), candidates...)
	slices.SortFunc(sorted, func(a, b providerpkg.CleanupCandidate) int {
		for _, diff := range []int{
			strings.Compare(a.CleanupType, b.CleanupType),
			strings.Compare(a.Provider, b.Provider),
			strings.Compare(a.Domain, b.Domain),
			strings.Compare(a.CertificateID, b.CertificateID),
		} {
			if diff != 0 {
				return diff
			}
		}
		return a.NotAfter.Compare(b.NotAfter)
	})
	return sorted
}

func cleanupDisplayValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func cleanupDisplayDomains(domains []string) string {
	values := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		values = append(values, domain)
	}
	if len(values) == 0 {
		return "-"
	}
	slices.Sort(values)
	return strings.Join(slices.Compact(values), ",")
}

func cleanupDisplayTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.Format(time.DateOnly)
}

func handleShutdown(stop func()) {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigc
		zap.L().Info("received shutdown signal", zap.String("signal", sig.String()))
		stop()
	}()
}

func acquireProcessLock() (*os.File, error) {
	return acquireLock(processLockPath)
}

func acquireLock(lockPath string) (*os.File, error) {
	lockDir := filepath.Dir(lockPath)
	if err := os.MkdirAll(lockDir, 0755); err != nil {
		return nil, fmt.Errorf("ensure lock directory %s: %w", lockDir, err)
	}

	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", lockPath, err)
	}

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockFile.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("another cert-renewer process is already running")
		}
		return nil, fmt.Errorf("lock file %s: %w", lockPath, err)
	}

	return lockFile, nil
}

func releaseLock(lockFile *os.File) {
	if lockFile == nil {
		return
	}
	_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	_ = lockFile.Close()
}
