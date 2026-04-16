package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

var configFilePath string
var onceMode bool
var showVersion bool

func init() {
	flag.StringVar(&configFilePath, "config", "config.yaml", "Config file path")
	flag.BoolVar(&onceMode, "once", false, "Run one normal check/update round and exit")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
}

func main() {
	flag.Parse()
	os.Exit(run())
}

type updaterRunner interface {
	Run()
	RunOnce(options CheckOptions) CheckResult
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
		zap.Bool("once", onceMode))

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
		zap.Bool("once", onceMode))

	return executeRun(updater, onceMode)
}

func executeRun(updater updaterRunner, once bool) int {
	if !once {
		updater.Run()
		return 0
	}

	result := updater.RunOnce(CheckOptions{})
	if result.Failures > 0 {
		return 1
	}
	return 0
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
