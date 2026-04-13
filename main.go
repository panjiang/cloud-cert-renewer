package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

var configFilePath string

func init() {
	flag.StringVar(&configFilePath, "config", "config.yaml", "Config file path")
}

func main() {
	flag.Parse()

	if err := initGlobalLogger("info"); err != nil {
		_, _ = os.Stderr.WriteString("init logger: " + err.Error() + "\n")
		os.Exit(1)
	}
	defer func() {
		syncLoggerBestEffort(zap.L())
	}()

	zap.L().Info("starting cloud-cert-renewer", zap.String("config", configFilePath))

	cfg, err := LoadConfig(configFilePath)
	if err != nil {
		zap.L().Error("load config failed", zap.Error(err), zap.String("config", configFilePath))
		os.Exit(1)
	}
	if err := initGlobalLogger(cfg.Log.Level); err != nil {
		zap.L().Error("reconfigure logger failed", zap.Error(err), zap.String("level", cfg.Log.Level))
		os.Exit(1)
	}

	notifier := NewNotifier(cfg.Alert.NotifyURL)
	updater, stop, err := NewUpdater(cfg, notifier)
	if err != nil {
		zap.L().Error("init updater failed", zap.Error(err))
		os.Exit(1)
	}

	handleShutdown(stop)

	zap.L().Info("config loaded",
		zap.String("config", configFilePath),
		zap.Int("domains", len(cfg.Domains)),
		zap.String("defaultProvider", cfg.DefaultProvider),
		zap.Duration("beforeExpired", cfg.Alert.BeforeExpired),
		zap.Duration("checkInterval", cfg.Alert.CheckInterval),
		zap.String("logLevel", cfg.Log.Level))

	updater.Run()
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
