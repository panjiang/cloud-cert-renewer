package main

import (
	"errors"
	"os"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func initGlobalLogger(level string) error {
	zapLevel, err := parseZapLevel(level)
	if err != nil {
		return err
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.TimeEncoderOfLayout(time.RFC3339),
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	logger := zap.New(
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.Lock(os.Stderr),
			zapLevel,
		),
		zap.AddCaller(),
	)

	old := zap.L()
	zap.ReplaceGlobals(logger)
	syncLoggerBestEffort(old)
	return nil
}

func parseZapLevel(level string) (zapcore.Level, error) {
	switch normalizeLogLevel(level) {
	case "debug":
		return zap.DebugLevel, nil
	case "info":
		return zap.InfoLevel, nil
	case "warn":
		return zap.WarnLevel, nil
	case "error":
		return zap.ErrorLevel, nil
	default:
		return zap.InfoLevel, validateLogLevel(level)
	}
}

func syncLoggerBestEffort(logger *zap.Logger) {
	if logger == nil {
		return
	}
	if err := logger.Sync(); err != nil && !isIgnorableSyncError(err) {
		_, _ = os.Stderr.WriteString("sync logger: " + err.Error() + "\n")
	}
}

func isIgnorableSyncError(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTTY) || errors.Is(err, os.ErrInvalid)
}
