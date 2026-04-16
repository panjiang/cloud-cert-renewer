package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

var cliLogBufferPool = buffer.NewPool()

func initGlobalLogger(level string) error {
	return initGlobalLoggerWithOptions(level, isTerminal(os.Stderr), zapcore.Lock(os.Stderr))
}

func initGlobalLoggerWithOptions(level string, cliMode bool, sink zapcore.WriteSyncer) error {
	zapLevel, err := parseZapLevel(level)
	if err != nil {
		return err
	}

	encoder := zapcore.NewConsoleEncoder(defaultEncoderConfig())
	if cliMode {
		encoder = newCLIEncoder()
	}

	logger := zap.New(
		zapcore.NewCore(
			encoder,
			sink,
			zapLevel,
		),
		zap.AddCaller(),
	)

	old := zap.L()
	zap.ReplaceGlobals(logger)
	syncLoggerBestEffort(old)
	return nil
}

func defaultEncoderConfig() zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
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
}

func isTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
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

type cliEncoder struct {
	fields []logField
}

type logField struct {
	key   string
	value string
}

func newCLIEncoder() zapcore.Encoder {
	return &cliEncoder{}
}

func (e *cliEncoder) Clone() zapcore.Encoder {
	clone := &cliEncoder{
		fields: make([]logField, len(e.fields)),
	}
	copy(clone.fields, e.fields)
	return clone
}

func (e *cliEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	clone := e.Clone().(*cliEncoder)
	for _, field := range fields {
		field.AddTo(clone)
	}

	buf := cliLogBufferPool.Get()
	buf.AppendString(entry.Message)
	for _, field := range clone.fields {
		if strings.TrimSpace(field.key) == "" {
			continue
		}
		buf.AppendByte(' ')
		buf.AppendString(field.key)
		buf.AppendByte('=')
		buf.AppendString(field.value)
	}
	if entry.Stack != "" {
		buf.AppendString(" stacktrace=")
		buf.AppendString(formatLogString(entry.Stack))
	}
	buf.AppendString(zapcore.DefaultLineEnding)
	return buf, nil
}

func (e *cliEncoder) addField(key string, value interface{}) {
	e.fields = append(e.fields, logField{key: key, value: formatLogValue(value)})
}

func (e *cliEncoder) AddArray(key string, marshaler zapcore.ArrayMarshaler) error {
	enc := &cliArrayEncoder{}
	err := marshaler.MarshalLogArray(enc)
	e.addField(key, enc.values)
	return err
}

func (e *cliEncoder) AddObject(key string, marshaler zapcore.ObjectMarshaler) error {
	enc := &cliObjectEncoder{}
	err := marshaler.MarshalLogObject(enc)
	e.addField(key, enc.fields)
	return err
}

func (e *cliEncoder) AddBinary(key string, value []byte) {
	e.addField(key, value)
}

func (e *cliEncoder) AddByteString(key string, value []byte) {
	e.addField(key, string(value))
}

func (e *cliEncoder) AddBool(key string, value bool) {
	e.addField(key, value)
}

func (e *cliEncoder) AddComplex128(key string, value complex128) {
	e.addField(key, value)
}

func (e *cliEncoder) AddComplex64(key string, value complex64) {
	e.addField(key, value)
}

func (e *cliEncoder) AddDuration(key string, value time.Duration) {
	e.addField(key, value.String())
}

func (e *cliEncoder) AddFloat64(key string, value float64) {
	e.addField(key, value)
}

func (e *cliEncoder) AddFloat32(key string, value float32) {
	e.addField(key, value)
}

func (e *cliEncoder) AddInt(key string, value int) {
	e.addField(key, value)
}

func (e *cliEncoder) AddInt64(key string, value int64) {
	e.addField(key, value)
}

func (e *cliEncoder) AddInt32(key string, value int32) {
	e.addField(key, value)
}

func (e *cliEncoder) AddInt16(key string, value int16) {
	e.addField(key, value)
}

func (e *cliEncoder) AddInt8(key string, value int8) {
	e.addField(key, value)
}

func (e *cliEncoder) AddString(key, value string) {
	e.addField(key, value)
}

func (e *cliEncoder) AddTime(key string, value time.Time) {
	e.addField(key, value.Format(time.RFC3339))
}

func (e *cliEncoder) AddUint(key string, value uint) {
	e.addField(key, value)
}

func (e *cliEncoder) AddUint64(key string, value uint64) {
	e.addField(key, value)
}

func (e *cliEncoder) AddUint32(key string, value uint32) {
	e.addField(key, value)
}

func (e *cliEncoder) AddUint16(key string, value uint16) {
	e.addField(key, value)
}

func (e *cliEncoder) AddUint8(key string, value uint8) {
	e.addField(key, value)
}

func (e *cliEncoder) AddUintptr(key string, value uintptr) {
	e.addField(key, value)
}

func (e *cliEncoder) AddReflected(key string, value interface{}) error {
	e.addField(key, value)
	return nil
}

func (e *cliEncoder) OpenNamespace(key string) {
	e.addField(key, "")
}

type cliObjectEncoder struct {
	fields map[string]interface{}
}

func (e *cliObjectEncoder) ensureFields() {
	if e.fields == nil {
		e.fields = make(map[string]interface{})
	}
}

func (e *cliObjectEncoder) AddArray(key string, marshaler zapcore.ArrayMarshaler) error {
	enc := &cliArrayEncoder{}
	err := marshaler.MarshalLogArray(enc)
	e.set(key, enc.values)
	return err
}

func (e *cliObjectEncoder) AddObject(key string, marshaler zapcore.ObjectMarshaler) error {
	enc := &cliObjectEncoder{}
	err := marshaler.MarshalLogObject(enc)
	e.set(key, enc.fields)
	return err
}

func (e *cliObjectEncoder) AddBinary(key string, value []byte)     { e.set(key, value) }
func (e *cliObjectEncoder) AddByteString(key string, value []byte) { e.set(key, string(value)) }
func (e *cliObjectEncoder) AddBool(key string, value bool)         { e.set(key, value) }
func (e *cliObjectEncoder) AddComplex128(key string, value complex128) {
	e.set(key, fmt.Sprint(value))
}
func (e *cliObjectEncoder) AddComplex64(key string, value complex64) { e.set(key, fmt.Sprint(value)) }
func (e *cliObjectEncoder) AddDuration(key string, value time.Duration) {
	e.set(key, value.String())
}
func (e *cliObjectEncoder) AddFloat64(key string, value float64) { e.set(key, value) }
func (e *cliObjectEncoder) AddFloat32(key string, value float32) { e.set(key, value) }
func (e *cliObjectEncoder) AddInt(key string, value int)         { e.set(key, value) }
func (e *cliObjectEncoder) AddInt64(key string, value int64)     { e.set(key, value) }
func (e *cliObjectEncoder) AddInt32(key string, value int32)     { e.set(key, value) }
func (e *cliObjectEncoder) AddInt16(key string, value int16)     { e.set(key, value) }
func (e *cliObjectEncoder) AddInt8(key string, value int8)       { e.set(key, value) }
func (e *cliObjectEncoder) AddString(key, value string)          { e.set(key, value) }
func (e *cliObjectEncoder) AddTime(key string, value time.Time) {
	e.set(key, value.Format(time.RFC3339))
}
func (e *cliObjectEncoder) AddUint(key string, value uint)       { e.set(key, value) }
func (e *cliObjectEncoder) AddUint64(key string, value uint64)   { e.set(key, value) }
func (e *cliObjectEncoder) AddUint32(key string, value uint32)   { e.set(key, value) }
func (e *cliObjectEncoder) AddUint16(key string, value uint16)   { e.set(key, value) }
func (e *cliObjectEncoder) AddUint8(key string, value uint8)     { e.set(key, value) }
func (e *cliObjectEncoder) AddUintptr(key string, value uintptr) { e.set(key, value) }
func (e *cliObjectEncoder) AddReflected(key string, value interface{}) error {
	e.set(key, value)
	return nil
}
func (e *cliObjectEncoder) OpenNamespace(key string) { e.set(key, map[string]interface{}{}) }

func (e *cliObjectEncoder) set(key string, value interface{}) {
	e.ensureFields()
	e.fields[key] = value
}

type cliArrayEncoder struct {
	values []interface{}
}

func (e *cliArrayEncoder) AppendBool(value bool)         { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendByteString(value []byte) { e.values = append(e.values, string(value)) }
func (e *cliArrayEncoder) AppendComplex128(value complex128) {
	e.values = append(e.values, fmt.Sprint(value))
}
func (e *cliArrayEncoder) AppendComplex64(value complex64) {
	e.values = append(e.values, fmt.Sprint(value))
}
func (e *cliArrayEncoder) AppendFloat64(value float64) { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendFloat32(value float32) { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendInt(value int)         { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendInt64(value int64)     { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendInt32(value int32)     { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendInt16(value int16)     { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendInt8(value int8)       { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendString(value string)   { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendUint(value uint)       { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendUint64(value uint64)   { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendUint32(value uint32)   { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendUint16(value uint16)   { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendUint8(value uint8)     { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendUintptr(value uintptr) { e.values = append(e.values, value) }
func (e *cliArrayEncoder) AppendDuration(value time.Duration) {
	e.values = append(e.values, value.String())
}
func (e *cliArrayEncoder) AppendTime(value time.Time) {
	e.values = append(e.values, value.Format(time.RFC3339))
}
func (e *cliArrayEncoder) AppendArray(marshaler zapcore.ArrayMarshaler) error {
	enc := &cliArrayEncoder{}
	err := marshaler.MarshalLogArray(enc)
	e.values = append(e.values, enc.values)
	return err
}
func (e *cliArrayEncoder) AppendObject(marshaler zapcore.ObjectMarshaler) error {
	enc := &cliObjectEncoder{}
	err := marshaler.MarshalLogObject(enc)
	e.values = append(e.values, enc.fields)
	return err
}
func (e *cliArrayEncoder) AppendReflected(value interface{}) error {
	e.values = append(e.values, value)
	return nil
}

func formatLogValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return formatLogString(v)
	case fmt.Stringer:
		return formatLogString(v.String())
	case error:
		return formatLogString(v.Error())
	case []byte:
		return formatLogString(string(v))
	default:
		return formatLogJSON(v)
	}
}

func formatLogString(value string) string {
	if value == "" || strings.ContainsAny(value, " \t\r\n\"'=") {
		return strconv.Quote(value)
	}
	return value
}

func formatLogJSON(value interface{}) string {
	data, err := json.Marshal(value)
	if err != nil {
		return formatLogString(fmt.Sprint(value))
	}
	return string(data)
}
