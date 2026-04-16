package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigComplete(t *testing.T) {
	t.Run("valid with default provider", func(t *testing.T) {
		cfg := Config{
			Alert: AlertConfig{
				BeforeExpiredStr: "10d",
				NotifyURL:        "https://open.feishu.cn/open-apis/bot/v2/hook/xxxx",
			},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{
					SecretID:  "id",
					SecretKey: "key",
				},
			},
			GlobalPostCommands: []string{"nginx -t"},
			Domains: []DomainConfig{
				{
					Domain:       "doc.yourdomain.com",
					CertPath:     "/etc/nginx/ssl/doc.crt",
					KeyPath:      "/etc/nginx/ssl/doc.key",
					PostCommands: []string{"consul kv put certs/doc @{{.CertPath}}"},
				},
			},
		}

		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if cfg.Log.Level != "info" {
			t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, "info")
		}
		if cfg.Alert.CheckInterval != defaultCheckInterval {
			t.Fatalf("Alert.CheckInterval = %v, want %v", cfg.Alert.CheckInterval, defaultCheckInterval)
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.PollInterval != time.Minute {
			t.Fatalf("AutoApply.PollInterval = %v, want %v", cfg.ProviderConfigs.TencentCloud.AutoApply.PollInterval, time.Minute)
		}
		if !cfg.ProviderConfigs.TencentCloud.AutoApply.EnabledV {
			t.Fatal("AutoApply.EnabledV = false, want true")
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.PollTimeout != 10*time.Minute {
			t.Fatalf("AutoApply.PollTimeout = %v, want %v", cfg.ProviderConfigs.TencentCloud.AutoApply.PollTimeout, 10*time.Minute)
		}
		if !cfg.ProviderConfigs.TencentCloud.AutoApply.DeleteDNSAutoRecordV {
			t.Fatal("AutoApply.DeleteDNSAutoRecordV = false, want true")
		}
		if cfg.ProviderConfigs.TencentCloud.AutoDeleteOldCertificatesV {
			t.Fatal("AutoDeleteOldCertificatesV = true, want false by default")
		}
		if len(cfg.GlobalPostCommands) != 1 || cfg.GlobalPostCommands[0] != "nginx -t" {
			t.Fatalf("GlobalPostCommands = %#v, want %#v", cfg.GlobalPostCommands, []string{"nginx -t"})
		}
		if cfg.Domains[0].EffectiveProvider != ProviderTencentCloud {
			t.Fatalf("EffectiveProvider = %q, want %q", cfg.Domains[0].EffectiveProvider, ProviderTencentCloud)
		}
	})

	t.Run("unknown provider", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "10d"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{SecretID: "id", SecretKey: "key"},
			},
			Domains: []DomainConfig{
				{
					Domain:   "doc.yourdomain.com",
					Provider: "other",
					CertPath: "/etc/nginx/ssl/doc.crt",
					KeyPath:  "/etc/nginx/ssl/doc.key",
				},
			},
		}

		if err := cfg.Complete(); err == nil {
			t.Fatal("Complete() expected error")
		}
	})

	t.Run("notify url optional", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "10d"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{SecretID: "id", SecretKey: "key"},
			},
			Domains: []DomainConfig{
				{
					Domain:   "doc.yourdomain.com",
					CertPath: "/etc/nginx/ssl/doc.crt",
					KeyPath:  "/etc/nginx/ssl/doc.key",
				},
			},
		}

		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if cfg.Log.Level != "info" {
			t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, "info")
		}
	})

	t.Run("missing tencentcloud credentials", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "10d"},
			DefaultProvider: ProviderTencentCloud,
			Domains: []DomainConfig{
				{
					Domain:   "doc.yourdomain.com",
					CertPath: "/etc/nginx/ssl/doc.crt",
					KeyPath:  "/etc/nginx/ssl/doc.key",
				},
			},
		}

		if err := cfg.Complete(); err == nil {
			t.Fatal("Complete() expected missing credentials error")
		}
	})

	t.Run("duplicate domain", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "10d"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{SecretID: "id", SecretKey: "key"},
			},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc2.crt", KeyPath: "/etc/nginx/ssl/doc2.key"},
			},
		}

		if err := cfg.Complete(); err == nil {
			t.Fatal("Complete() expected duplicate error")
		}
	})

	t.Run("legacy top level postCommands is accepted", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "14d"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{SecretID: "id", SecretKey: "key"},
			},
			PostCommands: []string{"nginx -t"},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
			},
		}

		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if len(cfg.GlobalPostCommands) != 1 || cfg.GlobalPostCommands[0] != "nginx -t" {
			t.Fatalf("GlobalPostCommands = %#v, want %#v", cfg.GlobalPostCommands, []string{"nginx -t"})
		}
		if len(cfg.PostCommands) != 0 {
			t.Fatalf("PostCommands = %#v, want nil after normalization", cfg.PostCommands)
		}
	})

	t.Run("top level globalPostCommands and postCommands conflict", func(t *testing.T) {
		cfg := Config{
			Alert:              AlertConfig{BeforeExpiredStr: "14d"},
			DefaultProvider:    ProviderTencentCloud,
			ProviderConfigs:    ProviderConfigs{TencentCloud: TencentCloudConfig{SecretID: "id", SecretKey: "key"}},
			GlobalPostCommands: []string{"nginx -s reload"},
			PostCommands:       []string{"nginx -t"},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
			},
		}

		if err := cfg.Complete(); err == nil {
			t.Fatal("Complete() expected conflict error")
		}
	})

	t.Run("valid log levels", func(t *testing.T) {
		for _, level := range []string{"debug", "info", "warn", "error", " INFO "} {
			cfg := Config{
				Alert:           AlertConfig{BeforeExpiredStr: "14d"},
				Log:             LogConfig{Level: level},
				DefaultProvider: ProviderTencentCloud,
				ProviderConfigs: ProviderConfigs{TencentCloud: TencentCloudConfig{SecretID: "id", SecretKey: "key"}},
				Domains: []DomainConfig{
					{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
				},
			}

			if err := cfg.Complete(); err != nil {
				t.Fatalf("Complete() level=%q error = %v", level, err)
			}
		}
	})

	t.Run("invalid log level", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "14d"},
			Log:             LogConfig{Level: "trace"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{TencentCloud: TencentCloudConfig{SecretID: "id", SecretKey: "key"}},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
			},
		}

		if err := cfg.Complete(); err == nil {
			t.Fatal("Complete() expected invalid log level error")
		}
	})

	t.Run("valid check interval", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "14d", CheckIntervalStr: "6h"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{TencentCloud: TencentCloudConfig{SecretID: "id", SecretKey: "key"}},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
			},
		}

		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if cfg.Alert.CheckInterval != 6*time.Hour {
			t.Fatalf("Alert.CheckInterval = %v, want %v", cfg.Alert.CheckInterval, 6*time.Hour)
		}
	})

	t.Run("minimum check interval", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "14d", CheckIntervalStr: "1m"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{TencentCloud: TencentCloudConfig{SecretID: "id", SecretKey: "key"}},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
			},
		}

		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if cfg.Alert.CheckInterval != time.Minute {
			t.Fatalf("Alert.CheckInterval = %v, want %v", cfg.Alert.CheckInterval, time.Minute)
		}
	})

	t.Run("invalid check interval", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "14d", CheckIntervalStr: "59s"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{TencentCloud: TencentCloudConfig{SecretID: "id", SecretKey: "key"}},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
			},
		}

		if err := cfg.Complete(); err == nil {
			t.Fatal("Complete() expected invalid check interval error")
		}
	})

	t.Run("valid auto apply config", func(t *testing.T) {
		deleteDNSAutoRecord := false
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "14d"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{
					SecretID:  "id",
					SecretKey: "key",
					AutoApply: TencentAutoApplyConfig{
						Enabled:             boolPtr(true),
						PollIntervalStr:     "2m",
						PollTimeoutStr:      "15m",
						DeleteDNSAutoRecord: &deleteDNSAutoRecord,
					},
				},
			},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
			},
		}

		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.PollInterval != 2*time.Minute {
			t.Fatalf("AutoApply.PollInterval = %v, want %v", cfg.ProviderConfigs.TencentCloud.AutoApply.PollInterval, 2*time.Minute)
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.PollTimeout != 15*time.Minute {
			t.Fatalf("AutoApply.PollTimeout = %v, want %v", cfg.ProviderConfigs.TencentCloud.AutoApply.PollTimeout, 15*time.Minute)
		}
		if !cfg.ProviderConfigs.TencentCloud.AutoApply.EnabledV {
			t.Fatal("AutoApply.EnabledV = false, want true")
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.DeleteDNSAutoRecordV {
			t.Fatal("AutoApply.DeleteDNSAutoRecordV = true, want false")
		}
		if cfg.ProviderConfigs.TencentCloud.AutoDeleteOldCertificatesV {
			t.Fatal("AutoDeleteOldCertificatesV = true, want false")
		}
	})

	t.Run("explicit auto apply disabled", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "14d"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{
					SecretID:  "id",
					SecretKey: "key",
					AutoApply: TencentAutoApplyConfig{
						Enabled: boolPtr(false),
					},
				},
			},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
			},
		}

		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.EnabledV {
			t.Fatal("AutoApply.EnabledV = true, want false")
		}
	})

	t.Run("explicit auto delete old certificates enabled", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "14d"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{
					SecretID:                  "id",
					SecretKey:                 "key",
					AutoDeleteOldCertificates: boolPtr(true),
				},
			},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
			},
		}

		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if !cfg.ProviderConfigs.TencentCloud.AutoDeleteOldCertificatesV {
			t.Fatal("AutoDeleteOldCertificatesV = false, want true")
		}
	})

	t.Run("invalid auto apply poll timeout", func(t *testing.T) {
		cfg := Config{
			Alert:           AlertConfig{BeforeExpiredStr: "14d"},
			DefaultProvider: ProviderTencentCloud,
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{
					SecretID:  "id",
					SecretKey: "key",
					AutoApply: TencentAutoApplyConfig{
						Enabled:         boolPtr(true),
						PollIntervalStr: "2m",
						PollTimeoutStr:  "1m",
					},
				},
			},
			Domains: []DomainConfig{
				{Domain: "doc.yourdomain.com", CertPath: "/etc/nginx/ssl/doc.crt", KeyPath: "/etc/nginx/ssl/doc.key"},
			},
		}

		if err := cfg.Complete(); err == nil {
			t.Fatal("Complete() expected invalid auto apply timeout error")
		}
	})
}

func TestLoadConfigGlobalPostCommands(t *testing.T) {
	t.Run("defaults autoApply when omitted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		data := []byte(`alert:
  beforeExpired: 14d
defaultProvider: tencentcloud
providerConfigs:
  tencentcloud:
    secretId: id
    secretKey: key
domains:
  - domain: doc.yourdomain.com
    certPath: /etc/nginx/ssl/doc.crt
    keyPath: /etc/nginx/ssl/doc.key
`)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if !cfg.ProviderConfigs.TencentCloud.AutoApply.EnabledV {
			t.Fatal("AutoApply.EnabledV = false, want true")
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.PollInterval != time.Minute {
			t.Fatalf("AutoApply.PollInterval = %v, want %v", cfg.ProviderConfigs.TencentCloud.AutoApply.PollInterval, time.Minute)
		}
		if cfg.Alert.CheckInterval != defaultCheckInterval {
			t.Fatalf("Alert.CheckInterval = %v, want %v", cfg.Alert.CheckInterval, defaultCheckInterval)
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.PollTimeout != 10*time.Minute {
			t.Fatalf("AutoApply.PollTimeout = %v, want %v", cfg.ProviderConfigs.TencentCloud.AutoApply.PollTimeout, 10*time.Minute)
		}
		if !cfg.ProviderConfigs.TencentCloud.AutoApply.DeleteDNSAutoRecordV {
			t.Fatal("AutoApply.DeleteDNSAutoRecordV = false, want true")
		}
		if cfg.ProviderConfigs.TencentCloud.AutoDeleteOldCertificatesV {
			t.Fatal("AutoDeleteOldCertificatesV = true, want false when omitted")
		}
	})

	t.Run("loads globalPostCommands", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		data := []byte(`alert:
  beforeExpired: 14d
  checkInterval: 6h
log:
  level: debug
defaultProvider: tencentcloud
providerConfigs:
  tencentcloud:
    secretId: id
    secretKey: key
    autoDeleteOldCertificates: true
    autoApply:
      enabled: true
      pollInterval: 2m
      pollTimeout: 12m
      deleteDnsAutoRecord: false
globalPostCommands:
  - nginx -t
domains:
  - domain: doc.yourdomain.com
    certPath: /etc/nginx/ssl/doc.crt
    keyPath: /etc/nginx/ssl/doc.key
`)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if cfg.Log.Level != "debug" {
			t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
		}
		if cfg.Alert.CheckInterval != 6*time.Hour {
			t.Fatalf("Alert.CheckInterval = %v, want %v", cfg.Alert.CheckInterval, 6*time.Hour)
		}
		if !cfg.ProviderConfigs.TencentCloud.AutoApply.EnabledV {
			t.Fatal("AutoApply.EnabledV = false, want true")
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.PollInterval != 2*time.Minute {
			t.Fatalf("AutoApply.PollInterval = %v, want %v", cfg.ProviderConfigs.TencentCloud.AutoApply.PollInterval, 2*time.Minute)
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.PollTimeout != 12*time.Minute {
			t.Fatalf("AutoApply.PollTimeout = %v, want %v", cfg.ProviderConfigs.TencentCloud.AutoApply.PollTimeout, 12*time.Minute)
		}
		if cfg.ProviderConfigs.TencentCloud.AutoApply.DeleteDNSAutoRecordV {
			t.Fatal("AutoApply.DeleteDNSAutoRecordV = true, want false")
		}
		if !cfg.ProviderConfigs.TencentCloud.AutoDeleteOldCertificatesV {
			t.Fatal("AutoDeleteOldCertificatesV = false, want true")
		}
		if len(cfg.GlobalPostCommands) != 1 || cfg.GlobalPostCommands[0] != "nginx -t" {
			t.Fatalf("GlobalPostCommands = %#v, want %#v", cfg.GlobalPostCommands, []string{"nginx -t"})
		}
	})
}

func boolPtr(v bool) *bool {
	return &v
}
