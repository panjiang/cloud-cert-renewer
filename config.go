package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ProviderTencentCloud       = "tencentcloud"
	defaultCheckInterval       = 12 * time.Hour
	defaultCheckIntervalString = "12h"
	minCheckInterval           = time.Minute
)

type Config struct {
	Alert              AlertConfig     `yaml:"alert"`
	Log                LogConfig       `yaml:"log"`
	DefaultProvider    string          `yaml:"defaultProvider"`
	ProviderConfigs    ProviderConfigs `yaml:"providerConfigs"`
	GlobalPostCommands []string        `yaml:"globalPostCommands"`
	PostCommands       []string        `yaml:"postCommands"`
	Domains            []DomainConfig  `yaml:"domains"`
}

type AlertConfig struct {
	BeforeExpiredStr string        `yaml:"beforeExpired"`
	BeforeExpired    time.Duration `yaml:"-"`
	CheckIntervalStr string        `yaml:"checkInterval"`
	CheckInterval    time.Duration `yaml:"-"`
	NotifyURL        string        `yaml:"notifyUrl"`
}

type LogConfig struct {
	Level string `yaml:"level"`
}

type ProviderConfigs struct {
	TencentCloud TencentCloudConfig `yaml:"tencentcloud"`
}

type TencentCloudConfig struct {
	SecretID                   string                 `yaml:"secretId"`
	SecretKey                  string                 `yaml:"secretKey"`
	AutoApply                  TencentAutoApplyConfig `yaml:"autoApply"`
	AutoDeleteOldCertificates  *bool                  `yaml:"autoDeleteOldCertificates"`
	AutoDeleteOldCertificatesV bool                   `yaml:"-"`
}

type TencentAutoApplyConfig struct {
	Enabled              *bool         `yaml:"enabled"`
	EnabledV             bool          `yaml:"-"`
	PollIntervalStr      string        `yaml:"pollInterval"`
	PollInterval         time.Duration `yaml:"-"`
	PollTimeoutStr       string        `yaml:"pollTimeout"`
	PollTimeout          time.Duration `yaml:"-"`
	DeleteDNSAutoRecord  *bool         `yaml:"deleteDnsAutoRecord"`
	DeleteDNSAutoRecordV bool          `yaml:"-"`
}

type DomainConfig struct {
	Domain            string   `yaml:"domain"`
	Provider          string   `yaml:"provider"`
	CertPath          string   `yaml:"certPath"`
	KeyPath           string   `yaml:"keyPath"`
	PostCommands      []string `yaml:"postCommands"`
	EffectiveProvider string   `yaml:"-"`
}

func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := cfg.Complete(); err != nil {
		return nil, fmt.Errorf("complete config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) Complete() error {
	c.DefaultProvider = strings.TrimSpace(strings.ToLower(c.DefaultProvider))
	c.Log.Level = normalizeLogLevel(c.Log.Level)
	if c.DefaultProvider == "" {
		return fmt.Errorf("defaultProvider is required")
	}
	if c.DefaultProvider != ProviderTencentCloud {
		return fmt.Errorf("unsupported defaultProvider: %s", c.DefaultProvider)
	}
	if err := validateLogLevel(c.Log.Level); err != nil {
		return err
	}

	beforeExpired, err := ParseDuration(c.Alert.BeforeExpiredStr)
	if err != nil {
		return fmt.Errorf("invalid alert.beforeExpired: %w", err)
	}
	if beforeExpired.Hours() > 30*24 || beforeExpired.Hours() < 3*24 {
		return fmt.Errorf("invalid alert.beforeExpired: should be between 3 and 30 days")
	}
	c.Alert.BeforeExpired = beforeExpired

	c.Alert.CheckIntervalStr = strings.TrimSpace(c.Alert.CheckIntervalStr)
	if c.Alert.CheckIntervalStr == "" {
		c.Alert.CheckIntervalStr = defaultCheckIntervalString
	}
	checkInterval, err := ParseDuration(c.Alert.CheckIntervalStr)
	if err != nil {
		return fmt.Errorf("invalid alert.checkInterval: %w", err)
	}
	if checkInterval < minCheckInterval {
		return fmt.Errorf("invalid alert.checkInterval: should be greater than or equal to 1 minute")
	}
	c.Alert.CheckInterval = checkInterval

	if strings.TrimSpace(c.Alert.NotifyURL) != "" {
		if _, err := url.ParseRequestURI(c.Alert.NotifyURL); err != nil {
			return fmt.Errorf("invalid alert.notifyUrl: %w", err)
		}
	}

	if len(c.GlobalPostCommands) > 0 && len(c.PostCommands) > 0 {
		return fmt.Errorf("globalPostCommands and postCommands cannot be set together at the top level")
	}
	if len(c.GlobalPostCommands) == 0 && len(c.PostCommands) > 0 {
		c.GlobalPostCommands = c.PostCommands
	}
	c.PostCommands = nil

	if err := validateCommands("globalPostCommands", c.GlobalPostCommands); err != nil {
		return err
	}

	if len(c.Domains) == 0 {
		return fmt.Errorf("domains is required")
	}

	c.ProviderConfigs.TencentCloud.SecretID = strings.TrimSpace(c.ProviderConfigs.TencentCloud.SecretID)
	if c.ProviderConfigs.TencentCloud.SecretID == "" {
		return fmt.Errorf("providerConfigs.tencentcloud.secretId is required")
	}
	c.ProviderConfigs.TencentCloud.SecretKey = strings.TrimSpace(c.ProviderConfigs.TencentCloud.SecretKey)
	if c.ProviderConfigs.TencentCloud.SecretKey == "" {
		return fmt.Errorf("providerConfigs.tencentcloud.secretKey is required")
	}
	if err := c.ProviderConfigs.TencentCloud.AutoApply.complete(); err != nil {
		return fmt.Errorf("invalid providerConfigs.tencentcloud.autoApply: %w", err)
	}
	if c.ProviderConfigs.TencentCloud.AutoDeleteOldCertificates == nil {
		c.ProviderConfigs.TencentCloud.AutoDeleteOldCertificatesV = false
	} else {
		c.ProviderConfigs.TencentCloud.AutoDeleteOldCertificatesV = *c.ProviderConfigs.TencentCloud.AutoDeleteOldCertificates
	}

	seenDomains := make(map[string]struct{}, len(c.Domains))
	for i := range c.Domains {
		if err := c.Domains[i].complete(c.DefaultProvider); err != nil {
			return fmt.Errorf("invalid domains[%d]: %w", i, err)
		}
		if _, exists := seenDomains[c.Domains[i].Domain]; exists {
			return fmt.Errorf("duplicate domain: %s", c.Domains[i].Domain)
		}
		seenDomains[c.Domains[i].Domain] = struct{}{}
	}

	return nil
}

func (c *TencentAutoApplyConfig) complete() error {
	if c.Enabled == nil {
		c.EnabledV = true
	} else {
		c.EnabledV = *c.Enabled
	}

	c.PollIntervalStr = strings.TrimSpace(c.PollIntervalStr)
	c.PollTimeoutStr = strings.TrimSpace(c.PollTimeoutStr)

	if c.PollIntervalStr == "" {
		c.PollIntervalStr = "1m"
	}
	pollInterval, err := ParseDuration(c.PollIntervalStr)
	if err != nil {
		return fmt.Errorf("invalid pollInterval: %w", err)
	}
	if pollInterval <= 0 {
		return fmt.Errorf("invalid pollInterval: should be greater than 0")
	}
	c.PollInterval = pollInterval

	if c.PollTimeoutStr == "" {
		c.PollTimeoutStr = "10m"
	}
	pollTimeout, err := ParseDuration(c.PollTimeoutStr)
	if err != nil {
		return fmt.Errorf("invalid pollTimeout: %w", err)
	}
	if pollTimeout < pollInterval {
		return fmt.Errorf("invalid pollTimeout: should be greater than or equal to pollInterval")
	}
	c.PollTimeout = pollTimeout

	if c.DeleteDNSAutoRecord == nil {
		c.DeleteDNSAutoRecordV = true
	} else {
		c.DeleteDNSAutoRecordV = *c.DeleteDNSAutoRecord
	}

	return nil
}

func (d *DomainConfig) complete(defaultProvider string) error {
	d.Domain = strings.TrimSpace(d.Domain)
	d.Provider = strings.TrimSpace(strings.ToLower(d.Provider))
	d.CertPath = strings.TrimSpace(d.CertPath)
	d.KeyPath = strings.TrimSpace(d.KeyPath)

	if d.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if d.CertPath == "" {
		return fmt.Errorf("certPath is required")
	}
	if d.KeyPath == "" {
		return fmt.Errorf("keyPath is required")
	}

	d.EffectiveProvider = d.Provider
	if d.EffectiveProvider == "" {
		d.EffectiveProvider = defaultProvider
	}
	if d.EffectiveProvider != ProviderTencentCloud {
		return fmt.Errorf("unsupported provider: %s", d.EffectiveProvider)
	}

	if err := validateCommands("postCommands", d.PostCommands); err != nil {
		return err
	}

	return nil
}

func validateCommands(name string, commands []string) error {
	for i, command := range commands {
		if strings.TrimSpace(command) == "" {
			return fmt.Errorf("%s[%d] is empty", name, i)
		}
		if _, err := template.New("command").Option("missingkey=zero").Parse(command); err != nil {
			return fmt.Errorf("invalid %s[%d] template: %w", name, i, err)
		}
	}
	return nil
}

func normalizeLogLevel(level string) string {
	level = strings.TrimSpace(strings.ToLower(level))
	if level == "" {
		return "info"
	}
	return level
}

func validateLogLevel(level string) error {
	switch level {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("invalid log.level: %s", level)
	}
}
