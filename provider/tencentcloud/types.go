package tencentcloud

import "time"

type Config struct {
	SecretID                  string
	SecretKey                 string
	AutoApply                 AutoApplyConfig
	AutoDeleteOldCertificates bool
}

type AutoApplyConfig struct {
	Enabled             bool
	PollInterval        time.Duration
	PollTimeout         time.Duration
	DeleteDNSAutoRecord bool
}
