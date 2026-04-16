package main

import (
	"fmt"

	providerpkg "github.com/panjiang/cert-renewer/provider"
	tencentcloudprovider "github.com/panjiang/cert-renewer/provider/tencentcloud"
	"go.uber.org/zap"
)

func NewProviders(cfg *Config) (map[string]providerpkg.Provider, error) {
	tencentProvider, err := tencentcloudprovider.New(tencentcloudprovider.Config{
		SecretID:                  cfg.ProviderConfigs.TencentCloud.SecretID,
		SecretKey:                 cfg.ProviderConfigs.TencentCloud.SecretKey,
		AutoDeleteOldCertificates: cfg.ProviderConfigs.TencentCloud.AutoDeleteOldCertificatesV,
		AutoApply: tencentcloudprovider.AutoApplyConfig{
			Enabled:             cfg.ProviderConfigs.TencentCloud.AutoApply.EnabledV,
			PollInterval:        cfg.ProviderConfigs.TencentCloud.AutoApply.PollInterval,
			PollTimeout:         cfg.ProviderConfigs.TencentCloud.AutoApply.PollTimeout,
			DeleteDNSAutoRecord: cfg.ProviderConfigs.TencentCloud.AutoApply.DeleteDNSAutoRecordV,
		},
	})
	if err != nil {
		return nil, err
	}
	zap.L().Info("providers initialized", zap.String("defaultProvider", cfg.DefaultProvider))

	return map[string]providerpkg.Provider{
		ProviderTencentCloud: tencentProvider,
	}, nil
}

func resolveProvider(providers map[string]providerpkg.Provider, domain DomainConfig) (providerpkg.Provider, error) {
	provider, ok := providers[domain.EffectiveProvider]
	if !ok {
		return nil, fmt.Errorf("provider not initialized: %s", domain.EffectiveProvider)
	}
	return provider, nil
}

func toProviderObservedCertificate(cert *ObservedCertificate) *providerpkg.ObservedCertificate {
	if cert == nil {
		return nil
	}
	return &providerpkg.ObservedCertificate{
		Domain:      cert.Domain,
		Fingerprint: cert.Fingerprint,
		NotAfter:    cert.NotAfter,
	}
}

func toProviderCertificateMaterial(material *CertificateMaterial) *providerpkg.CertificateMaterial {
	if material == nil {
		return nil
	}
	return &providerpkg.CertificateMaterial{
		CertificateID:  material.CertificateID,
		Domain:         material.Domain,
		CertificatePEM: material.CertificatePEM,
		PrivateKeyPEM:  material.PrivateKeyPEM,
		Fingerprint:    material.Fingerprint,
		Serial:         material.Serial,
		NotAfter:       material.NotAfter,
	}
}

func fromProviderCertificateMaterial(material *providerpkg.CertificateMaterial) *CertificateMaterial {
	if material == nil {
		return nil
	}
	return &CertificateMaterial{
		CertificateID:  material.CertificateID,
		Domain:         material.Domain,
		CertificatePEM: material.CertificatePEM,
		PrivateKeyPEM:  material.PrivateKeyPEM,
		Fingerprint:    material.Fingerprint,
		Serial:         material.Serial,
		NotAfter:       material.NotAfter,
	}
}
