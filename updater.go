package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	providerpkg "github.com/panjiang/cloud-cert-renewer/provider"
	"go.uber.org/zap"
)

type Updater struct {
	cfg       *Config
	notifier  Notifier
	providers map[string]providerpkg.Provider
	deployer  *LocalDeployer
	ctx       context.Context
}

type successfulUpdate struct {
	domain   DomainConfig
	material *CertificateMaterial
	result   *DeployResult
	observed *ObservedCertificate
}

type deployedUpdate struct {
	domain   DomainConfig
	material *CertificateMaterial
	result   *DeployResult
}

func NewUpdater(cfg *Config, notifier Notifier) (*Updater, func(), error) {
	ctx, cancel := context.WithCancel(context.Background())

	providers, err := NewProviders(cfg)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	return &Updater{
			cfg:       cfg,
			notifier:  notifier,
			providers: providers,
			deployer:  NewLocalDeployer(),
			ctx:       ctx,
		}, func() {
			cancel()
			zap.L().Info("stopped")
		}, nil
}

func (u *Updater) Run() {
	ticker := time.NewTicker(u.cfg.Alert.CheckInterval)
	defer ticker.Stop()

	zap.L().Info("started", zap.Duration("interval", u.cfg.Alert.CheckInterval))
	for {
		u.checkOnce(u.ctx)
		select {
		case <-ticker.C:
		case <-u.ctx.Done():
			return
		}
	}
}

func (u *Updater) checkOnce(ctx context.Context) {
	var deployed []deployedUpdate
	var failureCount int

	zap.L().Info("certificate check round started", zap.Int("domains", len(u.cfg.Domains)))

	for _, domain := range u.cfg.Domains {
		item, ok := u.handleDomain(ctx, domain)
		if !ok {
			failureCount++
			zap.L().Warn("stopping certificate check round because domain update failed",
				zap.String("domain", domain.Domain),
				zap.String("provider", domain.EffectiveProvider),
				zap.Int("deployedUpdates", len(deployed)),
				zap.Int("failures", failureCount))
			break
		}
		if item != nil {
			deployed = append(deployed, *item)
		}
	}

	if len(deployed) == 0 {
		zap.L().Info("certificate check round finished",
			zap.Int("domains", len(u.cfg.Domains)),
			zap.Int("successfulUpdates", 0),
			zap.Int("failures", failureCount))
		return
	}

	if failureCount > 0 {
		zap.L().Warn("skipping global post commands because a domain update failed",
			zap.Int("deployedUpdates", len(deployed)),
			zap.Int("failures", failureCount))
		zap.L().Info("certificate check round finished",
			zap.Int("domains", len(u.cfg.Domains)),
			zap.Int("successfulUpdates", 0),
			zap.Int("failures", failureCount))
		return
	}

	zap.L().Info("running global post commands", zap.Int("commands", len(u.cfg.GlobalPostCommands)))
	globalPostCommands, err := u.deployer.RunGlobalCommands(ctx, u.cfg.GlobalPostCommands)
	if err != nil {
		for _, item := range deployed {
			zap.L().Error("global post commands failed",
				zap.Error(err),
				zap.String("domain", item.domain.Domain),
				zap.String("stage", "global_post_commands"),
				zap.String("provider", item.domain.EffectiveProvider),
				zap.String("certificateId", item.material.CertificateID),
				zap.Bool("filesChanged", item.result.FilesChanged))
			u.notifier.Failure("Certificate Update Failed",
				fmt.Sprintf("domain=%s stage=global_post_commands provider=%s certificateId=%s filesChanged=%t error=%v",
					item.domain.Domain,
					item.domain.EffectiveProvider,
					item.material.CertificateID,
					item.result.FilesChanged,
					err))
		}
		zap.L().Info("certificate check round finished",
			zap.Int("domains", len(u.cfg.Domains)),
			zap.Int("successfulUpdates", 0),
			zap.Int("failures", len(deployed)))
		return
	}
	zap.L().Info("global post commands completed", zap.Int("commands", len(globalPostCommands)))

	successful := make([]successfulUpdate, 0, len(deployed))
	for _, item := range deployed {
		observed, err := u.verifyDeployedDomain(ctx, item)
		if err != nil {
			zap.L().Info("certificate check round finished",
				zap.Int("domains", len(u.cfg.Domains)),
				zap.Int("successfulUpdates", len(successful)),
				zap.Int("failures", 1))
			return
		}
		successful = append(successful, successfulUpdate{
			domain:   item.domain,
			material: item.material,
			result:   item.result,
			observed: observed,
		})
	}

	for _, item := range successful {
		u.notifier.Success("Certificate Updated",
			fmt.Sprintf("domain=%s provider=%s certificateId=%s fingerprint=%s serial=%s notAfter=%s filesChanged=%t postCommands=%s globalPostCommands=%s",
				item.domain.Domain,
				item.domain.EffectiveProvider,
				item.material.CertificateID,
				item.observed.Fingerprint,
				item.observed.Serial,
				item.observed.NotAfter.Format(time.RFC3339),
				item.result.FilesChanged,
				strings.Join(item.result.Commands, "; "),
				strings.Join(globalPostCommands, "; ")))
	}
	zap.L().Info("certificate check round finished",
		zap.Int("domains", len(u.cfg.Domains)),
		zap.Int("successfulUpdates", len(successful)),
		zap.Int("failures", 0))
}

func (u *Updater) handleDomain(ctx context.Context, domain DomainConfig) (*deployedUpdate, bool) {
	zap.L().Info("processing domain",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider))

	currentCert, err := probeTLSCertificate(ctx, domain.Domain)
	if err != nil {
		zap.L().Error("probe current certificate failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", "probe_current_certificate"),
			zap.String("provider", domain.EffectiveProvider))
		u.notifier.Failure("Certificate Update Failed",
			fmt.Sprintf("domain=%s stage=probe_current_certificate provider=%s error=%v",
				domain.Domain, domain.EffectiveProvider, err))
		return nil, false
	}

	remaining := time.Until(currentCert.NotAfter)
	zap.L().Info("checked current certificate",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.Int64("daysRemaining", int64(remaining.Hours())/24),
		zap.Time("notAfter", currentCert.NotAfter),
		zap.String("fingerprint", currentCert.Fingerprint))

	if remaining > u.cfg.Alert.BeforeExpired {
		zap.L().Info("certificate is not in renewal window",
			zap.String("domain", domain.Domain),
			zap.String("provider", domain.EffectiveProvider),
			zap.Duration("remaining", remaining),
			zap.Duration("beforeExpired", u.cfg.Alert.BeforeExpired))
		return nil, true
	}

	zap.L().Info("certificate entered renewal window",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.Duration("remaining", remaining),
		zap.Duration("beforeExpired", u.cfg.Alert.BeforeExpired))

	provider, err := resolveProvider(u.providers, domain)
	if err != nil {
		zap.L().Error("resolve provider failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", "resolve_provider"),
			zap.String("provider", domain.EffectiveProvider))
		u.notifier.Failure("Certificate Update Failed",
			fmt.Sprintf("domain=%s stage=resolve_provider provider=%s error=%v",
				domain.Domain, domain.EffectiveProvider, err))
		return nil, false
	}

	zap.L().Info("querying provider for newer certificate",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider))
	resolution, err := provider.ResolveCertificate(ctx, domain.Domain, toProviderObservedCertificate(currentCert))
	if err != nil {
		stage := "query_or_download"
		var stageErr *providerpkg.StageError
		if errors.As(err, &stageErr) {
			stage = stageErr.Stage
		}
		zap.L().Error("query or download certificate failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", stage),
			zap.String("provider", domain.EffectiveProvider))
		u.notifier.Failure("Certificate Update Failed",
			fmt.Sprintf("domain=%s stage=%s provider=%s error=%v",
				domain.Domain, stage, domain.EffectiveProvider, err))
		return nil, false
	}
	if resolution == nil || (resolution.Material == nil && resolution.Pending == nil) {
		zap.L().Info("no newer provider certificate",
			zap.String("domain", domain.Domain),
			zap.String("provider", domain.EffectiveProvider))
		return nil, true
	}
	if resolution.Pending != nil {
		zap.L().Warn("certificate issuance is still pending",
			zap.String("domain", domain.Domain),
			zap.String("provider", domain.EffectiveProvider),
			zap.String("certificateId", resolution.Pending.CertificateID),
			zap.Uint64("status", resolution.Pending.Status),
			zap.String("statusName", resolution.Pending.StatusName),
			zap.String("statusMsg", resolution.Pending.StatusMsg),
			zap.String("verifyType", resolution.Pending.VerifyType))
		return nil, true
	}

	nextCert := fromProviderCertificateMaterial(resolution.Material)

	zap.L().Info("deploying newer certificate",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.String("certificateId", nextCert.CertificateID),
		zap.Time("notAfter", nextCert.NotAfter),
		zap.String("fingerprint", nextCert.Fingerprint),
		zap.String("certPath", domain.CertPath),
		zap.String("keyPath", domain.KeyPath))
	result, err := u.deployer.DeployDomain(ctx, domain, nextCert)
	if err != nil {
		stage := "deploy_local_files"
		var stageErr *DeployStageError
		if errors.As(err, &stageErr) {
			stage = stageErr.Stage
		}
		zap.L().Error("deploy local files failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", stage),
			zap.String("provider", domain.EffectiveProvider),
			zap.String("certificateId", nextCert.CertificateID),
			zap.String("certPath", domain.CertPath),
			zap.String("keyPath", domain.KeyPath))
		u.notifier.Failure("Certificate Update Failed",
			fmt.Sprintf("domain=%s stage=%s provider=%s certPath=%s keyPath=%s error=%v",
				domain.Domain, stage, domain.EffectiveProvider, domain.CertPath, domain.KeyPath, err))
		return nil, false
	}

	return &deployedUpdate{
		domain:   domain,
		material: nextCert,
		result:   result,
	}, true
}

func (u *Updater) verifyDeployedDomain(ctx context.Context, item deployedUpdate) (*ObservedCertificate, error) {
	domain := item.domain
	nextCert := item.material
	result := item.result

	zap.L().Info("verifying external deployment",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.String("certificateId", nextCert.CertificateID),
		zap.String("expectedFingerprint", nextCert.Fingerprint))
	observed, err := verifyExternalDeployment(ctx, domain.Domain, nextCert.Fingerprint)
	if err != nil {
		zap.L().Error("verify external deployment failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", "verify_external"),
			zap.String("provider", domain.EffectiveProvider),
			zap.String("certificateId", nextCert.CertificateID),
			zap.String("certPath", domain.CertPath),
			zap.String("keyPath", domain.KeyPath),
			zap.Bool("filesChanged", result.FilesChanged))
		u.notifier.Failure("Certificate Update Failed",
			fmt.Sprintf("domain=%s stage=verify_external provider=%s certPath=%s keyPath=%s filesChanged=%t error=%v",
				domain.Domain, domain.EffectiveProvider, domain.CertPath, domain.KeyPath, result.FilesChanged, err))
		return nil, err
	}
	zap.L().Info("external deployment verified",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.String("certificateId", nextCert.CertificateID),
		zap.String("fingerprint", observed.Fingerprint),
		zap.String("serial", observed.Serial),
		zap.Time("notAfter", observed.NotAfter),
		zap.Bool("filesChanged", result.FilesChanged))

	return observed, nil
}
