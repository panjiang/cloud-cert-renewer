package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"go.uber.org/zap"
)

type LocalDeployer struct{}

type DeployResult struct {
	FilesChanged   bool
	BackupCertPath string
	BackupKeyPath  string
	Commands       []string
}

type DeployStageError struct {
	Stage string
	Err   error
}

func (e *DeployStageError) Error() string {
	return e.Err.Error()
}

func (e *DeployStageError) Unwrap() error {
	return e.Err
}

type commandTemplateData struct {
	Domain         string
	CertPath       string
	KeyPath        string
	BackupCertPath string
	BackupKeyPath  string
}

func NewLocalDeployer() *LocalDeployer {
	zap.L().Info("initialized local deployer")
	return &LocalDeployer{}
}

func (d *LocalDeployer) DeployDomain(ctx context.Context, domain DomainConfig, material *CertificateMaterial) (*DeployResult, error) {
	result := &DeployResult{}

	zap.L().Info("starting local deployment",
		zap.String("domain", domain.Domain),
		zap.String("certificateId", material.CertificateID),
		zap.String("certPath", domain.CertPath),
		zap.String("keyPath", domain.KeyPath))

	currentFingerprint, err := localCertificateFingerprint(domain.CertPath)
	if err != nil {
		return nil, fmt.Errorf("read local certificate: %w", err)
	}

	if currentFingerprint != material.Fingerprint {
		if err := d.replaceLocalFiles(domain, material, result); err != nil {
			return nil, err
		}
		result.FilesChanged = true
	} else {
		zap.L().Info("local certificate files already match target fingerprint",
			zap.String("domain", domain.Domain),
			zap.String("certificateId", material.CertificateID),
			zap.String("fingerprint", material.Fingerprint))
	}

	templateData := commandTemplateData{
		Domain:         domain.Domain,
		CertPath:       domain.CertPath,
		KeyPath:        domain.KeyPath,
		BackupCertPath: result.BackupCertPath,
		BackupKeyPath:  result.BackupKeyPath,
	}
	for i, commandTemplate := range domain.PostCommands {
		command, err := renderCommand(commandTemplate, templateData)
		if err != nil {
			return nil, &DeployStageError{
				Stage: "post_commands",
				Err:   fmt.Errorf("render post command: %w", err),
			}
		}
		zap.L().Info("executing domain post command",
			zap.String("domain", domain.Domain),
			zap.Int("commandIndex", i+1),
			zap.Int("commandCount", len(domain.PostCommands)))
		zap.L().Debug("domain post command rendered",
			zap.String("domain", domain.Domain),
			zap.Int("commandIndex", i+1),
			zap.String("command", command))
		if err := execLocalCommand(ctx, command); err != nil {
			zap.L().Error("domain post command failed",
				zap.Error(err),
				zap.String("domain", domain.Domain),
				zap.Int("commandIndex", i+1))
			return nil, &DeployStageError{
				Stage: "post_commands",
				Err:   fmt.Errorf("exec local command %q: %w", command, err),
			}
		}
		zap.L().Info("domain post command completed",
			zap.String("domain", domain.Domain),
			zap.Int("commandIndex", i+1),
			zap.Int("commandCount", len(domain.PostCommands)))
		result.Commands = append(result.Commands, command)
	}

	zap.L().Info("local deployment completed",
		zap.String("domain", domain.Domain),
		zap.String("certificateId", material.CertificateID),
		zap.Bool("filesChanged", result.FilesChanged),
		zap.String("backupCertPath", result.BackupCertPath),
		zap.String("backupKeyPath", result.BackupKeyPath),
		zap.Int("postCommands", len(result.Commands)))

	return result, nil
}

func (d *LocalDeployer) RunGlobalCommands(ctx context.Context, commands []string) ([]string, error) {
	rendered := make([]string, 0, len(commands))
	for i, commandTemplate := range commands {
		command, err := renderCommand(commandTemplate, commandTemplateData{})
		if err != nil {
			return rendered, fmt.Errorf("render global command: %w", err)
		}
		zap.L().Info("executing global post command",
			zap.Int("commandIndex", i+1),
			zap.Int("commandCount", len(commands)))
		zap.L().Debug("global post command rendered",
			zap.Int("commandIndex", i+1),
			zap.String("command", command))
		if err := execLocalCommand(ctx, command); err != nil {
			zap.L().Error("global post command failed",
				zap.Error(err),
				zap.Int("commandIndex", i+1))
			return rendered, fmt.Errorf("exec global command %q: %w", command, err)
		}
		zap.L().Info("global post command completed",
			zap.Int("commandIndex", i+1),
			zap.Int("commandCount", len(commands)))
		rendered = append(rendered, command)
	}
	return rendered, nil
}

func (d *LocalDeployer) replaceLocalFiles(domain DomainConfig, material *CertificateMaterial, result *DeployResult) error {
	timestamp := time.Now().Format("20060102T150405")
	tempCertPath := fmt.Sprintf("%s.tmp.%d", domain.CertPath, time.Now().UnixNano())
	tempKeyPath := fmt.Sprintf("%s.tmp.%d", domain.KeyPath, time.Now().UnixNano())

	zap.L().Info("replacing local certificate files",
		zap.String("domain", domain.Domain),
		zap.String("certificateId", material.CertificateID),
		zap.String("certPath", domain.CertPath),
		zap.String("keyPath", domain.KeyPath))

	if err := ensureParentDir(domain.CertPath); err != nil {
		return fmt.Errorf("ensure cert parent dir: %w", err)
	}
	if err := ensureParentDir(domain.KeyPath); err != nil {
		return fmt.Errorf("ensure key parent dir: %w", err)
	}

	if err := writeLocalFile(tempCertPath, material.CertificatePEM, resolveLocalMode(domain.CertPath, 0644)); err != nil {
		return fmt.Errorf("write certificate temp file: %w", err)
	}
	defer os.Remove(tempCertPath)
	if err := writeLocalFile(tempKeyPath, material.PrivateKeyPEM, resolveLocalMode(domain.KeyPath, 0600)); err != nil {
		return fmt.Errorf("write key temp file: %w", err)
	}
	defer os.Remove(tempKeyPath)

	remoteCertPEM, err := os.ReadFile(tempCertPath)
	if err != nil {
		return fmt.Errorf("read certificate temp file: %w", err)
	}
	remoteKeyPEM, err := os.ReadFile(tempKeyPath)
	if err != nil {
		return fmt.Errorf("read key temp file: %w", err)
	}
	if _, err := parseCertificateMaterial(domain.Domain, material.CertificateID, remoteCertPEM, remoteKeyPEM); err != nil {
		return fmt.Errorf("validate temp certificate files: %w", err)
	}

	if backupPath, err := backupLocalFile(domain.CertPath, timestamp); err != nil {
		return fmt.Errorf("backup certificate: %w", err)
	} else {
		result.BackupCertPath = backupPath
	}
	if backupPath, err := backupLocalFile(domain.KeyPath, timestamp); err != nil {
		return fmt.Errorf("backup key: %w", err)
	} else {
		result.BackupKeyPath = backupPath
	}

	if err := os.Rename(tempCertPath, domain.CertPath); err != nil {
		return fmt.Errorf("replace certificate file: %w", err)
	}
	if err := os.Rename(tempKeyPath, domain.KeyPath); err != nil {
		return fmt.Errorf("replace key file: %w", err)
	}

	zap.L().Info("replaced local certificate files",
		zap.String("domain", domain.Domain),
		zap.String("certificateId", material.CertificateID),
		zap.String("backupCertPath", result.BackupCertPath),
		zap.String("backupKeyPath", result.BackupKeyPath))

	return nil
}

func localCertificateFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return certFingerprintFromPEM(data)
}

func ensureParentDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0755)
}

func resolveLocalMode(path string, fallback os.FileMode) os.FileMode {
	info, err := os.Stat(path)
	if err != nil {
		return fallback
	}
	return info.Mode()
}

func writeLocalFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func backupLocalFile(path, timestamp string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	backupPath := fmt.Sprintf("%s.bak.%s", path, timestamp)
	if err := writeLocalFile(backupPath, data, resolveLocalMode(path, 0600)); err != nil {
		return "", err
	}
	return backupPath, nil
}

func execLocalCommand(ctx context.Context, command string) error {
	cmd := exec.CommandContext(ctx, "sh", "-lc", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func renderCommand(commandTemplate string, data commandTemplateData) (string, error) {
	tmpl, err := template.New("command").Option("missingkey=zero").Parse(commandTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}
