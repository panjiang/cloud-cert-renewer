# cert-renewer

A small daemon/CLI that keeps Tencent Cloud SSL certificates in sync on the certificate host.

Run it on the machine that already serves the certificates.

Supported features:

- Checks the current public TLS certificate for each configured domain
- Downloads a newer Tencent Cloud certificate when the domain enters the `beforeExpired` window
- Optionally auto-applies a new Tencent Cloud DV certificate when no deployable certificate is available
- Replaces local certificate files atomically
- Runs domain-level `postCommands`
- Runs `globalPostCommands` for each domain that reaches the deployment stage
- Verifies the external certificate after `globalPostCommands`
- Optionally starts asynchronous cleanup of older Tencent Cloud certificates after verification succeeds

## Install

Install the latest Linux release:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | sudo sh
```

Optional: install a specific version instead of the latest release:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | \
  sudo env VERSION=v0.1.0 sh
```

## Install (Optional: China Proxy)

If direct access to GitHub is slow or blocked, use a mirrored script URL, set `GITHUB_PROXY`, and install an explicit release tag.

Use a specific version instead of relying on the default `latest` resolution.

Install or upgrade through `ghproxy.net`:

```sh
curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | \
  sudo env GITHUB_PROXY=https://ghproxy.net VERSION=<release-tag> sh
```

## Configure

If you want to start from the installed example file and `/etc/cert-renewer/config.yaml` does not already exist:

```sh
sudo cp -n /etc/cert-renewer/config.yaml.example /etc/cert-renewer/config.yaml
```

This avoids overwriting an existing runtime configuration.

Edit the runtime config:

The installer creates this file with `0600` permissions if it does not already exist.

```sh
sudo vi /etc/cert-renewer/config.yaml
```

Example configuration:

```yaml
alert:
  # Renewal window. Must be between 3d and 30d.
  beforeExpired: 10d
  # Check interval. Default is 12h. Minimum is 1m.
  checkInterval: 12h
  # Optional. Leave empty to log only.
  notifyUrl: https://open.feishu.cn/open-apis/bot/v2/hook/xxxx

log:
  # debug, info, warn, or error. Default is info.
  level: info

# Default provider. Currently only tencentcloud is supported.
defaultProvider: tencentcloud

providerConfigs:
  tencentcloud:
    # Required.
    secretId: xxx
    # Required.
    secretKey: xxx
    # Optional. Delete older Tencent Cloud certificates asynchronously
    # after the new certificate is externally verified. Default is false.
    autoDeleteOldCertificates: true
    autoApply:
      # Auto-apply a free DV certificate when no deployable certificate exists.
      # Wildcard domains are not auto-applied.
      enabled: true
      # Poll interval for issuance status. Must be greater than 0.
      pollInterval: 1m
      # Max wait time in one round. Must be >= pollInterval.
      pollTimeout: 10m
      # Delete the DNS_AUTO validation record after verification.
      deleteDnsAutoRecord: true

# Optional. Run once after each domain is deployed locally and before external verification.
globalPostCommands:
  - nginx -t
  - nginx -s reload

domains:
  - domain: doc.yourdomain.com
    # Required certificate file path.
    certPath: /etc/nginx/ssl/doc.yourdomain.com.crt
    # Required private key file path.
    keyPath: /etc/nginx/ssl/doc.yourdomain.com.key
    # Optional. Run after this domain is deployed.
    postCommands:
      - consul kv put certs/doc.yourdomain.com.crt @{{.CertPath}}
      - consul kv put certs/doc.yourdomain.com.key @{{.KeyPath}}
```

Configuration notes:

- Durations use Go-style units plus day and week units: `ms`, `s`, `m`, `h`, `d`, and `w`.
- Example durations: `12h`, `10d`, `1w`.
- Command entries are executed with `sh -lc`.
- Domain-level `postCommands` receive `{{.Domain}}`, `{{.CertPath}}`, `{{.KeyPath}}`, `{{.BackupCertPath}}`, and `{{.BackupKeyPath}}`.
- Top-level `globalPostCommands` do not receive domain-specific values.
- `providerConfigs.tencentcloud.autoDeleteOldCertificates` defaults to `false` when omitted.
- Old certificate cleanup only runs after the new certificate is externally verified, and it skips any certificate that still appears to be live or shared with another managed domain.

## Validate (Optional)

Run one normal round before starting the service:

```sh
sudo /usr/local/bin/cert-renewer -config=/etc/cert-renewer/config.yaml -once
```

This is not a dry-run. It may download or apply certificates, replace local files, run `postCommands`, run `globalPostCommands`, verify the external certificate, and trigger old certificate cleanup.

Use it to validate the configuration and operational flow before enabling the service.

Make sure the `cert-renewer` service is not already running when you execute it.

## Daemon

Start the service after the config is ready:

```sh
sudo systemctl enable --now cert-renewer
sudo systemctl status cert-renewer
```

View service logs:

```sh
sudo journalctl -u cert-renewer -f
```

## Upgrade

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | sudo sh
sudo systemctl restart cert-renewer
```

## Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/uninstall.sh | sudo sh
```

Keep the runtime config during uninstall:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/uninstall.sh | \
  sudo env KEEP_CONFIG=1 sh
```
