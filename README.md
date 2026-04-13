# cloud-cert-renewer

Update Tencent Cloud SSL certificates directly on the certificate host.

The program runs on the machine that already serves the certificates. It checks the current public TLS certificate for each configured domain, downloads a newer Tencent Cloud certificate when the domain enters the `beforeExpired` window, replaces local certificate files atomically, runs domain-level `postCommands`, verifies the external certificate, and finally runs one round of `globalPostCommands` if every updated domain succeeded.

## Config

```yaml
alert:
  beforeExpired: 10d
  checkInterval: 12h
  notifyUrl: https://open.feishu.cn/open-apis/bot/v2/hook/xxxx

log:
  level: info

defaultProvider: tencentcloud

providerConfigs:
  tencentcloud:
    secretId: xxx
    secretKey: xxx
    autoApply:
      enabled: true
      pollInterval: 1m
      pollTimeout: 10m
      deleteDnsAutoRecord: true

globalPostCommands:
  - nginx -t
  - nginx -s reload

domains:
  - domain: doc.yourdomain.com
    certPath: /etc/nginx/ssl/doc.yourdomain.com.crt
    keyPath: /etc/nginx/ssl/doc.yourdomain.com.key
    postCommands:
      - consul kv put certs/doc.yourdomain.com.crt @{{.CertPath}}
      - consul kv put certs/doc.yourdomain.com.key @{{.KeyPath}}
```

`alert.checkInterval` controls how often the updater checks the public TLS certificate for each configured domain. If omitted, it defaults to `12h`; the minimum allowed value is `1m`. `alert.beforeExpired` controls the renewal window, not the check interval.

## Run

```sh
go run . -config=config.yaml
```
