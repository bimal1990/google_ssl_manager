# SSL Truststore Manager

`ssl_truststore_manager.py` automates the comparison, updating, and cleanup of Java truststores (JKS or PKCS12) using a trusted certificate bundle such as Google’s `roots.pem`.

## Features

- Per-customer configuration via `env.json`
- Truststore type detection: JKS or PKCS12
- Downloads roots.pem via HTTP(S) with proxy support and exponential backoff
- Parses certificates using OpenSSL and Java keytool
- Creates backups only when changes are made
- Provides HTML-formatted email reports and plain-text alerts
- Tracks metrics like retries, failures, and errors
- Alerting thresholds configurable via `env.json`
- Optional local override of roots.pem

## Requirements

- Python 3.6 or later
- Python modules: `requests`, `cryptography`
- Java `keytool` and `openssl` installed and accessible in the system `PATH`

## Usage

```bash
python3 ssl_truststore_manager.py -c <customer_name> [--local-roots <path/to/roots.pem>] <mode>
```
## Available Modes
`compare`: Compares truststore with the given roots.pem

`update`: Adds new certificates from roots.pem to the truststore

`cleanup`: Removes expired certificates from the truststore

## Examples
```bash
python3 ssl_truststore_manager.py -c acme_corp compare
python3 ssl_truststore_manager.py -c acme_corp update
python3 ssl_truststore_manager.py -c acme_corp cleanup
```
## Configuration – `env.json`
Each customer must have a configuration block in the `env.json` file:
```bash
{
  "MAX_DOWNLOAD_RETRIES": 5,
  "customers": {
    "acme_corp": {
      "TRUSTSTORE_PATH": "/opt/acme/truststore.jks",
      "TRUSTSTORE_PASSWORD": "changeit",
      "BACKUP_DIR": "/opt/acme/backups",
      "EMAIL_RECIPIENTS": ["admin@acme.com"],
      "EMAIL_FROM_ADDRESS": "noreply@acme.com",
      "EMAIL_SUBJECT_PREFIX": "[Truststore Manager]",
      "PROXY_HOST": "proxy.acme.com",
      "PROXY_PORT": "8080",
      "PROXY_USER": "proxyuser",
      "PROXY_PASSWORD": "proxypass"
    }
  }
}
```
## Optional Config Flags
`SKIP_EMAIL`: Set to true to disable email reporting (useful for testing)

`GOOGLE_CA_URL`: Custom URL to download root certificates

Thresholds for alerts:

  `ALERT_MAX_DOWNLOAD_RETRIES`

  `ALERT_MAX_DOWNLOAD_FAILURES`

  `ALERT_MAX_ERRORS`

## Logging
Logs are written both to console and a file named truststore_manager.log located in the BACKUP_DIR.

## Email Reporting
Reports include a summary of metrics and HTML tables of matched/missing/expired certificates

Uses local SMTP (localhost) to send email

## Backup
Before updating or deleting certs, a backup of the truststore is created with a timestamp.

## License
`MIT License`
