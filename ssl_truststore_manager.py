#!/usr/bin/env python3
"""
ssl_truststore_manager.py

Automates compare/update/cleanup of a Java truststore (PKCS12 or JKS)
against a roots.pem bundle (e.g. Google’s Root CAs) for multiple customers.

Features:
- Per-customer config in env.json (with global thresholds)
- --customer <name> and optional --local-roots <file> override
- JKS vs PKCS12 detection
- HTTP(S) download via corporate proxy (with URL-encoded creds)
- Retries & exponential backoff
- Brute-force PEM parsing
- Truststore extraction via keytool -list -rfc (with OpenSSL fallback)
- Conditional backups only on real changes
- Detailed console + file logging
- Metrics tracking & threshold-based alerting
- HTML email reports for compare & update
- SKIP_EMAIL flag for dev/testing
"""

import os
import sys
import json
import time
import shutil
import subprocess
import tempfile
import logging
import datetime
import argparse
import smtplib

from pathlib import Path
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import quote_plus

import urllib3
import requests
from requests.exceptions import HTTPError
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

# suppress insecure-request warnings if verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/114.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    # do not request br (Brotli), requests can handle gzip/deflate
    "Accept-Encoding": "gzip, deflate",
}

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

def load_config(customer_name, env_path='env.json'):
    try:
        raw = json.loads(Path(env_path).read_text())
    except Exception as e:
        print(f"[ERROR] Cannot read {env_path}: {e}", file=sys.stderr)
        sys.exit(1)

    cfg = raw.get('customers', {}).get(customer_name)
    if not cfg:
        print(f"[ERROR] Unknown customer '{customer_name}'", file=sys.stderr)
        sys.exit(1)

    # apply global thresholds
    for key, default in (
        ('MAX_DOWNLOAD_RETRIES', 5),
        ('ALERT_MAX_DOWNLOAD_RETRIES', 1),
        ('ALERT_MAX_DOWNLOAD_FAILURES', 0),
        ('ALERT_MAX_ERRORS', 0)
    ):
        cfg.setdefault(key, raw.get(key, default))

    # required keys
    for key in (
        'TRUSTSTORE_PATH','TRUSTSTORE_PASSWORD',
        'BACKUP_DIR','EMAIL_RECIPIENTS',
        'EMAIL_FROM_ADDRESS','EMAIL_SUBJECT_PREFIX'
    ):
        if not cfg.get(key):
            print(f"[ERROR] Missing '{key}' for '{customer_name}'", file=sys.stderr)
            sys.exit(1)

    cfg.setdefault('GOOGLE_CA_URL', 'https://pki.goog/roots.pem')
    return cfg

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

def setup_logging(cfg):
    fmt = "[%(asctime)s] [%(levelname)s] %(message)s"
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter(fmt))
    root.addHandler(ch)

    log_path = Path(cfg.get('LOG_FILE') or Path(cfg['BACKUP_DIR'])/'truststore_manager.log')
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_path, encoding='utf-8')
    fh.setFormatter(logging.Formatter(fmt))
    root.addHandler(fh)

    logging.info(f"Logging initialized → {log_path}")

# ------------------------------------------------------------------------------
# Helpers: proxy, download, parsing, truststore extraction
# ------------------------------------------------------------------------------

def build_proxies(cfg):
    host, port = cfg.get('PROXY_HOST'), cfg.get('PROXY_PORT')
    if not host or not port:
        logging.error("Proxy host/port not set")
        return {}
    user, pwd = cfg.get('PROXY_USER'), cfg.get('PROXY_PASSWORD')
    creds = f"{quote_plus(user)}:{quote_plus(pwd)}@" if user and pwd else ''
    proxy_url = f"http://{creds}{host}:{port}"
    logging.info(f"Using proxy: {proxy_url}")
    return {'http': proxy_url, 'https': proxy_url}

def get_roots_pem(cfg, proxies, metrics, local_override):
    if local_override:
        path = Path(local_override)
        logging.info(f"Loading local roots.pem → {path}")
        return path.read_bytes()
    return download_roots(
        cfg['GOOGLE_CA_URL'], proxies,
        cfg['MAX_DOWNLOAD_RETRIES'], metrics
    )

def download_roots(url, proxies, max_retries, metrics):
    backoff, attempt = 1, 0
    while True:
        metrics['download_attempts'] += 1
        try:
            logging.info(f"Downloading roots.pem attempt {attempt+1}")
            r = requests.get(
                url, headers=DEFAULT_HEADERS,
                proxies=proxies, timeout=30, verify=False
            )
            r.raise_for_status()
            logging.info("Download succeeded")
            return r.content
        except HTTPError as he:
            metrics['download_failures'] += 1
            logging.warning(f"HTTP {he.response.status_code}: retry in {backoff}s")
        except Exception as e:
            metrics['download_failures'] += 1
            logging.warning(f"Download error: {e!r}, retry in {backoff}s")
        if attempt < max_retries:
            metrics['download_retries'] += 1
            time.sleep(backoff); backoff *= 2; attempt += 1
        else:
            logging.error("Download failed after retries")
            raise RuntimeError("Could not download roots.pem")

def parse_pem_certs(pem_bytes):
    text = pem_bytes.decode('utf-8', errors='ignore')
    parts = text.split('-----BEGIN CERTIFICATE-----')[1:]
    certs = []
    for p in parts:
        end = p.find('-----END CERTIFICATE-----')
        if end == -1:
            logging.warning("Skipping malformed PEM block")
            continue
        pem = '-----BEGIN CERTIFICATE-----' + p[:end+len('-----END CERTIFICATE-----')]
        try:
            certs.append(x509.load_pem_x509_certificate(pem.encode()))
        except Exception as e:
            logging.warning(f"PEM parse error: {e}")
    logging.info(f"Parsed {len(certs)} certificates")
    return certs

def extract_existing_certs(ts_path, password, storetype):
    # try OpenSSL
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_name = tmp.name
        subprocess.run(
            ["openssl","pkcs12","-in",ts_path,
             "-passin",f"pass:{password}","-nokeys","-out",tmp_name],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        data = Path(tmp_name).read_bytes()
        os.remove(tmp_name)
        certs = parse_pem_certs(data)
        if certs:
            logging.info(f"OpenSSL: extracted {len(certs)} cert(s)")
            return certs
        logging.info("OpenSSL: 0 certs found, falling back")
    except subprocess.CalledProcessError:
        logging.warning("OpenSSL failed; falling back")

    # fallback to keytool
    try:
        out = subprocess.check_output(
            ["keytool","-list","-rfc",
             "-keystore", ts_path,
             "-storepass", password,
             "-storetype", storetype],
            stderr=subprocess.DEVNULL
        )
        certs = parse_pem_certs(out)
        logging.info(f"Keytool: extracted {len(certs)} cert(s)")
        return certs
    except Exception as e:
        logging.error(f"Truststore parse failed: {e}")
        return []

def fingerprint(cert):
    return cert.fingerprint(hashes.SHA1()).hex()

def make_backup(ts_path, backup_dir):
    ts = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    dst = Path(backup_dir)/f"{Path(ts_path).stem}-{ts}{Path(ts_path).suffix}"
    Path(backup_dir).mkdir(parents=True, exist_ok=True)
    shutil.copy2(ts_path, dst)
    logging.info(f"Backup created: {dst}")
    return dst

def run_keytool_import(ts, pw, alias, pem_path, stype):
    subprocess.run([
        "keytool","-importcert","-alias",alias,
        "-file",pem_path,
        "-keystore",ts,
        "-storepass",pw,
        "-storetype",stype,
        "-noprompt"
    ], check=True)
    logging.debug(f"Imported {alias}")

def run_keytool_delete(ts, pw, alias, stype):
    subprocess.run([
        "keytool","-delete","-alias",alias,
        "-keystore",ts,
        "-storepass",pw,
        "-storetype",stype
    ], check=True)
    logging.debug(f"Deleted {alias}")

def send_email(subject, body, cfg):
    """Plain-text email for cleanup mode."""
    if cfg.get('SKIP_EMAIL'):
        logging.info("SKIP_EMAIL set; skipping email")
        return
    msg = EmailMessage()
    msg['Subject'] = f"{cfg['EMAIL_SUBJECT_PREFIX']} {subject}"
    msg['From']    = cfg['EMAIL_FROM_ADDRESS']
    msg['To']      = ', '.join(cfg['EMAIL_RECIPIENTS'])
    msg.set_content(body)
    try:
        with smtplib.SMTP('localhost', timeout=5) as s:
            s.send_message(msg)
        logging.info("Email sent")
    except Exception as e:
        logging.warning(f"Email error: {e}")

def send_html_report(subject, cfg,
                     local_map, remote_map,
                     matched, only_loc, only_rem):
    """HTML email with Metric+Count summary and detail tables."""
    if cfg.get('SKIP_EMAIL'):
        logging.info("SKIP_EMAIL set; skipping email")
        return

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"{cfg['EMAIL_SUBJECT_PREFIX']} {subject}"
    msg['From']    = cfg['EMAIL_FROM_ADDRESS']
    msg['To']      = ', '.join(cfg['EMAIL_RECIPIENTS'])

    # Plain-text fallback
    text = (
        f"{subject}\n\n"
        f"Total Local:  {len(local_map)}\n"
        f"Total Remote: {len(remote_map)}\n"
        f"Matched:      {len(matched)}\n"
        f"Only Local:   {len(only_loc)}\n"
        f"Only Remote:  {len(only_rem)}\n"
    )
    msg.attach(MIMEText(text, 'plain'))

    # HTML body
    html = [
        "<html><body style='font-family:Arial,sans-serif;'>",
        f"<h2>{subject}</h2>",
        "<style>",
        "table { border-collapse: collapse; width: 100%; margin-bottom:20px; }",
        "th, td { border:1px solid #ccc; padding:8px; text-align:left; }",
        "th { background:#f5f5f5; }",
        "</style>",

        # Summary
        "<h3>Summary</h3>",
        "<table><tr><th>Metric</th><th>Count</th></tr>"
    ]
    for name, count in [
        ("Total Local",   len(local_map)),
        ("Total Remote",  len(remote_map)),
        ("Matched",       len(matched)),
        ("Only Local",    len(only_loc)),
        ("Only Remote",   len(only_rem))
    ]:
        html.append(f"<tr><td>{name}</td><td>{count}</td></tr>")
    html.append("</table>")

    # Details helper
    def render_details(title, items, data_map):
        html.append(f"<h3>{title} ({len(items)})</h3>")
        html.append("<table><tr><th>Fingerprint</th><th>Common Name</th></tr>")
        for fp in items:
            cn = data_map.get(fp, "")
            html.append(f"<tr><td>{fp}</td><td>{cn}</td></tr>")
        html.append("</table>")

    html.append("<h3>Details</h3>")
    render_details("Matched Certificates", matched, local_map)
    render_details("Only in Local Truststore", only_loc, local_map)
    render_details("Only in Remote roots.pem", only_rem, remote_map)

    html.append("</body></html>")
    msg.attach(MIMEText(''.join(html), 'html'))

    try:
        with smtplib.SMTP('localhost', timeout=5) as smtp:
            smtp.send_message(msg)
        logging.info("HTML report sent")
    except Exception as e:
        logging.warning(f"Failed to send HTML report: {e}")

# ------------------------------------------------------------------------------
# Modes
# ------------------------------------------------------------------------------

def mode_compare(cfg, metrics, local_roots):
    proxies = build_proxies(cfg)
    pem = get_roots_pem(cfg, proxies, metrics, local_roots)
    remote = parse_pem_certs(pem)
    local  = extract_existing_certs(
        cfg['TRUSTSTORE_PATH'], cfg['TRUSTSTORE_PASSWORD'], cfg['STORE_TYPE']
    )

    # build fingerprint→CN maps
    def mkmap(certs):
        m = {}
        for c in certs:
            fp = fingerprint(c)
            cn_attr = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = cn_attr[0].value if cn_attr else ""
            m[fp] = cn
        return m

    local_map  = mkmap(local)
    remote_map = mkmap(remote)
    m   = set(local_map)&set(remote_map)
    only_loc = set(local_map) - m
    only_rem = set(remote_map) - m

    print(f"\nCOMPARE REPORT - {datetime.datetime.now().isoformat()}")
    print(f"Local: {len(local_map)}, Remote: {len(remote_map)}")
    print(f"Matched: {len(m)}, OnlyLocal: {len(only_loc)}, OnlyRemote: {len(only_rem)}")

    send_html_report(
        "Compare Report", cfg,
        local_map, remote_map,
        matched=m, only_loc=only_loc, only_rem=only_rem
    )

def mode_update(cfg, metrics, local_roots):
    proxies = build_proxies(cfg)
    pem = get_roots_pem(cfg, proxies, metrics, local_roots)
    new = parse_pem_certs(pem)
    exist = extract_existing_certs(
        cfg['TRUSTSTORE_PATH'], cfg['TRUSTSTORE_PASSWORD'], cfg['STORE_TYPE']
    )
    exist_fps = { fingerprint(c) for c in exist }

    to_add = []
    for cert in new:
        fp = fingerprint(cert)
        if fp not in exist_fps:
            subj = cert.subject.rfc4514_string()
            to_add.append((fp, subj, cert))

    if not to_add:
        msg = "No new certificates; truststore up-to-date."
        logging.info(msg); print(msg)
        return

    backup_path = make_backup(cfg['TRUSTSTORE_PATH'], cfg['BACKUP_DIR'])
    # import
    for fp, subj, cert in to_add:
        with tempfile.NamedTemporaryFile('wb', delete=False, suffix='.pem') as tmp:
            tmp.write(cert.public_bytes(
                encoding=x509.Encoding.PEM if hasattr(x509, 'Encoding') else cert.public_bytes
            ))
            pem_path = tmp.name
        run_keytool_import(
            cfg['TRUSTSTORE_PATH'], cfg['TRUSTSTORE_PASSWORD'],
            fp, pem_path, cfg['STORE_TYPE']
        )
        os.remove(pem_path)

    # build maps for report
    local_map  = {fingerprint(c): c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                  for c in exist}
    remote_map = {fingerprint(c): c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                  for c in new}
    m   = set(local_map)&set(remote_map)
    only_loc = set(local_map) - m
    only_rem = set(remote_map) - m

    print(f"\nUPDATE REPORT - {datetime.datetime.now().isoformat()}")
    print(f"Backup created at: {backup_path}")
    print(f"Added: {len(to_add)}")

    send_html_report(
        "Update Report", cfg,
        local_map, remote_map,
        matched=m, only_loc=only_loc, only_rem=only_rem
    )

def mode_cleanup(cfg, metrics, _):
    exist = extract_existing_certs(
        cfg['TRUSTSTORE_PATH'], cfg['TRUSTSTORE_PASSWORD'], cfg['STORE_TYPE']
    )
    now = datetime.datetime.utcnow()
    expired = [(fingerprint(c), c.subject.rfc4514_string())
               for c in exist if c.not_valid_after < now]

    if not expired:
        msg = "No expired certificates; skipping cleanup."
        logging.info(msg); print(msg)
        return

    backup = make_backup(cfg['TRUSTSTORE_PATH'], cfg['BACKUP_DIR'])
    for fp, _ in expired:
        run_keytool_delete(
            cfg['TRUSTSTORE_PATH'], cfg['TRUSTSTORE_PASSWORD'],
            fp, cfg['STORE_TYPE']
        )

    # plain-text cleanup report
    lines = [
        f"CLEANUP REPORT - {datetime.datetime.now().isoformat()}",
        f"Backup created at: {backup}",
        f"Removed: {len(expired)}"
    ] + [f"x {fp}" for fp, _ in expired]
    report = "\n".join(lines)
    print(report)
    send_email("Cleanup Report", report, cfg)

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser()
    p.add_argument('-c','--customer', required=True)
    p.add_argument('-r','--local-roots', help="path to local roots.pem")
    p.add_argument('mode', choices=['compare','update','cleanup'])
    args = p.parse_args()

    cfg = load_config(args.customer)
    Path(cfg['BACKUP_DIR']).mkdir(parents=True, exist_ok=True)
    setup_logging(cfg)

    cfg['STORE_TYPE'] = 'JKS' if cfg['TRUSTSTORE_PATH'].lower().endswith('.jks') else 'PKCS12'
    logging.info(f"Store type: {cfg['STORE_TYPE']}")

    metrics = { k:0 for k in (
        'download_attempts','download_retries','download_failures',
        'certs_added','certs_skipped','certs_removed','errors'
    )}

    try:
        fn = {'compare': mode_compare, 'update': mode_update, 'cleanup': mode_cleanup}[args.mode]
        fn(cfg, metrics, args.local_roots)
    except Exception:
        metrics['errors'] += 1
        logging.exception("Fatal error")
        sys.exit(1)
    else:
        # alert if thresholds exceeded
        if (metrics['download_retries']  > cfg['ALERT_MAX_DOWNLOAD_RETRIES'] or
            metrics['download_failures'] > cfg['ALERT_MAX_DOWNLOAD_FAILURES'] or
            metrics['errors']            > cfg['ALERT_MAX_ERRORS']):
            alert = "\n".join(f"{k}: {v}" for k, v in metrics.items())
            send_email("ALERT: thresholds exceeded", alert, cfg)

if __name__ == '__main__':
    main()