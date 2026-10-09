"""ACME issuance (DNS-01) by driving acme.sh. Install it first: https://github.com/acmesh-official/acme.sh"""
import os
import shutil
import subprocess
import sys

from .providers import ACME_PROVIDERS
from .util import safe_name

# config.ini key -> environment variable expected by the acme.sh dns hook
ENV_MAP = {
    "aliyun": {"access_key_id": "Ali_Key", "access_key_secret": "Ali_Secret"},
    "tencent": {"secret_id": "Tencent_SecretId", "secret_key": "Tencent_SecretKey"},
    "cloudflare": {"api_token": "CF_Token", "account_id": "CF_Account_ID", "zone_id": "CF_Zone_ID"},
    "huawei": {"username": "HUAWEICLOUD_Username", "password": "HUAWEICLOUD_Password",
               "domain_name": "HUAWEICLOUD_DomainName", "region": "HUAWEICLOUD_Region"},
    "godaddy": {"key": "GD_Key", "secret": "GD_Secret"},
    "aws": {"access_key_id": "AWS_ACCESS_KEY_ID", "secret_access_key": "AWS_SECRET_ACCESS_KEY"},
}


def find_acme_sh():
    p = shutil.which("acme.sh") or os.path.expanduser("~/.acme.sh/acme.sh")
    if not os.path.exists(p):
        sys.exit("acme.sh not found. Install: curl https://get.acme.sh | sh")
    return p


def issue(provider, domains, conf, out_dir, ca="letsencrypt", email=None):
    acme = find_acme_sh()
    env = dict(os.environ)
    for k, var in ENV_MAP.get(provider, {}).items():
        if conf.get(k):
            env[var] = conf[k]
    cmd = [acme, "--issue", "--dns", ACME_PROVIDERS[provider], "--server", ca]
    for d in domains:
        cmd += ["-d", d]
    if email:
        cmd += ["--accountemail", email]
    # acme.sh docs recommend --dnssleep 600 for GoDaddy; any provider can set dnssleep in config.ini
    sleep = conf.get("dnssleep") or ("600" if provider == "godaddy" else None)
    if sleep:
        cmd += ["--dnssleep", str(sleep)]
    rc = subprocess.run(cmd, env=env).returncode
    if rc not in (0, 2):  # 2 = skipped, still valid
        sys.exit("acme.sh issue failed (rc=%d)" % rc)
    d = os.path.join(out_dir, safe_name(domains[0]))
    os.makedirs(d, exist_ok=True)
    cmd = [acme, "--install-cert", "-d", domains[0],
           "--cert-file", os.path.join(d, "cert.pem"),
           "--ca-file", os.path.join(d, "chain.pem"),
           "--fullchain-file", os.path.join(d, "fullchain.pem"),
           "--key-file", os.path.join(d, "privkey.pem")]
    if subprocess.run(cmd, env=env).returncode != 0:
        sys.exit("acme.sh install-cert failed")
    os.chmod(os.path.join(d, "privkey.pem"), 0o600)
    return d
