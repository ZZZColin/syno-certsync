"""Shared helpers: certificate model, time-range filter, disk output. Stdlib only."""
import json
import os
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional

UTC = timezone.utc


@dataclass
class Cert:
    provider: str
    cert_id: str
    domain: str
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    status: str = ""
    cert_pem: str = ""
    chain_pem: str = ""
    key_pem: str = ""
    sans: str = ""  # extra names, comma separated; used by --domain matching only

    def normalize(self):
        """Some providers return a bundle in cert_pem; split it into leaf + chain."""
        blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", self.cert_pem, re.S)
        if len(blocks) > 1:
            self.cert_pem = blocks[0] + "\n"
            if not self.chain_pem.strip():
                self.chain_pem = "\n".join(blocks[1:]) + "\n"

    @property
    def fullchain_pem(self) -> str:
        body = self.cert_pem.strip() + "\n"
        if self.chain_pem.strip() and self.chain_pem.strip() not in self.cert_pem:
            body += self.chain_pem.strip() + "\n"
        return body


CN_TZ = timezone(timedelta(hours=8))  # Aliyun/Tencent return naive China local time


def parse_time(value, naive_tz=UTC) -> Optional[datetime]:
    """Accept epoch seconds/millis, 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM:SS', ISO8601.
    Naive strings are interpreted in naive_tz. Returns an aware datetime."""
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit() and len(value) >= 10):
        n = float(value)
        if n > 1e11:  # millis
            n /= 1000.0
        return datetime.fromtimestamp(n, UTC)
    s = str(value).strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=naive_tz)
        except ValueError:
            pass
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=naive_tz)


def resolve_range(since: Optional[str], until: Optional[str], days: Optional[int]):
    """--days N means 'since now-N days'. `until` stays open unless given, so that
    --by expires (future dates) is not accidentally cut off at 'now'."""
    u = parse_time(until)
    if since:
        s = parse_time(since)
    elif days is not None:
        s = datetime.now(UTC) - timedelta(days=days)
    else:
        s = None
    return s, u


def dedupe_latest(certs):
    """Keep only the newest cert per domain so repeated orders cannot overwrite each other."""
    best = {}
    floor = datetime.min.replace(tzinfo=UTC)
    for c in certs:
        cur = best.get(c.domain)
        if cur is None or (c.not_before or floor) > (cur.not_before or floor):
            best[c.domain] = c
    return list(best.values())


def in_range(dt: Optional[datetime], since, until) -> bool:
    if dt is None:
        return since is None
    if since and dt < since:
        return False
    if until and dt > until:
        return False
    return True


def filter_certs(certs: List[Cert], since, until, field_name="issued", domain=None, valid_only=True):
    now = datetime.now(UTC)
    out = []
    for c in certs:
        dt = c.not_before if field_name == "issued" else c.not_after
        if not in_range(dt, since, until):
            continue
        if valid_only and c.not_after and c.not_after < now:
            continue
        if domain and not (domain_match(domain, c.domain) or domain_match(domain, c.sans)):
            continue
        out.append(c)
    return out


def domain_match(want: str, have: str) -> bool:
    want, have = want.lower().strip(), have.lower().strip()
    names = [n.strip() for n in re.split(r"[,\s]+", have) if n.strip()]
    for n in names:
        if n == want:
            return True
        if n.startswith("*."):
            prefix = want[:-len(n) + 1] if want.endswith(n[1:]) else None
            if prefix and "." not in prefix:  # wildcard covers exactly one label
                return True
    return False


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s.replace("*", "wildcard"))


def write_cert(cert: Cert, out_dir: str) -> str:
    cert.normalize()
    d = os.path.join(out_dir, safe_name(cert.domain.split(",")[0]))
    os.makedirs(out_dir, mode=0o700, exist_ok=True)  # private keys live below this directory
    os.makedirs(d, mode=0o700, exist_ok=True)
    files = {
        "cert.pem": cert.cert_pem,
        "chain.pem": cert.chain_pem,
        "fullchain.pem": cert.fullchain_pem,
        "privkey.pem": cert.key_pem,
    }
    for name, content in files.items():
        p = os.path.join(d, name)
        mode = 0o600 if name == "privkey.pem" else 0o644
        # create with the final mode so the private key is never world-readable
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "w", newline="\n") as f:
            f.write(content)
    meta = {
        "provider": cert.provider,
        "cert_id": cert.cert_id,
        "domain": cert.domain,
        "not_before": cert.not_before.isoformat() if cert.not_before else None,
        "not_after": cert.not_after.isoformat() if cert.not_after else None,
    }
    with open(os.path.join(d, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    return d


def http(method, url, headers=None, data=None, timeout=30):
    if isinstance(data, str):
        data = data.encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode()
    except urllib.error.HTTPError as e:
        # strip the query string: signed URLs carry the access key id and signature
        raise RuntimeError("HTTP %s from %s: %s" % (e.code, url.split("?")[0], e.read().decode(errors="replace")[:500]))
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError("network error calling %s: %s" % (url.split("?")[0], e))
