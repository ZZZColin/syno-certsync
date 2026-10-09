"""Tencent Cloud SSL fetcher. TC3-HMAC-SHA256 signing, ssl 2019-12-05."""
import base64
import hashlib
import hmac
import io
import json
import time
import zipfile
from datetime import datetime, timezone

from ..util import Cert, parse_time, http, CN_TZ

HOST = "ssl.tencentcloudapi.com"
VERSION = "2019-12-05"


def _h(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def tc3_signature(secret_key, service, timestamp, canonical_headers, signed_headers, payload, method="POST"):
    """TC3-HMAC-SHA256. canonical_headers must already be 'k:v\\n' lines. Returns (signature, scope)."""
    date = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d")
    canon = "%s\n/\n\n%s\n%s\n%s" % (method, canonical_headers, signed_headers,
                                    hashlib.sha256(payload.encode()).hexdigest())
    scope = "%s/%s/tc3_request" % (date, service)
    sts = "TC3-HMAC-SHA256\n%d\n%s\n%s" % (timestamp, scope, hashlib.sha256(canon.encode()).hexdigest())
    k = _h(_h(_h(("TC3" + secret_key).encode(), date), service), "tc3_request")
    return hmac.new(k, sts.encode(), hashlib.sha256).hexdigest(), scope


class TencentFetcher:
    def __init__(self, conf):
        self.sid = conf.get("secret_id")
        self.skey = conf.get("secret_key")
        if not (self.sid and self.skey):
            raise SystemExit("[tencent] secret_id / secret_key missing in config")

    def _call(self, action, payload):
        body = json.dumps(payload)
        ts = int(time.time())
        ct = "application/json; charset=utf-8"
        sig, scope = tc3_signature(self.skey, "ssl", ts, "content-type:%s\nhost:%s\n" % (ct, HOST),
                                   "content-type;host", body)
        auth = "TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host, Signature=%s" % (self.sid, scope, sig)
        headers = {"Authorization": auth, "Content-Type": ct, "Host": HOST,
                   "X-TC-Action": action, "X-TC-Version": VERSION, "X-TC-Timestamp": str(ts)}
        r = json.loads(http("POST", "https://" + HOST, headers, body)).get("Response")
        if not isinstance(r, dict):
            raise RuntimeError("[tencent] %s: unexpected response" % action)
        if "Error" in r:
            raise RuntimeError("[tencent] %s: %s" % (action, r["Error"]))
        return r

    def list_certs(self):
        certs, offset = [], 0
        while True:
            r = self._call("DescribeCertificates", {"Offset": offset, "Limit": 100})
            items = r.get("Certificates") or []
            for it in items:
                if it.get("Status") not in (1, 3):  # 1 = issued, 3 = expired (dropped later unless --include-expired)
                    continue
                certs.append(Cert(
                    provider="tencent", cert_id=it["CertificateId"],
                    domain=it.get("Domain", ""),
                    not_before=parse_time(it.get("CertBeginTime"), CN_TZ),
                    not_after=parse_time(it.get("CertEndTime"), CN_TZ),
                    status="issued", sans=",".join(it.get("SubjectAltName") or []),
                ))
            offset += 100
            if offset >= r.get("TotalCount", 0) or not items:
                break
        return certs

    def download(self, cert):
        r = self._call("DownloadCertificate", {"CertificateId": cert.cert_id})
        z = zipfile.ZipFile(io.BytesIO(base64.b64decode(r["Content"])))
        names = [n for n in z.namelist() if "nginx" in n.lower()] or z.namelist()
        keys = [n for n in names if n.endswith(".key")]
        crts = [n for n in names if n.endswith((".crt", ".pem"))]
        if not crts:
            raise RuntimeError("[tencent] unexpected zip layout: %s" % z.namelist())
        bundle = next((n for n in crts if "bundle" in n), crts[0])
        full = z.read(bundle).decode()
        if keys:
            cert.key_pem = z.read(keys[0]).decode()
        else:  # zip without a key: DescribeCertificateDetail may still hold it
            d = self._call("DescribeCertificateDetail", {"CertificateId": cert.cert_id})
            cert.key_pem = d.get("CertificatePrivateKey") or ""
            if not cert.key_pem:
                raise RuntimeError("[tencent] cert %s has no downloadable private key" % cert.cert_id)
        # Split leaf from chain
        marker = "-----END CERTIFICATE-----"
        head, _, rest = full.partition(marker)
        cert.cert_pem = head + marker + "\n"
        cert.chain_pem = rest.strip() + "\n" if rest.strip() else ""
