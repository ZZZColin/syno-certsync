"""AWS ACM fetcher (SigV4). ExportCertificate returns an encrypted key; we decrypt with openssl."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
from datetime import datetime, timezone

from ..util import Cert, parse_time, http


def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4(secret, method, uri, query, headers, payload, region, service, amzdate):
    """AWS Signature V4. headers: lowercase name -> value, all of them get signed.
    Returns (signature, signed_headers, credential_scope)."""
    date = amzdate[:8]
    signed = ";".join(sorted(headers))
    canon_headers = "".join("%s:%s\n" % (k, headers[k]) for k in sorted(headers))
    canon = "\n".join([method, uri, query, canon_headers, signed, hashlib.sha256(payload.encode()).hexdigest()])
    scope = "%s/%s/%s/aws4_request" % (date, region, service)
    sts = "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (amzdate, scope, hashlib.sha256(canon.encode()).hexdigest())
    k = _sign(_sign(_sign(_sign(("AWS4" + secret).encode(), date), region), service), "aws4_request")
    return hmac.new(k, sts.encode(), hashlib.sha256).hexdigest(), signed, scope


class AwsFetcher:
    def __init__(self, conf):
        self.ak = conf.get("access_key_id")
        self.sk = conf.get("secret_access_key")
        self.token = conf.get("session_token")
        self.region = conf.get("region", "us-east-1")
        if not (self.ak and self.sk):
            raise SystemExit("[aws] access_key_id / secret_access_key missing in config")
        self.host = "acm.%s.amazonaws.com" % self.region

    def _call(self, target, payload):
        body = json.dumps(payload)
        now = datetime.now(timezone.utc)
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        hdrs = {"content-type": "application/x-amz-json-1.1", "host": self.host,
                "x-amz-date": amzdate, "x-amz-target": "CertificateManager." + target}
        if self.token:
            hdrs["x-amz-security-token"] = self.token
        sig, signed, scope = sigv4(self.sk, "POST", "/", "", hdrs, body, self.region, "acm", amzdate)
        hdrs["Authorization"] = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
            self.ak, scope, signed, sig)
        return json.loads(http("POST", "https://" + self.host + "/", hdrs, body))

    def list_certs(self):
        certs, token = [], None
        while True:
            # By default ACM lists only RSA_2048 certs; ask for every key type.
            req = {"CertificateStatuses": ["ISSUED"],
                   # only certs ACM allows to export; others would fail at ExportCertificate
                   "Includes": {"exportOption": "ENABLED", "keyTypes": ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
                                             "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]}}
            if token:
                req["NextToken"] = token
            r = self._call("ListCertificates", req)
            for s in r.get("CertificateSummaryList", []):
                certs.append(Cert(
                    provider="aws", cert_id=s["CertificateArn"], domain=s.get("DomainName", ""),
                    not_before=parse_time(s.get("IssuedAt") or s.get("NotBefore")),
                    not_after=parse_time(s.get("NotAfter")), status="issued",
                    sans=",".join(s.get("SubjectAlternativeNameSummaries") or [])))
            token = r.get("NextToken")
            if not token:
                return certs

    def download(self, cert):
        passphrase = secrets.token_hex(16)
        r = self._call("ExportCertificate", {
            "CertificateArn": cert.cert_id,
            "Passphrase": base64.b64encode(passphrase.encode()).decode()})
        cert.cert_pem = r["Certificate"]
        cert.chain_pem = r.get("CertificateChain", "")
        # pass the passphrase via env, not argv, so it does not show up in `ps`
        env = dict(os.environ, CERTSYNC_PASS=passphrase)
        try:
            p = subprocess.run(["openssl", "pkey", "-passin", "env:CERTSYNC_PASS"],
                               input=r["PrivateKey"].encode(), capture_output=True, env=env)
        except FileNotFoundError:
            raise RuntimeError("[aws] openssl not found; it is required to decrypt the exported key")
        if p.returncode != 0:
            raise RuntimeError("[aws] openssl failed to decrypt key: " + p.stderr.decode())
        cert.key_pem = p.stdout.decode()
