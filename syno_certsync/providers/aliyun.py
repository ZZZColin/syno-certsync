"""Alibaba Cloud SSL (CAS) fetcher. RPC API 2020-04-07, HMAC-SHA1 v1 signature."""
import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from ..util import Cert, parse_time, http, CN_TZ

ENDPOINT = "https://cas.aliyuncs.com/"
VERSION = "2020-04-07"


def _enc(s):
    return quote(str(s), safe="~")


def rpc_signature(params, secret):
    """Aliyun RPC signature v1 (HMAC-SHA1). Returns (canonical_query, signature)."""
    canon = "&".join("%s=%s" % (_enc(k), _enc(params[k])) for k in sorted(params))
    sts = "GET&%2F&" + _enc(canon)
    sig = base64.b64encode(hmac.new((secret + "&").encode(), sts.encode(), hashlib.sha1).digest()).decode()
    return canon, sig


class AliyunFetcher:
    def __init__(self, conf):
        self.ak = conf.get("access_key_id") or conf.get("ak")
        self.sk = conf.get("access_key_secret") or conf.get("sk")
        if not (self.ak and self.sk):
            raise SystemExit("[aliyun] access_key_id / access_key_secret missing in config")

    def _call(self, action, **params):
        p = {
            "Action": action, "Version": VERSION, "Format": "JSON",
            "AccessKeyId": self.ak, "SignatureMethod": "HMAC-SHA1",
            "SignatureVersion": "1.0", "SignatureNonce": uuid.uuid4().hex,
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        p.update({k: v for k, v in params.items() if v is not None})
        canon, sig = rpc_signature(p, self.sk)
        url = ENDPOINT + "?" + canon + "&Signature=" + _enc(sig)
        return json.loads(http("GET", url))

    def list_certs(self):
        certs, page = [], 1
        while True:
            r = self._call("ListUserCertificateOrder", OrderType="CERT", ShowSize=50, CurrentPage=page)
            items = r.get("CertificateOrderList") or []
            for it in items:
                # Only orders that already have an issued certificate id can be downloaded.
                cid = it.get("CertificateId")
                if not cid:
                    continue
                certs.append(Cert(
                    provider="aliyun", cert_id=str(cid),
                    domain=it.get("Domain") or it.get("CommonName") or "",
                    not_before=parse_time(it.get("StartDate") or it.get("CertStartTime"), CN_TZ),
                    not_after=parse_time(it.get("EndDate") or it.get("CertEndTime"), CN_TZ),
                    status="issued", sans=it.get("Sans") or "",
                ))
            total = r.get("TotalCount", 0)
            if page * 50 >= total or not items:
                break
            page += 1
        return certs

    def download(self, cert):
        r = self._call("GetUserCertificateDetail", CertId=cert.cert_id)
        cert.cert_pem = r.get("Cert", "")
        cert.key_pem = r.get("Key", "")
        if not cert.cert_pem or not cert.key_pem:
            # never echo the response: it may contain the private key
            raise RuntimeError("[aliyun] cert %s returned no cert/key (RequestId %s)" % (cert.cert_id, r.get("RequestId")))
