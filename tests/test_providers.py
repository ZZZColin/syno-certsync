"""Provider tests against canned API responses (shapes taken from the vendors' API docs)."""
import base64
import io
import json
import unittest
import zipfile
from unittest import mock
from urllib.parse import urlparse, parse_qs

from syno_certsync.providers.aliyun import AliyunFetcher
from syno_certsync.providers.tencent import TencentFetcher
from syno_certsync.providers.aws import AwsFetcher

LEAF = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
CA = "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n"
KEY = "-----BEGIN PRIVATE KEY-----\nKKK\n-----END PRIVATE KEY-----\n"


class AliyunTest(unittest.TestCase):
    def test_list_and_download(self):
        calls = []

        def fake_http(method, url, headers=None, data=None, timeout=30):
            q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
            calls.append(q)
            self.assertIn("Signature", q)
            if q["Action"] == "ListUserCertificateOrder":
                return json.dumps({"TotalCount": 1, "CertificateOrderList": [
                    {"CertificateId": 896521, "CommonName": "a.com", "Sans": "a.com,www.a.com",
                     "StartDate": "2026-09-01", "EndDate": "2026-12-01"}]})
            return json.dumps({"Cert": LEAF + CA, "Key": KEY})

        with mock.patch("syno_certsync.providers.aliyun.http", fake_http):
            f = AliyunFetcher({"access_key_id": "id", "access_key_secret": "s%ecret"})
            certs = f.list_certs()
            self.assertEqual(certs[0].cert_id, "896521")
            self.assertEqual(certs[0].domain, "a.com")
            self.assertEqual(certs[0].not_before.utcoffset().total_seconds(), 8 * 3600)
            self.assertEqual(calls[0]["OrderType"], "CERT")
            f.download(certs[0])
            self.assertEqual(calls[1]["CertId"], "896521")
            certs[0].normalize()
            self.assertEqual(certs[0].chain_pem.strip(), CA.strip())
            self.assertEqual(certs[0].key_pem, KEY)


class TencentTest(unittest.TestCase):
    def test_list_and_download(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("Nginx/1_a.com_bundle.crt", LEAF + CA)
            z.writestr("Nginx/2_a.com.key", KEY)
            z.writestr("Apache/a.com.crt", LEAF)
        zip_b64 = base64.b64encode(buf.getvalue()).decode()

        def fake_http(method, url, headers=None, data=None, timeout=30):
            self.assertTrue(headers["Authorization"].startswith("TC3-HMAC-SHA256 Credential=sid/"))
            if headers["X-TC-Action"] == "DescribeCertificates":
                return json.dumps({"Response": {"TotalCount": 2, "Certificates": [
                    {"CertificateId": "c1", "Domain": "a.com", "Status": 1,
                     "CertBeginTime": "2026-09-01 08:00:00", "CertEndTime": "2026-12-01 07:59:59",
                     "SubjectAltName": ["www.a.com"]},
                    {"CertificateId": "c2", "Domain": "b.com", "Status": 0}]}})
            return json.dumps({"Response": {"Content": zip_b64, "ContentType": "application/zip"}})

        with mock.patch("syno_certsync.providers.tencent.http", fake_http):
            f = TencentFetcher({"secret_id": "sid", "secret_key": "skey"})
            certs = f.list_certs()
            self.assertEqual([c.cert_id for c in certs], ["c1"])  # pending cert skipped
            self.assertEqual(certs[0].not_before.isoformat(), "2026-09-01T08:00:00+08:00")
            f.download(certs[0])
            self.assertEqual(certs[0].cert_pem.strip(), LEAF.strip())
            self.assertEqual(certs[0].chain_pem.strip(), CA.strip())
            self.assertEqual(certs[0].key_pem, KEY)


class AwsTest(unittest.TestCase):
    def test_list_request_shape(self):
        seen = {}

        def fake_http(method, url, headers=None, data=None, timeout=30):
            seen["target"] = headers["x-amz-target"]
            seen["body"] = json.loads(data)
            self.assertIn("SignedHeaders=content-type;host;x-amz-date;x-amz-target", headers["Authorization"])
            return json.dumps({"CertificateSummaryList": [
                {"CertificateArn": "arn:x", "DomainName": "a.com", "IssuedAt": 1788220800,
                 "NotAfter": 1796000000, "SubjectAlternativeNameSummaries": ["a.com"]}]})

        with mock.patch("syno_certsync.providers.aws.http", fake_http):
            certs = AwsFetcher({"access_key_id": "k", "secret_access_key": "s"}).list_certs()
        self.assertEqual(seen["target"], "CertificateManager.ListCertificates")
        self.assertEqual(seen["body"]["Includes"]["exportOption"], "ENABLED")
        self.assertIn("EC_prime256v1", seen["body"]["Includes"]["keyTypes"])
        self.assertEqual(certs[0].domain, "a.com")


if __name__ == "__main__":
    unittest.main()
