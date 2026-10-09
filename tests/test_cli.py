"""End-to-end CLI runs: fake cloud provider + fake DSM certificate tree."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from syno_certsync import cli, synology
from syno_certsync.util import Cert

UTC = timezone.utc


def make_pair(cn):
    d = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                    "-subj", "/CN=" + cn, "-addext", "subjectAltName=DNS:" + cn,
                    "-keyout", d + "/k.pem", "-out", d + "/c.pem"], capture_output=True, check=True)
    c, k = open(d + "/c.pem").read(), open(d + "/k.pem").read()
    shutil.rmtree(d)
    return c, k


@unittest.skipUnless(shutil.which("openssl"), "openssl required")
class CliTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        arch = self.t + "/_archive"
        os.makedirs(arch + "/s1")
        os.makedirs(arch + "/s2")
        for cid, cn in (("s1", "a.com"), ("s2", "b.com")):
            c, k = make_pair(cn)
            open("%s/%s/cert.pem" % (arch, cid), "w").write(c)
        json.dump({"s1": {"desc": "a", "services": []}, "s2": {"desc": "b", "services": []}},
                  open(arch + "/INFO", "w"))
        self.arch = arch
        now = datetime.now(UTC)
        self.certs = {}
        for cn in ("a.com", "b.com"):
            c, k = make_pair(cn)
            self.certs[cn] = Cert("fake", "id-" + cn, cn, now - timedelta(days=1), now + timedelta(days=60),
                                  cert_pem=c, key_pem=k)
        self.fail_domains = set()
        outer = self

        class Fake:
            def __init__(self, conf):
                pass

            def list_certs(self):
                return [Cert("fake", c.cert_id, c.domain, c.not_before, c.not_after)
                        for c in outer.certs.values()]

            def download(self, cert):
                if cert.domain in outer.fail_domains:
                    raise RuntimeError("boom")
                src = outer.certs[cert.domain]
                cert.cert_pem, cert.key_pem = src.cert_pem, src.key_pem

        self.patches = [
            mock.patch.dict(cli.FETCHERS, {"aliyun": Fake}),
            mock.patch.object(synology, "ARCHIVE", arch),
            mock.patch.object(synology, "SVC_DIR", self.t),
            mock.patch("os.geteuid", return_value=0, create=True),
        ]
        for p in self.patches:
            p.start()
        self.conf = self.t + "/config.ini"
        open(self.conf, "w").write("[aliyun]\naccess_key_id = x\naccess_key_secret = p%ss\n")

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.t, ignore_errors=True)

    def run_cli(self, *args):
        extra = ["--out", self.t + "/out"] if args[0] in ("sync", "fetch") else []
        return cli.main(["-c", self.conf] + list(args) + extra)

    def test_sync_deploys_all_and_reloads_once(self):
        with mock.patch.object(synology, "reload_services") as rl:
            self.assertEqual(self.run_cli("sync", "--provider", "aliyun", "--days", "2"), 0)
            self.assertEqual(rl.call_count, 1)
            self.assertEqual(open(self.arch + "/s1/cert.pem").read(), self.certs["a.com"].cert_pem)
            self.assertEqual(open(self.arch + "/s2/cert.pem").read(), self.certs["b.com"].cert_pem)
            # second run: nothing changed, no reload
            self.assertEqual(self.run_cli("sync", "--provider", "aliyun", "--days", "2"), 0)
            self.assertEqual(rl.call_count, 1)

    def test_domain_filter_and_time_window(self):
        with mock.patch.object(synology, "reload_services"):
            self.run_cli("sync", "--provider", "aliyun", "--days", "2", "--domain", "a.com")
            self.assertEqual(open(self.arch + "/s1/cert.pem").read(), self.certs["a.com"].cert_pem)
            self.assertNotEqual(open(self.arch + "/s2/cert.pem").read(), self.certs["b.com"].cert_pem)
        # window that excludes the certs (issued 1 day ago, ask for the last 0 days minus)
        with mock.patch.object(synology, "reload_services") as rl:
            old = self.certs["b.com"]
            old.not_before = datetime.now(UTC) - timedelta(days=30)
            self.run_cli("sync", "--provider", "aliyun", "--days", "2", "--domain", "b.com")
            self.assertEqual(rl.call_count, 0)

    def test_one_failed_download_does_not_block_others(self):
        self.fail_domains = {"a.com"}
        with mock.patch.object(synology, "reload_services") as rl:
            rc = self.run_cli("sync", "--provider", "aliyun", "--days", "2")
        self.assertEqual(rc, 1)
        self.assertEqual(rl.call_count, 1)
        self.assertEqual(open(self.arch + "/s2/cert.pem").read(), self.certs["b.com"].cert_pem)

    def test_bad_date_is_a_clean_error(self):
        self.assertEqual(self.run_cli("list", "--provider", "aliyun", "--since", "nope"), 1)

    def test_expires_window(self):
        with mock.patch.object(synology, "reload_services"):
            rc = self.run_cli("fetch", "--provider", "aliyun", "--by", "expires",
                              "--since", (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%d"))
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(self.t + "/out/a.com/privkey.pem"))


if __name__ == "__main__":
    unittest.main()
