"""Deploy logic against a fake DSM certificate tree (uses the real openssl binary)."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from syno_certsync import synology as s


def gen(d, cn):
    os.makedirs(d, exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                    "-subj", "/CN=" + cn, "-addext", "subjectAltName=DNS:" + cn,
                    "-keyout", d + "/privkey.pem", "-out", d + "/cert.pem"], capture_output=True, check=True)
    shutil.copy(d + "/cert.pem", d + "/fullchain.pem")


@unittest.skipUnless(shutil.which("openssl"), "openssl required")
class DeployTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.arch = self.t + "/_archive"
        gen(self.arch + "/abc123", "example.com")
        self.svc = self.t + "/system/default"
        os.makedirs(self.svc)
        os.makedirs(self.t + "/ReverseProxy/u1")
        json.dump({"abc123": {"desc": "mine", "services": [
            {"subscriber": "ReverseProxy", "service": "u1", "isPkg": False}]}}, open(self.arch + "/INFO", "w"))
        open(self.arch + "/DEFAULT", "w").write("abc123")
        self.patches = [mock.patch.object(s, "ARCHIVE", self.arch), mock.patch.object(s, "SVC_DIR", self.t),
                        mock.patch("os.geteuid", return_value=0, create=True)]
        for p in self.patches:
            p.start()
        self.src = self.t + "/new"
        gen(self.src, "example.com")

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.t, ignore_errors=True)

    def read(self, p):
        return open(p).read()

    def test_deploy_updates_slot_services_and_default(self):
        self.assertTrue(s.deploy(self.src, "example.com"))
        want = self.read(self.src + "/cert.pem")
        for d in (self.arch + "/abc123", self.t + "/ReverseProxy/u1", self.svc):
            self.assertEqual(self.read(d + "/cert.pem"), want, d)

    def test_existing_file_mode_is_preserved(self):
        os.chmod(self.arch + "/abc123/privkey.pem", 0o640)
        s.deploy(self.src, "example.com")
        import stat
        self.assertEqual(stat.S_IMODE(os.stat(self.arch + "/abc123/privkey.pem").st_mode), 0o640)
        self.assertFalse(os.path.exists(self.arch + "/abc123/privkey.pem.tmp"))

    def test_idempotent(self):
        s.deploy(self.src, "example.com")
        self.assertFalse(s.deploy(self.src, "example.com"))

    def test_mismatched_key_refused(self):
        bad = self.t + "/bad"
        gen(bad, "example.com")
        shutil.copy(self.src + "/privkey.pem", bad + "/privkey.pem")
        with self.assertRaises(s.DeployError):
            s.deploy(bad, "example.com")

    def test_unknown_domain(self):
        with self.assertRaises(s.DeployError):
            s.deploy(self.src, "other.org")

    def test_dry_run_changes_nothing(self):
        before = self.read(self.arch + "/abc123/cert.pem")
        self.assertTrue(s.deploy(self.src, "example.com", dry_run=True))
        self.assertEqual(self.read(self.arch + "/abc123/cert.pem"), before)


if __name__ == "__main__":
    unittest.main()
