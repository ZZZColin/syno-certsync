import configparser
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone

from syno_certsync.util import (Cert, parse_time, filter_certs, resolve_range, domain_match,
                                dedupe_latest, write_cert, CN_TZ)

UTC = timezone.utc


def mk(domain, nb, na):
    return Cert("t", domain, domain, parse_time(nb), parse_time(na))


class T(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_time("2026-09-01"), datetime(2026, 9, 1, tzinfo=UTC))
        self.assertEqual(parse_time(1788220800000), parse_time(1788220800))
        self.assertEqual(parse_time("2026-09-01 10:00:00").hour, 10)

    def test_naive_cn_timezone(self):
        # 2026-09-01 08:00 Beijing == 2026-09-01 00:00 UTC
        self.assertEqual(parse_time("2026-09-01 08:00:00", CN_TZ), datetime(2026, 9, 1, tzinfo=UTC))

    def test_filter(self):
        certs = [mk("a.com", "2026-09-05", "2099-01-01"), mk("b.com", "2026-01-01", "2099-01-01"),
                 mk("c.com", "2026-09-06", "2026-01-01")]
        s, u = resolve_range("2026-09-01", "2026-10-01", None)
        self.assertEqual([c.domain for c in filter_certs(certs, s, u)], ["a.com"])
        self.assertEqual([c.domain for c in filter_certs(certs, s, u, valid_only=False)], ["a.com", "c.com"])

    def test_expires_without_until_is_not_cut_at_now(self):
        certs = [mk("a.com", "2026-01-01", "2099-01-01")]
        s, u = resolve_range("2026-01-01", None, None)
        self.assertEqual(len(filter_certs(certs, s, u, field_name="expires")), 1)

    def test_domain(self):
        self.assertTrue(domain_match("x.a.com", "*.a.com"))
        self.assertFalse(domain_match("a.com", "*.a.com"))
        self.assertFalse(domain_match("x.y.a.com", "*.a.com"))
        self.assertTrue(domain_match("a.com", "b.com, a.com"))

    def test_dedupe_latest(self):
        old, new = mk("a.com", "2026-01-01", "2099-01-01"), mk("a.com", "2026-09-01", "2099-01-01")
        self.assertIs(dedupe_latest([old, new])[0], new)
        self.assertIs(dedupe_latest([new, old])[0], new)

    def test_key_file_mode(self):
        c = mk("a.com", "2026-01-01", "2099-01-01")
        c.cert_pem, c.key_pem = "CERT\n", "KEY\n"
        with tempfile.TemporaryDirectory() as d:
            p = write_cert(c, d)
            mode = stat.S_IMODE(os.stat(os.path.join(p, "privkey.pem")).st_mode)
            self.assertEqual(mode, 0o600)

    def test_bundle_split(self):
        leaf = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"
        ca = "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----"
        c = mk("a.com", "2026-01-01", "2099-01-01")
        c.cert_pem = leaf + "\n" + ca + "\n"
        c.normalize()
        self.assertEqual(c.cert_pem.strip(), leaf)
        self.assertEqual(c.chain_pem.strip(), ca)
        self.assertEqual(c.fullchain_pem.count("BEGIN CERTIFICATE"), 2)

    def test_config_percent_in_secret(self):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_string("[a]\nk = ab%cd\n")
        self.assertEqual(cp["a"]["k"], "ab%cd")


if __name__ == "__main__":
    unittest.main()
