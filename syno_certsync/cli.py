import argparse
import configparser
import os
import sys

from . import __version__
from .util import resolve_range, filter_certs, write_cert, dedupe_latest
from .providers import FETCHERS, ACME_PROVIDERS
from . import acme, synology

DEFAULT_CONF = os.environ.get("CERTSYNC_CONF", os.path.expanduser("~/.certsync/config.ini"))
DEFAULT_OUT = os.environ.get("CERTSYNC_OUT", os.path.expanduser("~/.certsync/certs"))


def load_conf(path):
    cp = configparser.ConfigParser(interpolation=None)  # secrets may contain '%'
    if os.path.exists(path):
        try:
            if os.stat(path).st_mode & 0o077:
                print("warning: %s is readable by other users; run chmod 600 on it" % path, file=sys.stderr)
        except OSError:
            pass
        cp.read(path)
    return cp


def add_range_args(p):
    p.add_argument("--since", help="start time, e.g. 2026-09-01 or 2026-09-01T00:00:00")
    p.add_argument("--until", help="end time (default: open-ended)")
    p.add_argument("--days", type=int, help="shortcut for --since now-N days (ignored if --since given)")
    p.add_argument("--by", choices=["issued", "expires"], default="issued",
                   help="which timestamp the range applies to (default: issued)")
    p.add_argument("--include-expired", action="store_true", help="do not drop expired certs")


def add_syno_args(p):
    p.add_argument("--syno-desc", help="Synology cert description to replace (default: match by domain)")
    p.add_argument("--syno-default", action="store_true", help="make the cert the DSM default")
    p.add_argument("--dry-run", action="store_true")


def fetch_certs(args, cp):
    section = args.provider
    if section not in FETCHERS:
        sys.exit("provider '%s' cannot fetch issued certs; use 'issue' (ACME). Fetchable: %s"
                 % (section, ", ".join(sorted(FETCHERS))))
    conf = dict(cp[section]) if cp.has_section(section) else {}
    since, until = resolve_range(args.since, args.until, args.days)
    fetcher = FETCHERS[section](conf)
    certs = fetcher.list_certs()
    certs = filter_certs(certs, since, until, args.by, args.domain, not args.include_expired)
    certs = dedupe_latest(certs)
    ok = []
    args.failed = False
    for c in certs:
        try:
            fetcher.download(c)
            ok.append(c)
        except RuntimeError as e:  # one bad cert must not block the others
            print("ERROR downloading %s (%s): %s" % (c.domain, c.cert_id, e), file=sys.stderr)
            args.failed = True
    return ok


def cmd_list(args, cp):
    since, until = resolve_range(args.since, args.until, args.days)
    conf = dict(cp[args.provider]) if cp.has_section(args.provider) else {}
    certs = FETCHERS[args.provider](conf).list_certs()
    for c in filter_certs(certs, since, until, args.by, args.domain, not args.include_expired):
        print("%s\t%s\t%s\t%s" % (c.cert_id, c.domain, c.not_before, c.not_after))


def cmd_fetch(args, cp):
    certs = fetch_certs(args, cp)
    for c in certs:
        print("saved", write_cert(c, args.out))
    if not certs and not args.failed:
        print("no certificate matched the time range")
    return 1 if args.failed else 0


def cmd_sync(args, cp):
    certs = fetch_certs(args, cp)
    if not certs and not args.failed:
        print("no certificate matched the time range")
    changed, failed = False, args.failed
    for c in certs:
        d = write_cert(c, args.out)
        try:
            changed |= synology.deploy(d, c.domain, args.syno_desc, args.syno_default, args.dry_run)
        except synology.DeployError as e:  # keep going with the other certs
            print("ERROR deploying %s: %s" % (c.domain, e), file=sys.stderr)
            failed = True
    if changed:
        synology.reload_services(args.dry_run)
    return 1 if failed else 0


def cmd_issue(args, cp):
    conf = dict(cp[args.provider]) if cp.has_section(args.provider) else {}
    d = acme.issue(args.provider, args.domain, conf, args.out, args.ca, args.email)
    if args.deploy:
        if synology.deploy(d, args.domain[0], args.syno_desc, args.syno_default, args.dry_run):
            synology.reload_services(args.dry_run)


def cmd_deploy(args, cp):
    if synology.deploy(args.dir, args.domain, args.syno_desc, args.syno_default, args.dry_run):
        synology.reload_services(args.dry_run)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="certsync", description="Fetch/issue certs from cloud providers and deploy to Synology DSM")
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("-c", "--config", default=DEFAULT_CONF)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def prov(p, choices):
        p.add_argument("--provider", required=True, choices=sorted(choices))

    p = sub.add_parser("list", help="list certs in a time range")
    prov(p, FETCHERS); add_range_args(p); p.add_argument("--domain")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("fetch", help="download certs in a time range")
    prov(p, FETCHERS); add_range_args(p); p.add_argument("--domain")
    p.add_argument("--out", default=DEFAULT_OUT)
    p.set_defaults(fn=cmd_fetch)

    p = sub.add_parser("sync", help="fetch + deploy to local Synology")
    prov(p, FETCHERS); add_range_args(p); add_syno_args(p); p.add_argument("--domain")
    p.add_argument("--out", default=DEFAULT_OUT)
    p.set_defaults(fn=cmd_sync)

    p = sub.add_parser("issue", help="issue via ACME (DNS-01, uses acme.sh as engine)")
    prov(p, ACME_PROVIDERS); add_syno_args(p)
    p.add_argument("-d", "--domain", action="append", required=True)
    p.add_argument("--ca", default="letsencrypt")
    p.add_argument("--email")
    p.add_argument("--deploy", action="store_true")
    p.add_argument("--out", default=DEFAULT_OUT)
    p.set_defaults(fn=cmd_issue)

    p = sub.add_parser("deploy", help="deploy an existing cert dir to local Synology")
    p.add_argument("--dir", required=True, help="dir containing cert.pem/fullchain.pem/privkey.pem")
    p.add_argument("--domain", required=True)
    add_syno_args(p)
    p.set_defaults(fn=cmd_deploy)

    args = ap.parse_args(argv)
    try:
        return args.fn(args, load_conf(args.config)) or 0
    except (synology.DeployError, RuntimeError, ValueError) as e:  # ValueError: bad --since/--until
        print("error: %s" % e, file=sys.stderr)
        return 1
