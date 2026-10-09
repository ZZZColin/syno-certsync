"""Replace a certificate on the local Synology DSM (run as root on the NAS).

Strategy: locate an existing cert slot in /usr/syno/etc/certificate/_archive (by DSM
description or by matching domain), overwrite its PEM files, copy them to every service
that subscribes to it, then reload nginx. Import the cert once through the DSM UI first
so the slot exists and services are assigned.
"""
import json
import os
import re
import shutil
import stat
import subprocess

from .util import domain_match

ARCHIVE = "/usr/syno/etc/certificate/_archive"
SVC_DIR = "/usr/syno/etc/certificate"
PKG_DIR = "/usr/local/etc/certificate"
FILES = ["cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"]
REQUIRED = ["cert.pem", "fullchain.pem", "privkey.pem"]


class DeployError(Exception):
    pass


def _info():
    with open(os.path.join(ARCHIVE, "INFO")) as f:
        return json.load(f)


def _openssl(args, stdin=None):
    try:
        p = subprocess.run(["openssl"] + args, capture_output=True, text=True, input=stdin)
    except FileNotFoundError:
        return None
    return p.stdout if p.returncode == 0 else None


def _cert_domains(path):
    out = _openssl(["x509", "-in", path, "-noout", "-subject", "-ext", "subjectAltName"]) or ""
    return re.findall(r"(?:CN\s*=\s*|DNS:)([^,\s]+)", out)


def key_matches_cert(cert_path, key_path):
    """True if the private key belongs to the cert. If openssl is unavailable, skip the check."""
    a = _openssl(["x509", "-in", cert_path, "-noout", "-pubkey"])
    b = _openssl(["pkey", "-in", key_path, "-pubout"])
    if a is None and b is None:
        return True
    return a is not None and a == b


def find_slot(domain, desc=None):
    info = _info()
    if desc:
        for cid, meta in info.items():
            if meta.get("desc") == desc:
                return cid
        raise DeployError("no Synology certificate with description %r" % desc)
    for cid in info:
        names = _cert_domains(os.path.join(ARCHIVE, cid, "cert.pem"))
        if any(domain_match(domain, n) or domain_match(n, domain) for n in names):
            return cid
    raise DeployError("no Synology cert slot matches %s. Import it once via DSM (Control Panel > Security > "
                      "Certificate) or pass --syno-desc." % domain)


def _read(p):
    try:
        with open(p, "rb") as f:
            return f.read()
    except OSError:
        return None


def _atomic_copy(src, dst, default_mode):
    """Replace dst atomically. An existing file keeps its mode and owner, because some DSM
    services run as non-root users and must still be able to read their key."""
    tmp = dst + ".tmp"
    mode, owner = default_mode, None
    try:
        st = os.stat(dst)
        mode, owner = stat.S_IMODE(st.st_mode), (st.st_uid, st.st_gid)
    except OSError:
        pass
    try:
        shutil.copyfile(src, tmp)
        os.chmod(tmp, mode)
        if owner:
            os.chown(tmp, *owner)
        os.replace(tmp, dst)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def deploy(src_dir, domain, desc=None, make_default=False, dry_run=False):
    """Returns True if anything on the NAS changed (so the caller knows to reload)."""
    for name in REQUIRED:
        if not os.path.exists(os.path.join(src_dir, name)):
            raise DeployError("%s missing in %s" % (name, src_dir))
    if not key_matches_cert(os.path.join(src_dir, "cert.pem"), os.path.join(src_dir, "privkey.pem")):
        raise DeployError("private key does not match certificate in %s; refusing to deploy" % src_dir)
    if not dry_run and os.geteuid() != 0:
        raise DeployError("must run as root on the Synology")
    cid = find_slot(domain, desc)
    info = _info()
    print("target slot:", cid, info[cid].get("desc", ""))
    targets = [os.path.join(ARCHIVE, cid)]
    for s in info[cid].get("services", []):
        if not (s.get("subscriber") and s.get("service")):
            continue
        base = PKG_DIR if s.get("isPkg") else SVC_DIR
        d = os.path.join(base, s["subscriber"], s["service"])
        if os.path.isdir(d):
            targets.append(d)
    # The default cert also lives in system/default (+ FQDN) which DSM 7 itself uses.
    is_default = (_read(os.path.join(ARCHIVE, "DEFAULT")) or b"").decode().strip() == cid or make_default
    if is_default:
        for sub in ("system/default", "system/FQDN"):
            d = os.path.join(SVC_DIR, sub)
            if os.path.isdir(d) and d not in targets:
                targets.append(d)
    changed = False
    for t in targets:
        for name in FILES:
            src = os.path.join(src_dir, name)
            dst = os.path.join(t, name)
            if not os.path.exists(src) or os.path.getsize(src) == 0:
                continue  # e.g. empty chain.pem: do not clobber the NAS copy
            if _read(src) == _read(dst):
                continue
            changed = True
            print("  update", dst)
            if not dry_run:
                _atomic_copy(src, dst, 0o600 if name == "privkey.pem" else 0o644)
    if not changed:
        print("  already up to date")
    if make_default:
        p = os.path.join(ARCHIVE, "DEFAULT")
        if (_read(p) or b"").decode().strip() != cid:
            changed = True
            print("  set default ->", cid)
            if not dry_run:
                with open(p, "w") as f:
                    f.write(cid)
    return changed


def reload_services(dry_run=False):
    # In Docker (privileged + pid: host) run the host's own tool via nsenter into PID 1's namespaces.
    # DSM 7: regenerate nginx config (synow3tool) then restart; DSM 6: synoservicectl --reload.
    script = ("if [ -x /usr/syno/bin/synosystemctl ]; then "
              "[ -x /usr/syno/bin/synow3tool ] && /usr/syno/bin/synow3tool --gen-all; "
              "/usr/syno/bin/synosystemctl restart nginx; "
              "else /usr/syno/sbin/synoservicectl --reload nginx; fi")
    if os.environ.get("CERTSYNC_NSENTER") == "1":
        c = ["nsenter", "-t", "1", "-m", "-u", "-n", "-i", "/bin/sh", "-c", script]
    else:
        c = ["/bin/sh", "-c", script]
    print("run:", " ".join(c))
    if not dry_run:
        rc = subprocess.run(c).returncode
        if rc != 0:
            raise DeployError("nginx reload failed (rc=%d)" % rc)
    # Packages that read the certificate (e.g. ftp, mail) pick it up on their own restart.
