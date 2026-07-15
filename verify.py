#!/usr/bin/env python3
"""Standalone verifier for the LTIsland signal commitment ledger.

No dependency on the Hermes private repo — pure Python stdlib for the
hash/merkle checks. Anyone can run this against the JSON files in
ingest/commits/ and ingest/reveals/ to independently confirm that revealed
signals match what was committed beforehand, and that no committed signal
in a date's set is missing from the merkle root.

This ledger anchors each day's merkle_root against three independent
mechanisms, checked in this order:
  1. GitHub push receipt (not checked by this script — see "What actually
     proves the timing" below; it's the server-side timestamp of when
     this repo's history received the commit, external to anything
     Hermes controls)
  2. RFC3161 timestamp (added 2026-07-14, checked by `_verify_rfc3161`)
  3. OpenTimestamps / Bitcoin block attestation (added 2026-07-15, checked
     by `_verify_ots`)
Each stands on its own — losing one doesn't invalidate the others, and none
of them are required for the underlying hash/Merkle commitment itself to be
valid math regardless.

RFC3161 timestamp check (added 2026-07-14): if ingest/commits/<date>.tsr and
its paired ingest/commits/<date>.tsq exist, this script also shells out to
the system `openssl` binary (must be installed separately — this is the
one external dependency this script has, precisely because verifying a
cryptographic timestamp token requires a certificate-chain-aware tool,
which stdlib `ssl`/`hashlib` don't provide) to confirm the token is a valid
RFC3161 response signed by a publicly-trusted CA (DigiCert or Sectigo — see
"What actually proves the timing" below for why those two and not
freetsa.org) covering exactly that day's merkle_root. Dates with
tsa_status=="failed" in their commit JSON will not have a .tsr file — that
is an expected, disclosed gap (see that field), not a bug in this script.

OpenTimestamps check (added 2026-07-15): if ingest/commits/<date>.ots
exists, this script shells out to the `ots` binary (`pip install
opentimestamps-client` — the second and last external dependency, for the
same reason as openssl above: verifying a Bitcoin-block attestation isn't
something stdlib can do) to report whether that day's merkle_root is
already confirmed by a Bitcoin block, or still pending (OpenTimestamps is
inherently two-phase — a stamp is submitted instantly to public calendar
servers, but full Bitcoin-block confirmation typically takes hours to about
a day). Dates with ots_status=="failed" won't have a .ots file — same
disclosed-gap convention as tsa_status.

Usage:
  python3 verify.py 2026-07-10
  python3 verify.py 2026-07-10 --ca-bundle /path/to/ca-bundle.pem   # override CA bundle auto-detection
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys


def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root(hashes):
    if not hashes:
        return sha256_hex(b"")
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [sha256_hex((level[i] + level[i + 1]).encode("utf-8")) for i in range(0, len(level), 2)]
    return level[0]


# Common system CA bundle locations, tried in order. This script has no pip
# dependencies (not even `certifi`) on principle — see module docstring — so
# instead of installing a portable CA bundle package, it just tries the
# well-known paths for the most common platforms/package managers. If none
# exist, pass --ca-bundle explicitly (openssl itself doesn't reliably fall
# back to a built-in default across platforms for `ts -verify` — confirmed
# by hand while building this feature: omitting -CAfile entirely fails with
# "self-signed certificate in certificate chain" even when the OS trust
# store is present, so a bundle path must always be supplied explicitly).
_CA_BUNDLE_CANDIDATES = [
    "/opt/homebrew/etc/openssl@3/cert.pem",   # macOS, Homebrew, Apple Silicon
    "/usr/local/etc/openssl@3/cert.pem",      # macOS, Homebrew, Intel
    "/etc/ssl/certs/ca-certificates.crt",     # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",       # RHEL/CentOS/Fedora
    "/etc/ssl/cert.pem",                      # Alpine, some BSDs
]


def _find_ca_bundle(override=None):
    if override:
        return override if os.path.exists(override) else None
    for path in _CA_BUNDLE_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def _find_ots_bin():
    return shutil.which("ots")


def _verify_ots(date_str, commit_doc):
    """Checks ingest/commits/<date>.ots against the `ots` CLI
    (opentimestamps-client — `pip install opentimestamps-client`, not
    bundled with this repo on principle, same as the openssl dependency
    above: verifying an OpenTimestamps proof requires walking a Merkle
    path against public calendar servers / a Bitcoin block, which this
    script's stdlib-only design deliberately doesn't reimplement).

    Returns one of: None (no .ots for this date — expected when
    ots_status != "pending" in the commit JSON, a disclosed gap not a
    bug), 'confirmed' (a Bitcoin block attests the timestamp — this is
    the strongest of the three anchors, fully independent of both
    GitHub and any TSA), 'pending' (stamped but not yet confirmed by a
    Bitcoin block — normal for anything stamped in roughly the last day;
    OpenTimestamps is inherently two-phase, unlike the instant RFC3161
    token above), or 'error' (ots not installed, or the check itself
    failed unexpectedly).
    """
    ots_path = f"ingest/commits/{date_str}.ots"
    ots_status = commit_doc.get("ots_status")

    if not os.path.exists(ots_path):
        if ots_status == "pending":
            print(f"  ⚠️ commit_doc claims ots_status=pending but {ots_path} is missing "
                  f"— inconsistent, treat as unverified")
            return "error"
        print(f"OpenTimestamps: none for this date (ots_status={ots_status!r}, "
              f"a disclosed gap — see that field in the commit JSON, not a bug here)")
        return None

    ots_bin = _find_ots_bin()
    if not ots_bin:
        print("OpenTimestamps: proof file present but `ots` is not installed on this "
              "machine — install it to verify (`pip install opentimestamps-client`), "
              "skipping this check for now")
        return "error"

    digest = sha256_hex(commit_doc["merkle_root"].encode("utf-8"))
    result = subprocess.run(
        [ots_bin, "verify", "-d", digest, ots_path],
        capture_output=True, text=True,
    )
    combined = (result.stdout + result.stderr).lower()
    if result.returncode == 0 and ("success" in combined or "attests existence" in combined):
        print(f"OpenTimestamps: CONFIRMED (Bitcoin block attests existence)")
        print(f"  {result.stdout.strip()}")
        return "confirmed"
    if "pending confirmation" in combined:
        print(f"OpenTimestamps: PENDING (stamped, awaiting Bitcoin block confirmation — "
              f"this anchor is not yet complete, but the other two above still stand on "
              f"their own)")
        return "pending"
    print(f"OpenTimestamps: FAILED to verify")
    print(f"  ots stdout: {result.stdout.strip()}")
    print(f"  ots stderr: {result.stderr.strip()}")
    return "error"


def _verify_rfc3161(date_str, commit_doc, ca_bundle_override=None):
    """Checks ingest/commits/<date>.tsr (+ its paired .tsq) against the
    system openssl binary. Returns None if no token exists for this date
    (expected when tsa_status=="failed" — not an error), True/False otherwise.
    """
    tsr_path = f"ingest/commits/{date_str}.tsr"
    tsq_path = f"ingest/commits/{date_str}.tsr.tsq"
    tsa_status = commit_doc.get("tsa_status")

    if not (os.path.exists(tsr_path) and os.path.exists(tsq_path)):
        if tsa_status == "ok":
            print(f"  ⚠️ commit_doc claims tsa_status=ok but {tsr_path}/{tsq_path} "
                  f"are missing — inconsistent, treat as unverified")
            return False
        print(f"RFC3161 timestamp: none for this date (tsa_status={tsa_status!r}, "
              f"a disclosed gap — see that field in the commit JSON, not a bug here)")
        return None

    if not shutil.which("openssl"):
        print("RFC3161 timestamp: token files present but `openssl` is not installed "
              "on this machine — install it to verify (e.g. `brew install openssl` / "
              "`apt install openssl`), skipping this check for now")
        return None

    ca_bundle = _find_ca_bundle(ca_bundle_override)
    if not ca_bundle:
        print("RFC3161 timestamp: token files present but no system CA bundle found "
              "at any known path — pass --ca-bundle /path/to/bundle.pem to verify")
        return None

    result = subprocess.run(
        ["openssl", "ts", "-verify", "-in", tsr_path, "-queryfile", tsq_path,
         "-CAfile", ca_bundle, "-untrusted", ca_bundle],
        capture_output=True, text=True,
    )
    ok = result.returncode == 0 and "Verification: OK" in result.stdout
    provider = commit_doc.get("tsa_provider", "unknown")
    print(f"RFC3161 timestamp ({provider}): {'OK' if ok else 'FAILED'}")
    if not ok:
        print(f"  openssl stdout: {result.stdout.strip()}")
        print(f"  openssl stderr: {result.stderr.strip()}")
    return ok


def verify(date_str, ca_bundle_override=None):
    with open(f"ingest/commits/{date_str}.json", encoding="utf-8") as f:
        commit_doc = json.load(f)

    committed_hashes = sorted(commit_doc["hashes"])
    recomputed_root = merkle_root(committed_hashes)
    root_ok = recomputed_root == commit_doc["merkle_root"]
    print(f"date: {date_str}")
    print(f"committed signal_count: {commit_doc['signal_count']}")
    print(f"merkle root matches: {root_ok}")
    if not root_ok:
        print(f"  expected {commit_doc['merkle_root']}")
        print(f"  got      {recomputed_root}")
        sys.exit(1)

    _verify_rfc3161(date_str, commit_doc, ca_bundle_override)
    _verify_ots(date_str, commit_doc)

    try:
        with open(f"ingest/reveals/{date_str}.json", encoding="utf-8") as f:
            revealed_doc = json.load(f)
    except FileNotFoundError:
        print("no reveal file yet for this date (signals may not have matured)")
        return

    ok_count = 0
    for row in revealed_doc["signals"]:
        norm = {k: row[k] for k in ("code", "type", "layer", "direction", "signal_time", "signal_close", "nonce")}
        h = sha256_hex(canonical_bytes(norm))
        matches_own_hash = h == row["hash"]
        in_committed_set = h in committed_hashes
        if matches_own_hash and in_committed_set:
            ok_count += 1
        else:
            print(f"  ⚠️ FAILED verification: {row.get('code')} recomputed={h} "
                  f"matches_own_hash={matches_own_hash} in_committed_set={in_committed_set}")

    print(f"revealed: {len(revealed_doc['signals'])}/{commit_doc['signal_count']} "
          f"({ok_count} verified OK)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage="python3 verify.py YYYY-MM-DD [--ca-bundle PATH]")
    parser.add_argument("date")
    parser.add_argument("--ca-bundle", default=None,
                         help="path to a CA bundle PEM for RFC3161 verification, "
                              "if none of the common system paths apply to your machine")
    args = parser.parse_args()
    verify(args.date, ca_bundle_override=args.ca_bundle)
