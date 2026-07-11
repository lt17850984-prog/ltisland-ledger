#!/usr/bin/env python3
"""Standalone verifier for the LTIsland signal commitment ledger.

No dependency on the Hermes private repo — pure Python stdlib. Anyone can
run this against the JSON files in ingest/commits/ and ingest/reveals/ to
independently confirm that revealed signals match what was committed
beforehand, and that no committed signal in a date's set is missing from
the merkle root.

Usage:
  python3 verify.py 2026-07-10
"""
import hashlib
import json
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


def verify(date_str):
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
    if len(sys.argv) != 2:
        print("usage: python3 verify.py YYYY-MM-DD")
        sys.exit(1)
    verify(sys.argv[1])
