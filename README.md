# LTIsland Insight — 信號存證帳本

Verifiable commitment ledger for stock signals produced by the LTIsland
Insight screening pipeline. Purpose: prove a signal existed at a given time,
before its outcome was known, without revealing the proprietary scoring
logic or parameters that produced it.

## How it works

Two-stage commit/reveal scheme:

1. **Commit** (`ingest/commits/YYYY-MM-DD.json`) — published the same day
   the signals are produced. Contains **zero plaintext**: only the day's
   signal count, a list of per-signal SHA-256 hashes, and a Merkle root over
   those hashes. Each hash commits to `{code, type, layer, direction,
   signal_time, signal_close, nonce}` for one signal — the nonce (32 random
   bytes, independently generated per signal) means the hash can't be
   brute-forced even though the space of possible stock codes is small.

2. **Reveal** (`ingest/reveals/YYYY-MM-DD.json`) — published once a signal's
   tracking window has matured past its exit-rule ceiling (so the signal is
   guaranteed to already be closed/invalidated — nothing here can still be an
   open, exploitable position). Contains the full plaintext record plus its
   forward return, letting anyone recompute the hash and confirm it matches
   what was committed on day one.

**Never published, at either stage:** scoring values, screening thresholds,
stop-loss/take-profit levels — anything that would reveal the underlying
strategy logic. The commitment only ever proves *that a signal existed*, not
*why it was generated*.

## What actually proves the timing

The `committed_at` field inside each commit file is **self-reported** —
generated locally before the file is ever pushed, so it proves nothing on
its own (a local clock is trivially adjustable). The only externally
checkable anchor is **when GitHub's servers actually received the push** —
visible via the commit's presence in this repo's public history and
GitHub's own commit/API metadata, which the publisher does not control.
Treat `committed_at` as informational only; treat the push (and the fact
that this repo is public and cloneable by anyone from that point on) as the
actual timestamp. This is also why the publish step is expected to run the
same evening the signals are generated, not the next day — the gap between
"signals produced" and "push received by GitHub" is exactly the window
where a self-serving publisher *could* cherry-pick, so it's kept as short as
possible by process, not by any property of the hash scheme itself.

## Verifying it yourself

```
python3 verify.py 2026-07-10
```

Pure stdlib, no dependency on this repo's producer (Hermes, private). Checks:
- the published Merkle root matches a recomputation from the committed hash list
- every revealed record's recomputed hash matches both its own commit-time hash and appears in that date's committed hash set

## Status

Early stage — first real commitment expected 2026-07-13 (Monday close,
JST/CST). Until then this repo may contain only scaffolding.
