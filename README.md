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

**Added 2026-07-14 — independent RFC3161 timestamp.** Alongside the
self-reported `committed_at`, each day's `merkle_root` is also submitted to
a public RFC3161 Time-Stamp Authority (DigiCert primary, Sectigo backup —
**not** freetsa.org: it's flagged "not credible" on the community-maintained
public-TSA list and its CA isn't in any default OS trust store, which would
have meant bundling a special CA file in this repo just to verify it —
DigiCert/Sectigo are standard publicly-trusted CAs, so any machine's normal
CA bundle verifies the token without anything extra) at the moment the root
is computed — the same day signals are produced, before the evening push.
The response (`ingest/commits/<date>.tsr`) plus its paired query file
(`ingest/commits/<date>.tsr.tsq` — RFC3161 verification checks a nonce
matching the two, so they must be kept together; a `.tsr` alone cannot be
re-verified) are published alongside the commit JSON.

This does **not** replace the GitHub-push anchor above — it's an additional,
independent one, cross-checkable against a source Hermes itself doesn't
control (a public CA-backed TSA) rather than only against GitHub. If the TSA
request fails (network issue, TSA outage — it's retried twice against
DigiCert then twice against Sectigo before giving up), that day's commit
JSON simply has `"tsa_status": "failed"` and no `.tsr`/`.tsq` files. That's a
disclosed gap, not a bug — a missing token doesn't invalidate the hash
commitment itself, which stands on its own math regardless.

## Verifying it yourself

```
python3 verify.py 2026-07-10
```

Pure stdlib for the hash/Merkle checks, no dependency on this repo's
producer (Hermes, private). Checks:
- the published Merkle root matches a recomputation from the committed hash list
- every revealed record's recomputed hash matches both its own commit-time hash and appears in that date's committed hash set
- **if that date has an RFC3161 token** (`ingest/commits/<date>.tsr` + `.tsr.tsq`): shells out to the system `openssl` binary (`openssl ts -verify`) to confirm it's a valid timestamp response, signed by a publicly-trusted CA, covering exactly that day's `merkle_root`. This is the one external dependency this script has — verifying a cryptographic timestamp requires a certificate-chain-aware tool that Python's stdlib doesn't provide on its own. Install it if you don't have it (`brew install openssl` / `apt install openssl` / etc. — it's on most systems already). If your machine's CA bundle isn't at one of the common paths the script checks, pass `--ca-bundle /path/to/bundle.pem` explicitly. Dates with `tsa_status: "failed"` in their commit JSON won't have a token to check — the script reports that as an expected gap, not a failure.

## Status

Early stage — first real commitment expected 2026-07-13 (Monday close,
JST/CST). Until then this repo may contain only scaffolding.
