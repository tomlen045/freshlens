# freshlens — Baseline-free File Anomaly Lens

**What files changed on this box recently — and do any of them look like an intruder?**

No aide, no trusted-baseline database, no full-disk hashing. freshlens scans once with
a time window and file-shape heuristics, and answers the first question you should ask
during incident response: **among recently touched files, which ones look wrong.**

简体中文 | [English](README_EN.md)

```
$ python3 freshlens.py --demo
[P0 FJ-01]  /tmp/freshlens-demo/tmpd/kworker
        Freshly dropped executable in a transient dir (2.0h ago)
[P0 FJ-02]  /tmp/freshlens-demo/tmpd/sshd
        Executable masquerading as system service "sshd" outside system dirs
[P1 FJ-04]  /tmp/freshlens-demo/www/uploads/cache.php
        Fresh 0KB .php script under webroot (classic webshell shape)
判决统计: P0=4  P1=1  P2=0  →  exit 3
[demo] planted 3/3 hit, clean files 0 false-positive: YES
```

## Why "baseline-free"

Baseline tools (aide/tripwire) share one precondition: **you need a clean machine first,
build the database, then wait for someone to touch it.** Reality is usually reversed —
an alert fires and you land on a server nobody ever baselined. All you have is *now*.
freshlens is built for that moment:

| | aide/tripwire style | freshlens |
|---|---|---|
| Precondition | clean machine + baseline DB | none, scan immediately |
| Question answered | "who changed a known state?" | "which recent changes look hostile?" |
| Cost | full-hash, DB grows with disk | stat metadata only, minutes |
| First useful run | after baseline build | immediately |
| DB | must be guarded (tamperable) | no DB to tamper with |

They complement each other: freshlens covers "the first moment, when no baseline exists",
baseline tools cover "long-term controlled environments". For durable auditing use
auditd — freshlens is **zero-deployment first-layer visibility**.

## Install

Single file, stdlib-only, Python 3.8+:

```bash
curl -O https://raw.githubusercontent.com/tomlen045/freshlens/main/freshlens.py
chmod +x freshlens.py
python3 freshlens.py --version   # freshlens 1.0.1
python3 freshlens.py --demo      # 60-second tour of what it catches
```

## Usage

```bash
python3 freshlens.py                    # OS-aware default sensitive roots, 24h window
python3 freshlens.py --since 72         # widen the window to 72h
python3 freshlens.py /data/www /app     # scan given roots only (replaces defaults)
python3 freshlens.py --ignore .DS_Store # noise filter (a filter, not a baseline)
python3 freshlens.py --json             # machine-readable, for cron/webhooks
python3 freshlens.py --quiet            # verdict lines only
python3 freshlens.py --no-color         # no ANSI colors
python3 freshlens.py --demo             # built-in sandbox demo
```

Works on Linux and macOS. Exit codes: `0` clean / `1` P2 only / `2` has P1 / `3` has P0.

Cron wiring:

```cron
17 * * * * python3 /opt/freshlens.py --quiet --json >> /var/log/freshlens.jsonl
```

## 12 verdicts (FJ-01 ~ FJ-12)

| ID | Sev | Verdict |
|---|---|---|
| FJ-01 | P0 | fresh executable dropped in transient dir (/tmp, /dev/shm…) |
| FJ-02 | P0 | executable masquerading as a system service name outside system dirs |
| FJ-05 | P0/P2 | fresh file under sensitive dirs (etc…); world-writable escalates to P0 |
| FJ-10 | P0 | /etc/ld.so.preload present with content (LD_PRELOAD poisoning staple) |
| FJ-11 | P0 | SUID binary created/modified inside the window |
| FJ-03 | P1 | fresh executable inside a hidden dir (normal dot-dirs exempted) |
| FJ-04 | P1 | fresh small .php/.jsp/.asp under webroot (webshell shape) |
| FJ-07 | P1 | authorized_keys modified inside the window |
| FJ-08 | P1 | new job file in cron.d/cron.hourly/spool/LaunchDaemon dirs |
| FJ-09 | P1 | batch landing in one dir (≥10 fresh files, or ≥5 fresh dotfiles) |
| FJ-06 | P2 | non-log-suffix fresh file inside log dirs |
| FJ-12 | P2 | executable squatting in a transient dir, never cleaned |

## Design boundaries (read first)

- **Read-only**: os.scandir/os.stat only — never writes, deletes, or touches scanned objects
- **mtime is spoofable**: physical limit of baseline-free mode (`touch -r`). For real
  anti-tamper use auditd/inotify. freshlens catches "the majority that doesn't bother
  hiding": cryptominers, batch droppers, webshells, accidental deploys
- **`--since 0` is smoke mode**: walks the scan path, emits no verdicts
- **Heuristics are triage, not forensics**: verdicts rank what to look at first

## Self-test

```bash
python3 selftest.py
# TOTAL 21 | PASS 21 | FAIL 0 — ALL GREEN
```

## The Sentry Suite

[**porteye**](https://github.com/tomlen045/porteye) listens →
[**suidhunt**](https://github.com/tomlen045/suidhunt) escalates →
[**authguard**](https://github.com/tomlen045/authguard) guards the door →
[**callhome**](https://github.com/tomlen045/callhome) watches phone-homes →
**freshlens watches what files got touched** — the landing surface, fifth of five.

## License

MIT
