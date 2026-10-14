# egress-triage

**"This host doesn't work from my network" is not a diagnosis.**

A host that fails to load can fail at four different layers, and each one has a
different fix. Without knowing which layer, people spend days applying the
wrong one.

| layer | what you observe | what actually fixes it |
|---|---|---|
| **DNS** | the name resolves, to the wrong address | pin the real IP, or change resolver |
| **TCP** | the socket to `:443` never opens | a different egress (or a proxy) |
| **TLS** | TCP opens, then the handshake is reset | a different egress — pinning is useless |
| **application** | HTTP 401 / 403 / 429 | headers, cookies, a session |

`egress-triage` runs one experiment per host that separates them: **it makes the
same request twice — once through normal name resolution, once pinned to the
address an independent resolver returned.**

* pinned request succeeds → the layer that failed was **DNS**
* pinned request also times out → **TCP**
* pinned request turns a timeout into a reset → you just watched TCP succeed
  and **TLS** get killed
* an HTTP status comes back at all → it was never a network problem

This tool does **not** proxy, tunnel, or obfuscate anything. It sends two
requests and reports which layer answered.

## Install

Single file, Python 3.8+, standard library only. It shells out to `curl`, and
uses `dig` when present.

```bash
curl -O https://raw.githubusercontent.com/yff124/egress-triage/main/egress_triage.py
python3 egress_triage.py --selftest        # offline, no network
```

## Usage

```bash
python3 egress_triage.py example.com another.example
python3 egress_triage.py --file hosts.txt
python3 egress_triage.py --json example.com
python3 egress_triage.py --known-ip 104.17.176.98 example.com   # skip discovery
python3 egress_triage.py --resolver 1.1.1.1 example.com
python3 egress_triage.py --skip-dns example.com                 # faster, cannot separate DNS from TCP
python3 egress_triage.py --dump-raw example.com                 # print resolver bodies before parsing
```

Real output from a network where two hosts are interfered with:

```
[OK       ] dev.to          code=200  exit=ok
[TLS      ] gumroad.com     code=000  exit=operation-timeout  | pinned 104.17.176.98 -> 000 / ssl-connect-error  | DNS MISMATCH
[TLS      ] www.redbubble.com  code=000  exit=operation-timeout  | pinned 104.18.40.219 -> 000 / ssl-connect-error  | DNS MISMATCH
[NXDOMAIN ] no-such-host.example  code=000  exit=could-not-resolve-host
```

Read the second line carefully. Unpinned, that host looks like a plain TCP
timeout — the same signature as a firewall dropping packets. Pinned to the
address an independent resolver gave, TCP **connects** and the TLS handshake is
what gets reset (`ssl-connect-error`). Those are two different failures with two
different fixes. Reporting either one as "blocked" throws away the distinction.

## Verdicts

| verdict | meaning |
|---|---|
| `OK` | 2xx/3xx |
| `AUTH-WALL` | 401/403/429/451 — reachable, refusing automated clients |
| `DNS` | resolution was the failure; the true IP works |
| `NXDOMAIN` | no A record from any resolver we could reach |
| `TCP` | socket never opens, pinned or not |
| `TLS` | TCP connects, handshake is reset; pinning cannot help |
| `SERVER` | the site itself is erroring |
| `UNKNOWN` | inconclusive — retry with `--resolver` or `--known-ip` |

`DNS MISMATCH` is reported separately: your resolver's answer and the
independent answer have no address in common.

## Two failures worth knowing about, both found by using this

**1. The check that silently did nothing.**

The first version resolved real addresses from a plain-text DNS API whose output
looks like this:

```
A : 172.64.147.37
MX : 10 aspmx.l.google.com.
```

The parser was `^([\d.]+)$` — "the line is just an IP". It matches **zero** of
those lines, because every line carries a `TYPE : ` prefix. No exception, no
warning, just an empty list. Downstream, an empty list means "no independent
address available", which means "cannot pin", which means the host gets reported
as unreachable — when in fact it was never tested properly. Five hosts were
misclassified that way before anyone noticed.

The fix is one regex, but the lesson is the ordering: **print a raw sample
before writing a parser**, and make "pinning failed" loud enough that it cannot
be confused with "pinning was not attempted". `--dump-raw` exists for exactly
this, and both forms are in the selftest.

**2. A selftest that passed against broken code.**

The first selftest for that parser used a shortened copy of the real response,
typed out by hand. It passed 5/5 while live data kept failing. Fixtures here are
the **literal** response bodies, kept verbatim, including the case that the old
regex returns `[]` for.

## Caveats

* A verdict describes **one moment from one network**. Re-run it rather than
  trusting a result from last week.
* An independent resolver may itself be unreachable. When it is, the tool says
  `dns_source: none` instead of guessing — an unpinned failure cannot, on its
  own, tell DNS interference apart from a TCP block.
* `--resolve` pins the address but still uses the hostname for SNI/Host, which
  is the point: it isolates name resolution without changing anything else.
* Do not use this to do anything you would not otherwise be allowed to do.

## License

MIT.
