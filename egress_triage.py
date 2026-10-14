#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""egress-triage — "this host doesn't work from my network" is not a diagnosis.

A host that fails to load can fail at four different layers, and each one has a
different fix:

  layer            symptom                          what actually fixes it
  ---------------  -------------------------------  ---------------------------------
  DNS              name resolves to the wrong IP    pin the real IP / change resolver
  TCP              socket to :443 never opens       different egress (or a proxy)
  TLS              TCP opens, handshake is reset    different egress; pinning is useless
  application      HTTP 401/403/429                 headers, cookies, or a login
  (and) OK         2xx/3xx                          nothing

Pinning the real IP is the experiment that separates them. It is standard curl
behaviour (`--resolve host:443:IP`). If pinning fixes it, the problem was DNS.
If pinning changes nothing, the problem is below DNS and only a different egress
will help. If pinning turns a timeout into a reset, you have just watched TCP
succeed and TLS get killed -- two different layers.

Without that one experiment, every one of these gets written down as the same
word: "blocked". And then people spend days on the wrong fix.

This tool does not proxy, tunnel or obfuscate anything. It makes one request
per host, plus one pinned request, and tells you which layer answered. That is
the whole point: get the diagnosis right before touching the fix.

Usage:
  python3 egress_triage.py host1 host2 ...        # triage
  python3 egress_triage.py --file hosts.txt
  python3 egress_triage.py --selftest             # offline, no network
  python3 egress_triage.py --json host            # machine-readable
  python3 egress_triage.py --resolve-only host    # just compare DNS answers

Requires curl and dig on PATH. No third-party packages.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# curl exit codes we actually distinguish. Anything else is reported verbatim.
EXIT_NAMES = {
    0: "ok",
    5: "proxy-resolve",
    6: "could-not-resolve-host",
    7: "could-not-connect",
    28: "operation-timeout",
    35: "ssl-connect-error",
    47: "too-many-redirects",
    52: "empty-reply",
    55: "send-error",
    56: "recv-error",
}

# DoH endpoints, tried in order. In restrictive networks these are frequently
# unreachable, which is exactly why the tool reports *which* independent source
# answered instead of assuming one exists.
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query?name={host}&type=A",
    "https://dns.google/resolve?name={host}&type=A",
]
# Last resort. Returns plain text, one record per line, with a *type prefix*:
#     A : 172.64.147.37
# That prefix is the reason this parser is written the way it is (see parse_ht).
HT_URL = "https://api.hackertarget.com/dnslookup/?q={host}"


# --------------------------------------------------------------------------- #
# process helpers
# --------------------------------------------------------------------------- #

def _run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "subprocess timeout"
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"


def _has(binary):
    return shutil.which(binary) is not None


CURL_FMT = "%{http_code}|%{remote_ip}|%{time_connect}|%{time_total}"


def curl_probe(url, resolve=None, timeout=15):
    """One request. Returns (http_code, exit_code, remote_ip, stderr_tail).

    curl still emits `-w` output when the transfer fails, so http_code is
    "000" rather than missing -- which is what makes a single probe able to
    report both "what the server said" and "how the socket died".
    """
    cmd = ["curl", "-sS", "-o", os.devnull,
           "-m", str(timeout), "--connect-timeout", str(min(10, timeout)),
           "-A", UA, "-w", CURL_FMT]
    if resolve:
        cmd += ["--resolve", resolve]
    cmd.append(url)
    rc, out, err = _run(cmd, timeout=timeout + 10)
    code, ip = "000", ""
    parts = out.strip().split("|")
    if parts and parts[0].strip().isdigit():
        code = parts[0].strip()
    if len(parts) > 1:
        ip = parts[1].strip()
    tail = err.strip().splitlines()[-1][:160] if err.strip() else ""
    return code, rc, ip, tail


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #

def resolve_system(host):
    """The resolver that the machine's own stack would use."""
    if _has("dig"):
        rc, out, _ = _run(["dig", "+short", "+time=3", "+tries=1", "A", host], timeout=12)
        if rc == 0:
            ips = [l.strip() for l in out.splitlines() if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", l.strip())]
            if ips:
                return ips, "system-dig"
        # CNAME chains sometimes hide the A records; ask for the resolved set.
        rc, out, _ = _run(["dig", "+short", "+time=3", "+tries=1", host, "A"], timeout=12)
        ips = [l.strip() for l in out.splitlines() if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", l.strip())]
        if ips:
            return ips, "system-dig"
    if _has("nslookup"):
        rc, out, _ = _run(["nslookup", "-type=A", host], timeout=12)
        ips = re.findall(r"Address:\s*(\d+\.\d+\.\d+\.\d+)", out)
        ips = [ip for ip in ips if ip != "127.0.0.1"]
        if ips:
            return ips, "system-nslookup"
    return [], "none"


def resolve_doh(host, timeout=12):
    """Independent resolution over HTTPS. Returns (ips, source)."""
    for tpl in DOH_ENDPOINTS:
        url = tpl.format(host=host)
        rc, out, _ = _run(["curl", "-sS", "-m", str(timeout), "-H",
                           "accept: application/dns-json", url], timeout=timeout + 6)
        if rc != 0 or not out.strip():
            continue
        try:
            data = json.loads(out)
        except ValueError:
            continue
        ips = []
        for ans in data.get("Answer", []) or []:
            if ans.get("type") == 1 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", str(ans.get("data", "")).strip()):
                ips.append(str(ans["data"]).strip())
        if ips:
            return sorted(set(ips)), url.split("/")[2]
    return [], "none"


def parse_ht(text):
    """Parse api.hackertarget.com's dnslookup output.

    Real output looks like this:

        A : 172.64.147.37
        MX : 10 aspmx.l.google.com.
        NS : ns1.example.com.

    The trap: a regex written as `^([\\d.]+)$` -- "the line is just an IP" --
    matches nothing here, because every line carries a `TYPE : ` prefix. A
    parser like that fails *silently*: no exception, no warning, just an empty
    list. Downstream that empty list reads as "no independent answer available",
    which in turn reads as "could not pin the IP", which reads as "the host is
    unreachable" -- when in fact the host was never tested properly.

    So: require the `A : ` prefix explicitly, and if you change this function,
    run `--dump-raw` against a host you already know the answer for.
    """
    ips = []
    for line in (text or "").splitlines():
        line = line.strip()
        m = re.match(r"^A\s*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if not m:
            # Tolerate a bare-IP dump too, but only as a separate pattern.
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)$", line)
        if m:
            ips.append(m.group(1))
    return sorted(set(ips))


def resolve_ht(host, timeout=20):
    url = HT_URL.format(host=host)
    rc, out, _ = _run(["curl", "-sS", "-m", str(timeout), url], timeout=timeout + 6)
    if rc != 0:
        return [], "none", out
    # hackertarget answers rate-limit and error messages in the body, with 200.
    if "API count exceeded" in out or "error" in out.lower()[:200]:
        return [], "none", out
    return parse_ht(out), "api.hackertarget.com", out


# Ranges that are not a plausible public answer for the host we asked about.
# 100.64.0.0/10 is carrier-grade NAT: seen in practice as the address a
# tampering resolver hands back.
BOGUS_PREFIXES = ("100.", "0.", "127.", "10.", "192.168.", "172.16.", "172.17.",
                  "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "169.254.")


def _plausible(ip):
    return not ip.startswith(BOGUS_PREFIXES)


def resolve_independent(host, explicit_resolver=None, dump_raw=False):
    """Best independent answer we can get, plus how we got it."""
    sources = []
    if explicit_resolver and _has("dig"):
        rc, out, _ = _run(["dig", f"@{explicit_resolver}", "+short", "+time=4", "+tries=1",
                           "A", host], timeout=12)
        if dump_raw:
            print(f"  [raw] dig @{explicit_resolver} -> rc={rc} {out.strip()[:200]!r}")
        ips = [l.strip() for l in out.splitlines() if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", l.strip())]
        if ips:
            sources.append((sorted(set(ips)), f"dig@{explicit_resolver}"))

    ips, src = resolve_doh(host)
    if ips:
        sources.append((ips, src))

    if not sources:
        ips, src, raw = resolve_ht(host)
        if dump_raw:
            print(f"  [raw] hackertarget -> {raw.strip()[:300]!r}")
        if ips:
            sources.append((ips, src))

    if not sources:
        return [], "none", False

    ips, src = sources[0]
    sys_ips, _ = resolve_system(host)
    mismatch = bool(sys_ips) and not (set(sys_ips) & set(ips))
    return ips, src, mismatch


# --------------------------------------------------------------------------- #
# the judgement itself
# --------------------------------------------------------------------------- #

def classify(code, exit_code, pinned_code=None, pinned_exit=None, dns_mismatch=False,
             independent_empty=False):
    """Turn two probes into one verdict: OK / AUTH-WALL / DNS / NXDOMAIN / TCP / TLS / SERVER / UNKNOWN.

    `pinned_*` is the probe whose destination IP came from an independent
    resolver. Its exit code is the honest signal about what happens *below* DNS.

    `independent_empty` says that an independent resolver was reachable and had
    no A record either -- which is a different problem from a tampered answer.
    """
    if code and code.startswith(("2", "3")):
        return "OK"
    if code in ("401", "403", "429", "451"):
        return "AUTH-WALL"
    if code and code.startswith("5"):
        return "SERVER"

    if code == "000":
        # A pinned attempt that succeeded proves the name resolution was the bug.
        if pinned_code and not pinned_code.startswith("000"):
            return "DNS"
        # Pinned attempt also failed: whatever killed it is below DNS.
        eff = pinned_exit if pinned_code == "000" else exit_code
        if eff == 6:
            return "NXDOMAIN" if independent_empty else "DNS"
        if eff in (35, 52, 56, 55):
            return "TLS"
        if eff in (7, 28):
            return "TCP"
        if eff == 0:
            return "TCP"          # curl reported no socket error but got nothing back
        return "UNKNOWN"

    return "UNKNOWN"


FIX_HINT = {
    "OK": "nothing to fix",
    "AUTH-WALL": "reachable; the site is refusing automated clients (headers, cookies, or login)",
    "DNS": "resolution is the failure; the true IP works, so pin it or change resolver",
    "NXDOMAIN": "no A record from any resolver we reached; check the spelling first",
    "TCP": "socket never opens, pinned or not: only a different egress will help",
    "TLS": "TCP connects and the handshake is reset: pinning cannot help, change egress",
    "SERVER": "the site itself is erroring; retry later",
    "UNKNOWN": "inconclusive; re-run with --resolver or --known-ip",
}


# --------------------------------------------------------------------------- #
# per-host driver
# --------------------------------------------------------------------------- #

def triage(host, url=None, resolver=None, known_ip=None, timeout=15,
           skip_dns=False, dump_raw=False):
    url = url or f"https://{host}/"
    # Never build a --resolve hint out of a URL that already carries a scheme
    # the caller supplied; keep the host we were told about.
    host_only = host

    row = {"host": host_only, "url": url}

    code, rc, ip, tail = curl_probe(url, timeout=timeout)
    row.update({"code": code, "exit": rc, "exit_name": EXIT_NAMES.get(rc, str(rc)),
                "remote_ip": ip, "stderr": tail})

    pinned_code = pinned_exit = None
    indep_ips, indep_src, mismatch = [], "none", False

    if code == "000" and not skip_dns:
        if known_ip:
            indep_ips, indep_src, mismatch = [known_ip], "--known-ip", False
            if dump_raw:
                print(f"  [raw] --known-ip -> {known_ip!r}")
        else:
            indep_ips, indep_src, mismatch = resolve_independent(
                host_only, explicit_resolver=resolver, dump_raw=dump_raw)

        if indep_ips:
            pin = f"{host_only}:443:{indep_ips[0]}"
            pinned_code, pinned_exit, pip, ptail = curl_probe(url, resolve=pin, timeout=timeout)
            row["pin"] = pin
            row["pinned_code"] = pinned_code
            row["pinned_exit"] = pinned_exit
            row["pinned_exit_name"] = EXIT_NAMES.get(pinned_exit, str(pinned_exit))
            row["pinned_remote_ip"] = pip
            if ptail:
                row["pinned_stderr"] = ptail

    row["dns_ips"] = indep_ips
    row["dns_source"] = indep_src
    row["dns_mismatch"] = mismatch
    independent_empty = (indep_src == "none" and not indep_ips)
    row["verdict"] = classify(code, rc, pinned_code, pinned_exit, mismatch,
                              independent_empty=independent_empty)
    row["fix"] = FIX_HINT[row["verdict"]]
    return row


def render(row):
    v = row["verdict"]
    line = f"[{v:<9}] {row['host']:<34} code={row['code']:<4} exit={row['exit_name']}"
    if row.get("pin"):
        line += (f"  | pinned {row['pin'].split(':')[-1]} -> "
                 f"{row.get('pinned_code')} / {row.get('pinned_exit_name')}")
    if row.get("dns_mismatch"):
        line += "  | DNS MISMATCH"
    return line


# --------------------------------------------------------------------------- #
# offline selftest
# --------------------------------------------------------------------------- #

# Every case below is a real observation, not a guess. The `raw` field of the
# hackertarget case is the literal body that broke the first parser.
FIXTURES = [
    dict(name="plain reachable",
         call=dict(code="200", exit_code=0), want="OK"),
    dict(name="cloudflare 302",
         call=dict(code="302", exit_code=0), want="OK"),
    dict(name="anti-bot wall",
         call=dict(code="403", exit_code=0), want="AUTH-WALL"),
    dict(name="rate limited",
         call=dict(code="429", exit_code=0), want="AUTH-WALL"),
    dict(name="origin 503",
         call=dict(code="503", exit_code=0), want="SERVER"),
    dict(name="tcp timeout, cannot pin",
         call=dict(code="000", exit_code=28, pinned_code="000", pinned_exit=28), want="TCP"),
    dict(name="tcp refused",
         call=dict(code="000", exit_code=7, pinned_code="000", pinned_exit=7), want="TCP"),
    dict(name="tcp opens, tls reset by peer",
         call=dict(code="000", exit_code=28, pinned_code="000", pinned_exit=35), want="TLS"),
    dict(name="tls reset without a pin",
         call=dict(code="000", exit_code=35), want="TLS"),
    dict(name="empty reply from server",
         call=dict(code="000", exit_code=52, pinned_code="000", pinned_exit=52), want="TLS"),
    dict(name="local resolver dead, independent answers",
         call=dict(code="000", exit_code=6, independent_empty=False), want="DNS"),
    dict(name="no resolver has this name",
         call=dict(code="000", exit_code=6, independent_empty=True), want="NXDOMAIN"),
    dict(name="resolver tampered, true ip works",
         call=dict(code="000", exit_code=28, pinned_code="200", pinned_exit=0), want="DNS"),
    dict(name="resolver tampered, true ip hits a wall too",
         call=dict(code="000", exit_code=28, pinned_code="403", pinned_exit=0), want="DNS"),
]

# The literal body returned by api.hackertarget.com for a host with both A and
# MX records. Kept verbatim on purpose: a hand-shortened version of this string
# is what produced a "5/5 passing" selftest against a parser that still failed
# on live data.
HT_RAW_REAL = """A : 172.64.147.37
A : 104.16.132.229
MX : 10 aspmx.l.google.com.
NS : ns1.example.com.
TXT : "v=spf1 include:_spf.google.com ~all"
"""

HT_RAW_BARE = """151.101.2.217
151.101.66.217
"""


def selftest():
    fails = []

    for fx in FIXTURES:
        got = classify(**fx["call"])
        tag = "ok  " if got == fx["want"] else "FAIL"
        if got != fx["want"]:
            fails.append(fx["name"])
        print(f"  {tag} {fx['name']:<42} want={fx['want']:<9} got={got}")

    got = parse_ht(HT_RAW_REAL)
    want = ["104.16.132.229", "172.64.147.37"]
    tag = "ok  " if got == want else "FAIL"
    if got != want:
        fails.append("parse_ht typed-prefix")
    print(f"  {tag} {'parse_ht keeps only A records':<42} want={want} got={got}")

    got = parse_ht(HT_RAW_BARE)
    want = ["151.101.2.217", "151.101.66.217"]
    tag = "ok  " if got == want else "FAIL"
    if got != want:
        fails.append("parse_ht bare")
    print(f"  {tag} {'parse_ht tolerates a bare dump':<42} want={want} got={got}")

    # The regression that motivated the explicit prefix match: the old
    # `^([\\d.]+)$` pattern returned [] on the real body above, silently.
    old = [l.strip() for l in HT_RAW_REAL.splitlines() if re.fullmatch(r"[\d.]+", l.strip())]
    tag = "ok  " if old == [] else "FAIL"
    if old != []:
        fails.append("regression guard")
    print(f"  {tag} {'regression guard: old regex is silent-empty':<42} "
          f"want=[] got={old}")

    total = len(FIXTURES) + 3
    print(f"\nselftest: {total - len(fails)}/{total} passed")
    for f in fails:
        print(f"  FAILED: {f}")
    return 0 if not fails else 1


# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="Find out which layer is failing: DNS, TCP, TLS, or the application.")
    ap.add_argument("hosts", nargs="*", help="hostnames, e.g. example.com")
    ap.add_argument("--file", help="read hostnames from a file, one per line")
    ap.add_argument("--url", help="override the URL probed (applies to the first host)")
    ap.add_argument("--resolver", help="independent resolver IP to pin against, e.g. 1.1.1.1")
    ap.add_argument("--known-ip", help="skip discovery and pin this IP")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--skip-dns", action="store_true",
                    help="do not attempt pinning (faster, but cannot separate DNS from TCP)")
    ap.add_argument("--dump-raw", action="store_true",
                    help="print the raw resolver bodies before parsing them")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        sys.exit(selftest())

    hosts = list(a.hosts)
    if a.file:
        with open(a.file) as f:
            hosts += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not hosts:
        ap.print_help()
        sys.exit(2)

    if not _has("curl"):
        sys.exit("curl is required and was not found on PATH")

    rows = []
    for i, h in enumerate(hosts):
        row = triage(h, url=(a.url if i == 0 else None), resolver=a.resolver,
                     known_ip=a.known_ip, timeout=a.timeout,
                     skip_dns=a.skip_dns, dump_raw=a.dump_raw)
        rows.append(row)
        if not a.json:
            print(render(row))

    if a.json:
        print(json.dumps(rows, indent=1, ensure_ascii=False))
        return

    bad = [r for r in rows if r["verdict"] != "OK"]
    if bad:
        print("\nwhat each verdict means:")
        for v in sorted({r["verdict"] for r in bad}):
            print(f"  {v:<9} {FIX_HINT[v]}")


if __name__ == "__main__":
    main()
