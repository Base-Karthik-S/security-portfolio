#!/usr/bin/env python3
"""Beacon interval-regularity hunt over Zeek conn.log (T1071). Project 1 home SOC, IR-2026-004.

Groups connections by (source, destination, destination port); for groups with at least
--min-count connections, computes the mean and population standard deviation of
inter-arrival times and the coefficient of variation (cv = sd / mean).

STATUS: the statistics part (grouping, mean, sd, cv) is what was run on 15 Oct 2026 and
produced the table in IR-2026-004. The FLAG column (cv below --max-cv, multicast
excluded) is a later addition and has NOT been run yet; re-run it and compare the output
with the IR table before relying on it.

Zeek rotates conn.log hourly, so a window that crosses the hour needs the rotated .gz
files as well as current/conn.log. Run with sudo: the log directory is root-owned.

Example (the 30-request run, 15:57:26 to 16:27:33 UTC, with margin):
  sudo python3 T1071-beacon-interval.py --start 1792079800 --end 1792081700 \
       --logdir /opt/zeek/logs --day 2026-10-15
"""
import argparse
import glob
import gzip
import ipaddress
import json
import statistics as st
from collections import defaultdict


def is_multicast(ip):
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--start", type=float, required=True, help="window start, UTC epoch seconds")
    ap.add_argument("--end", type=float, required=True, help="window end, UTC epoch seconds")
    ap.add_argument("--logdir", default="/opt/zeek/logs")
    ap.add_argument("--day", required=True, help="rotated-log folder name, e.g. 2026-10-15")
    ap.add_argument("--min-count", type=int, default=10)
    ap.add_argument("--max-cv", type=float, default=0.2)
    a = ap.parse_args()

    files = glob.glob(f"{a.logdir}/{a.day}/conn.*.log.gz") + [f"{a.logdir}/current/conn.log"]
    pairs = defaultdict(list)
    for f in files:
        opener = gzip.open if f.endswith(".gz") else open
        try:
            fh = opener(f, "rt")
        except OSError:
            continue
        with fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if a.start <= r["ts"] <= a.end:
                    pairs[(r["id.orig_h"], r["id.resp_h"], r["id.resp_p"])].append(r["ts"])

    print(f"{'src':<16}{'dst':<18}{'port':<6}{'n':>4}{'mean_s':>9}{'sd_s':>8}{'cv':>7}  flag")
    for k, ts in sorted(pairs.items(), key=lambda x: -len(x[1])):
        if len(ts) < a.min_count:
            continue
        ts.sort()
        d = [y - x for x, y in zip(ts, ts[1:])]
        m, s = st.mean(d), st.pstdev(d)
        cv = s / m if m else float("inf")
        flag = "BEACON?" if (cv < a.max_cv and not is_multicast(k[1])) else ""
        print(f"{k[0]:<16}{k[1]:<18}{k[2]:<6}{len(ts):>4}{m:>9.1f}{s:>8.1f}{cv:>7.2f}  {flag}")


if __name__ == "__main__":
    main()
