#!/usr/bin/env python3
"""
FlowIQ Top Talkers Report

Top external destinations and internal sources ranked by bytes transferred,
using Aviatrix CoPilot FlowIQ field_agg API. Supports per-spoke breakdown,
group-by attributes, and multiple output formats.

Bidirectional: queries both outbound (RFC1918→public) and inbound
(public→RFC1918) flows, then normalizes the public IP as "destination"
and the private IP as "source" regardless of flow record direction.
This captures the full conversation (request + response) for each pair.
"""

import csv
import io
import json
import os
import sys
import argparse
from collections import OrderedDict
from datetime import datetime, timedelta
from urllib.parse import urlencode

import requests

requests.packages.urllib3.disable_warnings()


# ---------------------------------------------------------------------------
# CIDR constants
# ---------------------------------------------------------------------------

RFC1918_CIDR = '("10.0.0.0/8" OR "172.16.0.0/12" OR "192.168.0.0/16")'
CGNAT_CIDR = '"100.64.0.0/10"'

# Outbound: RFC1918 src → public dst (classic egress direction)
EGRESS_OUTBOUND = (
    f'netflow.src_addr:{RFC1918_CIDR}'
    f' AND NOT netflow.dst_addr:{RFC1918_CIDR}'
    f' AND NOT netflow.dst_addr:{CGNAT_CIDR}'
)

# Inbound: public src → RFC1918 dst (return traffic / reversed flows)
EGRESS_INBOUND = (
    f'NOT netflow.src_addr:{RFC1918_CIDR}'
    f' AND NOT netflow.src_addr:{CGNAT_CIDR}'
    f' AND netflow.dst_addr:{RFC1918_CIDR}'
)


# ---------------------------------------------------------------------------
# Env / auth (from spoke_bandwidth_report.py)
# ---------------------------------------------------------------------------

def load_env(path):
    """Load key=value pairs from a .env file."""
    env = {}
    if not os.path.exists(path):
        return env
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:]
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def resolve_creds(env):
    """Resolve credentials from env dict, supporting both naming conventions."""
    copilot = (env.get("AVIATRIX_COPILOT_IP")
               or (env.get("COPILOT_URL", "").replace("https://", "").replace("http://", ""))
               or os.environ.get("AVIATRIX_COPILOT_IP", ""))
    user = env.get("AVIATRIX_USERNAME") or env.get("USERNAME") or os.environ.get("AVIATRIX_USERNAME", "")
    pwd = env.get("AVIATRIX_PASSWORD") or env.get("PASSWORD") or os.environ.get("AVIATRIX_PASSWORD", "")
    return copilot, user, pwd


def login(copilot, username, password):
    """Authenticate and return a session with cookies."""
    s = requests.Session()
    r = s.post(f"https://{copilot}/api/login",
               json={"username": username, "password": password},
               verify=False, timeout=30)
    r.raise_for_status()
    return s


# ---------------------------------------------------------------------------
# Gateway metadata
# ---------------------------------------------------------------------------

def get_spoke_gateways(session, copilot):
    """Return list of spoke gateways with metadata."""
    r = session.get(f"https://{copilot}/api/gateways", verify=False, timeout=30)
    r.raise_for_status()
    return [g for g in r.json().get("results", [])
            if g.get("$gw_type", "").lower() == "spoke"]


def gateway_meta(gw):
    """Extract metadata dict from a gateway object."""
    return {
        "account_name": gw.get("account_name", ""),
        "vpc_name": gw.get("vpc_name", ""),
        "vpc_id": gw.get("vpc_id", ""),
        "vpc_region": gw.get("vpc_region", ""),
        "vendor_name": gw.get("vendor_name", ""),
        "transit_gw_name": gw.get("transit_gw_name", ""),
        "group_name": gw.get("group_name", ""),
    }


# ---------------------------------------------------------------------------
# FlowIQ helpers (from flowiq_nat_traffic.py)
# ---------------------------------------------------------------------------

def flowiq_field_agg(session, copilot, field, metric, query_string,
                     start_time, end_time, size=None,
                     interval="1d", timezone="-05:00"):
    """Query FlowIQ field_agg endpoint for top-N aggregation."""
    params = {
        "field": field,
        "metric": metric,
        "query_string": query_string,
        "date_range[time_zone]": timezone,
        "date_range[gte]": start_time,
        "date_range[lte]": end_time,
        "interval": interval,
    }
    if size is not None:
        params["size"] = size
    url = f"https://{copilot}/api/flowiq/field_agg?{urlencode(params)}"
    r = session.get(url, verify=False, timeout=60)
    r.raise_for_status()
    return r.json()


def is_cgnat(ip):
    """Check if IP is in CGNAT range (100.64.0.0/10)."""
    if ip and ip.startswith('100.'):
        octets = ip.split('.')
        if len(octets) >= 2:
            try:
                if 64 <= int(octets[1]) <= 127:
                    return True
            except ValueError:
                pass
    return False


# ---------------------------------------------------------------------------
# Formatting (from spoke_bandwidth_report.py)
# ---------------------------------------------------------------------------

def fmt(b):
    """Human-readable bytes (GB/MB/KB)."""
    if b >= 1_099_511_627_776:
        return f"{b / 1_099_511_627_776:.2f} TB"
    if b >= 1_073_741_824:
        return f"{b / 1_073_741_824:.2f} GB"
    if b >= 1_048_576:
        return f"{b / 1_048_576:.1f} MB"
    if b >= 1024:
        return f"{b / 1024:.0f} KB"
    return f"{b} B"


GROUPBY_FIELDS = {
    "account":  "account_name",
    "vpc":      "vpc_name",
    "vpc_id":   "vpc_id",
    "region":   "vpc_region",
    "cloud":    "vendor_name",
    "transit":  "transit_gw_name",
    "group":    "group_name",
}

FLOWIQ_PATH = "/monitor/flow-iq/flowiq/overview"


def flowiq_filter(ip):
    """Build the filter string to paste into CoPilot FlowIQ for an IP."""
    return ip


def flowiq_url(copilot):
    """Return the base FlowIQ URL (no deep-link params — CoPilot doesn't support them)."""
    return f"https://{copilot}{FLOWIQ_PATH}"


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _agg_to_dict(result, limit):
    """Convert field_agg response to {ip: bytes} dict."""
    out = {}
    for item in result.get("value", [])[:limit]:
        out[item.get("key", "unknown")] = item.get("value", 0)
    return out


def _merge_and_rank(dict_a, dict_b, top):
    """Merge two {ip: bytes} dicts, sum duplicates, return top-N list."""
    merged = {}
    for d in (dict_a, dict_b):
        for ip, b in d.items():
            merged[ip] = merged.get(ip, 0) + b
    ranked = sorted(merged.items(), key=lambda x: x[1], reverse=True)[:top]
    return [{"ip": ip, "bytes": b, "is_cgnat": is_cgnat(ip),
             "flowiq_filter": flowiq_filter(ip)} for ip, b in ranked]


def fetch_top_talkers(session, copilot, start_iso, end_iso, top,
                      gw_filter=None):
    """Fetch top external destinations and internal sources.

    Runs two directional queries and normalizes:
      Outbound (RFC1918→public): dst_addr = external IP, src_addr = internal IP
      Inbound  (public→RFC1918): src_addr = external IP, dst_addr = internal IP

    Merges both directions so every external IP is counted as a "destination"
    and every internal IP as a "source", regardless of flow record direction.

    Returns (destinations, sources) where each is a list of
    {"ip": str, "bytes": int, "is_cgnat": bool}.
    """
    outbound_q = EGRESS_OUTBOUND
    inbound_q = EGRESS_INBOUND
    if gw_filter:
        outbound_q = f'({outbound_q}) AND netflow.gw_name:"{gw_filter}"'
        inbound_q = f'({inbound_q}) AND netflow.gw_name:"{gw_filter}"'

    # Over-fetch from each sub-query so merge doesn't miss borderline IPs
    fetch_size = top * 3

    # External IPs — outbound: dst_addr is external; inbound: src_addr is external
    out_dst = flowiq_field_agg(
        session, copilot, field="netflow.dst_addr", metric="bytes",
        query_string=outbound_q, start_time=start_iso, end_time=end_iso,
        size=fetch_size,
    )
    in_src = flowiq_field_agg(
        session, copilot, field="netflow.src_addr", metric="bytes",
        query_string=inbound_q, start_time=start_iso, end_time=end_iso,
        size=fetch_size,
    )
    destinations = _merge_and_rank(
        _agg_to_dict(out_dst, fetch_size),
        _agg_to_dict(in_src, fetch_size),
        top,
    )

    # Internal IPs — outbound: src_addr is internal; inbound: dst_addr is internal
    out_src = flowiq_field_agg(
        session, copilot, field="netflow.src_addr", metric="bytes",
        query_string=outbound_q, start_time=start_iso, end_time=end_iso,
        size=fetch_size,
    )
    in_dst = flowiq_field_agg(
        session, copilot, field="netflow.dst_addr", metric="bytes",
        query_string=inbound_q, start_time=start_iso, end_time=end_iso,
        size=fetch_size,
    )
    sources = _merge_and_rank(
        _agg_to_dict(out_src, fetch_size),
        _agg_to_dict(in_dst, fetch_size),
        top,
    )

    return destinations, sources


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

def render_text_global(destinations, sources, period_start, period_end, days,
                       top, copilot_url):
    """Render global (non-per-spoke) text report."""
    w = 70
    lines = []
    lines.append("=" * w)
    lines.append("FlowIQ Top Talkers Report")
    lines.append(f"Period: {period_start:%Y-%m-%d} to {period_end:%Y-%m-%d} ({days} days)")
    lines.append("=" * w)

    lines.append("")
    lines.append(f"TOP {min(top, len(destinations))} DESTINATIONS (Egress)")
    lines.append("-" * w)
    for i, d in enumerate(destinations, 1):
        cgnat = " [CGNAT]" if d["is_cgnat"] else ""
        lines.append(f"  {i:3}. {d['ip']:24} {fmt(d['bytes']):>12}{cgnat}")

    lines.append("")
    lines.append(f"TOP {min(top, len(sources))} SOURCES (Internal \u2192 Egress)")
    lines.append("-" * w)
    for i, s in enumerate(sources, 1):
        cgnat = " [CGNAT]" if s["is_cgnat"] else ""
        lines.append(f"  {i:3}. {s['ip']:24} {fmt(s['bytes']):>12}{cgnat}")

    lines.append("")
    lines.append("Method: FlowIQ field_agg (bidirectional, CIDR-based egress filter)")
    lines.append(f"CoPilot: {copilot_url}")
    lines.append("Tip: paste any IP into the FlowIQ filter bar to drill down")
    lines.append("=" * w)
    return "\n".join(lines)


def render_text_per_spoke(spoke_results, period_start, period_end, days, top,
                          copilot_url, group_by=None):
    """Render per-spoke (or grouped) text report."""
    w = 70
    lines = []
    lines.append("=" * w)
    lines.append("FlowIQ Top Talkers Report")
    lines.append(f"Period: {period_start:%Y-%m-%d} to {period_end:%Y-%m-%d} ({days} days)")
    lines.append("Per-spoke breakdown")
    if group_by:
        lines.append(f"Grouped by: {group_by}")
    lines.append("=" * w)

    if group_by:
        field = GROUPBY_FIELDS[group_by]
        groups = OrderedDict()
        for r in spoke_results:
            key = r["meta"].get(field) or "(none)"
            groups.setdefault(key, []).append(r)

        for label, rows in groups.items():
            lines.append("")
            lines.append(f"{label}:  ({len(rows)} spoke{'s' if len(rows) != 1 else ''})")
            gw_names = ", ".join(r["gateway"] for r in rows)
            lines.append(f"  Gateways: {gw_names}")

            # Merge destinations and sources across gateways in this group
            merged_dst = _merge_ip_lists([r["destinations"] for r in rows])[:top]
            merged_src = _merge_ip_lists([r["sources"] for r in rows])[:top]

            if merged_dst:
                lines.append(f"  Top Destinations:")
                for i, d in enumerate(merged_dst, 1):
                    cgnat = " [CGNAT]" if d["is_cgnat"] else ""
                    lines.append(f"    {i:3}. {d['ip']:24} {fmt(d['bytes']):>12}{cgnat}")
            if merged_src:
                lines.append(f"  Top Sources:")
                for i, s in enumerate(merged_src, 1):
                    cgnat = " [CGNAT]" if s["is_cgnat"] else ""
                    lines.append(f"    {i:3}. {s['ip']:24} {fmt(s['bytes']):>12}{cgnat}")
    else:
        for r in spoke_results:
            lines.append("")
            lines.append(f"{r['gateway']}:")
            if r["destinations"]:
                lines.append("  Top Destinations:")
                for i, d in enumerate(r["destinations"], 1):
                    cgnat = " [CGNAT]" if d["is_cgnat"] else ""
                    lines.append(f"    {i:3}. {d['ip']:24} {fmt(d['bytes']):>12}{cgnat}")
            if r["sources"]:
                lines.append("  Top Sources:")
                for i, s in enumerate(r["sources"], 1):
                    cgnat = " [CGNAT]" if s["is_cgnat"] else ""
                    lines.append(f"    {i:3}. {s['ip']:24} {fmt(s['bytes']):>12}{cgnat}")

    lines.append("")
    lines.append("Method: FlowIQ field_agg (bidirectional, CIDR-based egress filter)")
    lines.append(f"CoPilot: {copilot_url}")
    lines.append("Tip: paste any IP into the FlowIQ filter bar to drill down")
    lines.append("=" * w)
    return "\n".join(lines)


def _merge_ip_lists(lists):
    """Merge multiple [{ip, bytes, is_cgnat, flowiq_filter}] lists, summing by IP."""
    merged = {}
    for lst in lists:
        for entry in lst:
            ip = entry["ip"]
            if ip in merged:
                merged[ip]["bytes"] += entry["bytes"]
            else:
                merged[ip] = dict(entry)
    return sorted(merged.values(), key=lambda x: x["bytes"], reverse=True)


def render_json_global(destinations, sources, period_start, period_end, days,
                       copilot_url):
    """Render global JSON output."""
    return json.dumps({
        "report": "flowiq_top_talkers",
        "mode": "global",
        "period_start": period_start.isoformat() + "Z",
        "period_end": period_end.isoformat() + "Z",
        "period_days": days,
        "copilot_flowiq_url": copilot_url,
        "destinations": destinations,
        "sources": sources,
    }, indent=2)


def render_json_per_spoke(spoke_results, period_start, period_end, days,
                          copilot_url):
    """Render per-spoke JSON output."""
    gateways = []
    for r in spoke_results:
        gateways.append({
            "gateway": r["gateway"],
            **r["meta"],
            "destinations": r["destinations"],
            "sources": r["sources"],
        })
    return json.dumps({
        "report": "flowiq_top_talkers",
        "mode": "per_spoke",
        "period_start": period_start.isoformat() + "Z",
        "period_end": period_end.isoformat() + "Z",
        "period_days": days,
        "copilot_flowiq_url": copilot_url,
        "gateways": gateways,
    }, indent=2)


def render_csv_global(destinations, sources, copilot_url):
    """Render global CSV output."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "direction", "rank", "ip", "bytes", "human_readable", "is_cgnat",
        "flowiq_filter", "copilot_url",
    ])
    for i, d in enumerate(destinations, 1):
        w.writerow(["destination", i, d["ip"], d["bytes"], fmt(d["bytes"]),
                     d["is_cgnat"], d["flowiq_filter"], copilot_url])
    for i, s in enumerate(sources, 1):
        w.writerow(["source", i, s["ip"], s["bytes"], fmt(s["bytes"]),
                     s["is_cgnat"], s["flowiq_filter"], copilot_url])
    return buf.getvalue()


def render_csv_per_spoke(spoke_results, copilot_url):
    """Render per-spoke CSV output with gateway attributes."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "gateway", "account_name", "vpc_name", "vpc_id", "vpc_region",
        "vendor_name", "transit_gw_name", "group_name",
        "rank", "direction", "ip", "bytes", "human_readable", "is_cgnat",
        "flowiq_filter", "copilot_url",
    ])
    for r in spoke_results:
        m = r["meta"]
        for i, d in enumerate(r["destinations"], 1):
            w.writerow([
                r["gateway"], m["account_name"], m["vpc_name"], m["vpc_id"],
                m["vpc_region"], m["vendor_name"], m["transit_gw_name"],
                m["group_name"],
                i, "destination", d["ip"], d["bytes"], fmt(d["bytes"]),
                d["is_cgnat"], d["flowiq_filter"], copilot_url,
            ])
        for i, s in enumerate(r["sources"], 1):
            w.writerow([
                r["gateway"], m["account_name"], m["vpc_name"], m["vpc_id"],
                m["vpc_region"], m["vendor_name"], m["transit_gw_name"],
                m["group_name"],
                i, "source", s["ip"], s["bytes"], fmt(s["bytes"]),
                s["is_cgnat"], s["flowiq_filter"], copilot_url,
            ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="FlowIQ Top Talkers — top egress destinations and internal sources")
    parser.add_argument("--days", type=int, default=30,
                        help="Look-back period in days (default: 30)")
    parser.add_argument("--top", type=int, default=10,
                        help="Number of top results per direction (default: 10)")
    parser.add_argument("--gateway", type=str, default=None,
                        help="Filter to a specific spoke gateway name")
    parser.add_argument("--per-spoke", action="store_true", dest="per_spoke",
                        help="Show breakdown per spoke gateway")
    parser.add_argument("--output", choices=["text", "json", "csv"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--group-by", choices=list(GROUPBY_FIELDS.keys()),
                        default=None, dest="group_by",
                        help="Group per-spoke results by attribute (requires --per-spoke)")
    parser.add_argument("--env", type=str, default=".env.avx.local",
                        help="Path to .env file (default: .env.avx.local)")
    args = parser.parse_args()

    if args.group_by and not args.per_spoke:
        args.per_spoke = True

    env = load_env(args.env)
    copilot, user, pwd = resolve_creds(env)
    if not all([copilot, user, pwd]):
        print("[ERROR] Missing credentials. Set AVIATRIX_COPILOT_IP / USERNAME / PASSWORD "
              "in env file or environment.", file=sys.stderr)
        sys.exit(1)

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=args.days)
    start_iso = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_iso = end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    print(f"[INFO] Connecting to {copilot}...", file=sys.stderr)
    session = login(copilot, user, pwd)

    print("[INFO] Fetching gateways...", file=sys.stderr)
    spokes = get_spoke_gateways(session, copilot)

    if args.gateway:
        spokes = [g for g in spokes if g.get("gw_name") == args.gateway]
        if not spokes:
            print(f"[ERROR] Gateway '{args.gateway}' not found among spoke gateways.",
                  file=sys.stderr)
            sys.exit(1)

    # Build gateway metadata lookup and CoPilot link
    gw_meta = {g.get("gw_name"): gateway_meta(g) for g in spokes}
    copilot_url = flowiq_url(copilot)

    if args.per_spoke:
        # Per-spoke mode: query each spoke individually
        print(f"[INFO] {len(spokes)} spoke(s), fetching top {args.top} per spoke...",
              file=sys.stderr)
        spoke_results = []
        for gw in spokes:
            name = gw.get("gw_name")
            print(f"[INFO] {name}...", file=sys.stderr)
            destinations, sources = fetch_top_talkers(
                session, copilot, start_iso, end_iso, args.top,
                gw_filter=name,
            )
            spoke_results.append({
                "gateway": name,
                "meta": gw_meta[name],
                "destinations": destinations,
                "sources": sources,
            })

        if args.output == "json":
            print(render_json_per_spoke(spoke_results, start_time, end_time,
                                        args.days, copilot_url))
        elif args.output == "csv":
            print(render_csv_per_spoke(spoke_results, copilot_url), end="")
        else:
            print(render_text_per_spoke(spoke_results, start_time, end_time,
                                        args.days, args.top, copilot_url,
                                        group_by=args.group_by))
    else:
        # Global mode: single query across all spokes (or filtered gateway)
        gw_filter = args.gateway if args.gateway else None
        print(f"[INFO] Fetching global top {args.top} talkers...", file=sys.stderr)
        destinations, sources = fetch_top_talkers(
            session, copilot, start_iso, end_iso, args.top,
            gw_filter=gw_filter,
        )

        if args.output == "json":
            print(render_json_global(destinations, sources, start_time,
                                     end_time, args.days, copilot_url))
        elif args.output == "csv":
            print(render_csv_global(destinations, sources, copilot_url), end="")
        else:
            print(render_text_global(destinations, sources, start_time,
                                     end_time, args.days, args.top,
                                     copilot_url))


if __name__ == "__main__":
    main()
