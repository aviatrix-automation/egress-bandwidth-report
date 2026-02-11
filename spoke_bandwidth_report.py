#!/usr/bin/env python3
"""
Spoke Gateway Bandwidth Report

Per-spoke breakdown of Internal (transit/tunnel) vs Egress (internet) traffic
using interface counters from Aviatrix CoPilot.

Method:
  Internal RX = Σ(tun_rx)                    — bytes from other VPCs into this spoke
  Internal TX = Σ(tun_tx)                    — bytes from this spoke to other VPCs
  Egress RX   = eth0_rx - Σ(tun_rx+tun_tx)  — non-tunnel bytes arriving at gateway
  Egress TX   = eth0_tx - Σ(tun_rx+tun_tx)  — non-tunnel bytes leaving gateway

  The small delta between Egress RX and TX is IPsec encap/decap overhead.
"""

import csv
import io
import json
import os
import sys
import argparse
from collections import OrderedDict
import calendar
from datetime import datetime, timedelta

import requests

requests.packages.urllib3.disable_warnings()


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


def get_spoke_gateways(session, copilot):
    """Return list of spoke gateways."""
    r = session.get(f"https://{copilot}/api/gateways", verify=False, timeout=30)
    r.raise_for_status()
    return [g for g in r.json().get("results", [])
            if g.get("$gw_type", "").lower() == "spoke"]


def get_tunnel_map(session, copilot):
    """Return {gw_name: [tun-interface, ...]} for all gateways."""
    r = session.get(f"https://{copilot}/api/cloud-routes/routes/gateways",
                    verify=False, timeout=30)
    r.raise_for_status()
    tun_map = {}
    for gw in r.json():
        name = gw.get("gw_name")
        tuns = []
        for route in gw.get("route_table", []):
            dev = route.get("dev", "")
            if dev.startswith("tun-") and dev not in tuns:
                tuns.append(dev)
        tun_map[name] = tuns
    return tun_map


def get_interface_metrics(session, copilot, gw_name, start_iso, end_iso):
    """Fetch rx_bytes/tx_bytes counters for all interfaces on a gateway."""
    r = session.post(
        f"https://{copilot}/api/reports/report/performance",
        json=[{
            "gatewayName": gw_name,
            "systemMetrics": [],
            "interfaceMetrics": ["rx_bytes", "tx_bytes"],
            "start": start_iso,
            "end": end_iso,
            "perInterfaceStats": True,
        }],
        verify=False, timeout=60,
    )
    r.raise_for_status()
    data = r.json()
    if data and len(data) > 0:
        return data[0].get("interfaces", {})
    return {}


def counter_delta(iface_data, metric):
    """Compute max-min delta for a cumulative counter, handling rollover."""
    c = iface_data.get(metric, {})
    lo, hi = c.get("min", 0) or 0, c.get("max", 0) or 0
    if hi >= lo:
        return hi - lo
    # Rollover — use max as approximation
    print(f"  [WARN] Counter rollover on {metric}: min={lo} max={hi}", file=sys.stderr)
    return hi


def compute_gateway(interfaces, tun_names):
    """Compute traffic breakdown for one gateway.

    Returns dict with eth0_rx, eth0_tx, internal_rx, internal_tx,
    egress_rx, egress_tx.
    """
    eth0 = interfaces.get("eth0", {})
    eth0_rx = counter_delta(eth0, "rx_bytes")
    eth0_tx = counter_delta(eth0, "tx_bytes")

    tun_rx = sum(counter_delta(interfaces.get(t, {}), "rx_bytes") for t in tun_names)
    tun_tx = sum(counter_delta(interfaces.get(t, {}), "tx_bytes") for t in tun_names)

    tun_total = tun_rx + tun_tx
    egress_rx = max(0, eth0_rx - tun_total)
    egress_tx = max(0, eth0_tx - tun_total)

    return {
        "eth0_rx": eth0_rx,
        "eth0_tx": eth0_tx,
        "internal_rx": tun_rx,
        "internal_tx": tun_tx,
        "egress_rx": egress_rx,
        "egress_tx": egress_tx,
    }


# ---------------------------------------------------------------------------
# Formatting
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


def fmt_short(b):
    """Short format: 1.50T / 4.32G / 250M / 12K."""
    if b >= 1_099_511_627_776:
        return f"{b / 1_099_511_627_776:.2f}T"
    if b >= 1_073_741_824:
        return f"{b / 1_073_741_824:.2f}G"
    if b >= 1_048_576:
        return f"{b / 1_048_576:.1f}M"
    if b >= 1024:
        return f"{b / 1024:.0f}K"
    return f"{b}B"


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

GROUPBY_FIELDS = {
    "account":  "account_name",
    "vpc":      "vpc_name",
    "vpc_id":   "vpc_id",
    "region":   "vpc_region",
    "cloud":    "vendor_name",
    "transit":  "transit_gw_name",
    "group":    "group_name",
}


def _sum_data(rows):
    """Sum the data dicts across a list of result rows."""
    agg = {"internal_rx": 0, "internal_tx": 0, "egress_rx": 0, "egress_tx": 0}
    for r in rows:
        for k in agg:
            agg[k] += r["data"][k]
    return agg


def _group_results(results, group_by):
    """Group results by a field. Returns OrderedDict {label: [rows]}."""
    field = GROUPBY_FIELDS[group_by]
    groups = OrderedDict()
    for r in results:
        key = r.get(field) or "(none)"
        groups.setdefault(key, []).append(r)
    return groups


def _render_section(lines, label, data_dict):
    """Append a labeled Internal/Egress/Total block."""
    lines.append(f"  Internal:  RX {fmt(data_dict['internal_rx'])}, TX {fmt(data_dict['internal_tx'])}")
    lines.append(f"  Egress:    RX {fmt(data_dict['egress_rx'])}, TX {fmt(data_dict['egress_tx'])}")
    total = sum(data_dict.values())
    lines.append(f"  Total:     {fmt(total)}")


def render_text(results, period_start, period_end, days, group_by=None):
    """Render the customer-facing text report."""
    lines = []
    w = 70
    lines.append("=" * w)
    lines.append("Spoke Gateway Bandwidth Report")
    lines.append(f"Period: {period_start:%Y-%m-%d} to {period_end:%Y-%m-%d} ({days} days)")
    if group_by:
        lines.append(f"Grouped by: {group_by}")
    lines.append("=" * w)

    if group_by:
        groups = _group_results(results, group_by)
        for label, rows in groups.items():
            agg = _sum_data(rows)
            lines.append("")
            gw_names = ", ".join(r["gateway"] for r in rows)
            lines.append(f"{label}:  ({len(rows)} spoke{'s' if len(rows)!=1 else ''})")
            _render_section(lines, label, agg)
            lines.append(f"  Gateways:  {gw_names}")
    else:
        for r in results:
            lines.append("")
            lines.append(f"{r['gateway']}:")
            _render_section(lines, r["gateway"], r["data"])

    lines.append("")
    lines.append("-" * w)
    lines.append("AGGREGATE (all spokes)")
    lines.append("-" * w)
    agg = _sum_data(results)
    _render_section(lines, "AGGREGATE", agg)
    lines.append("")
    lines.append("Method: Interface counters (eth0 minus tunnel interfaces)")
    lines.append("Note:   Egress RX/TX delta narrows with traffic volume. In low-traffic")
    lines.append("        environments, control-plane overhead inflates the gap.")
    lines.append("=" * w)
    return "\n".join(lines)


def render_json(results, period_start, period_end, days):
    """Render JSON output."""
    gateways = []
    for r in results:
        d = r["data"]
        gateways.append({
            "gateway": r["gateway"],
            "account_name": r["account_name"],
            "vpc_name": r["vpc_name"],
            "vpc_id": r["vpc_id"],
            "vpc_region": r["vpc_region"],
            "vendor_name": r["vendor_name"],
            "transit_gw_name": r["transit_gw_name"],
            "group_name": r["group_name"],
            "tunnel_interfaces": r["tunnels"],
            "internal_rx_bytes": d["internal_rx"],
            "internal_tx_bytes": d["internal_tx"],
            "egress_rx_bytes": d["egress_rx"],
            "egress_tx_bytes": d["egress_tx"],
            "eth0_rx_bytes": d["eth0_rx"],
            "eth0_tx_bytes": d["eth0_tx"],
        })
    return json.dumps({
        "report": "spoke_gateway_bandwidth",
        "method": "interface_counters",
        "period_start": period_start.isoformat() + "Z",
        "period_end": period_end.isoformat() + "Z",
        "period_days": days,
        "gateways": gateways,
    }, indent=2)


def render_csv(results):
    """Render CSV output with gateway attributes for group-by in Excel."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "gateway", "account_name", "vpc_name", "vpc_id", "vpc_region",
        "vendor_name", "transit_gw_name", "group_name",
        "internal_rx_bytes", "internal_tx_bytes",
        "egress_rx_bytes", "egress_tx_bytes",
        "internal_rx", "internal_tx", "egress_rx", "egress_tx",
    ])
    for r in results:
        d = r["data"]
        w.writerow([
            r["gateway"], r["account_name"], r["vpc_name"], r["vpc_id"],
            r["vpc_region"], r["vendor_name"], r["transit_gw_name"],
            r["group_name"],
            d["internal_rx"], d["internal_tx"],
            d["egress_rx"], d["egress_tx"],
            fmt(d["internal_rx"]), fmt(d["internal_tx"]),
            fmt(d["egress_rx"]), fmt(d["egress_tx"]),
        ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Spoke Gateway Bandwidth Report — Internal vs Egress breakdown")
    parser.add_argument("--days", type=int, default=30,
                        help="Look-back period in days (default: 30)")
    parser.add_argument("--gateway", type=str, default=None,
                        help="Filter to a specific gateway name")
    parser.add_argument("--output", choices=["text", "json", "csv"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--group-by", choices=list(GROUPBY_FIELDS.keys()), default=None,
                        dest="group_by",
                        help="Group results (text output): account, vpc, vpc_id, region, cloud, transit, group")
    parser.add_argument("--month", type=int, choices=range(1, 13), metavar="1-12",
                        help="Calendar month (requires --year, mutually exclusive with --days)")
    parser.add_argument("--year", type=int,
                        help="Calendar year (requires --month)")
    parser.add_argument("--env", type=str, default=".env.avx.local",
                        help="Path to .env file (default: .env.avx.local)")
    args = parser.parse_args()

    if args.month and not args.year:
        parser.error("--month requires --year")
    if args.year and not args.month:
        parser.error("--year requires --month")

    env = load_env(args.env)
    copilot, user, pwd = resolve_creds(env)
    if not all([copilot, user, pwd]):
        print("[ERROR] Missing credentials. Set AVIATRIX_COPILOT_IP / USERNAME / PASSWORD "
              "in env file or environment.", file=sys.stderr)
        sys.exit(1)

    if args.month:
        start_time = datetime(args.year, args.month, 1)
        last_day = calendar.monthrange(args.year, args.month)[1]
        end_time = datetime(args.year, args.month, last_day, 23, 59, 59)
        days = last_day
    else:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=args.days)
        days = args.days
    start_iso = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_iso = end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    print(f"[INFO] Connecting to {copilot}...", file=sys.stderr)
    session = login(copilot, user, pwd)

    print("[INFO] Fetching gateways...", file=sys.stderr)
    spokes = get_spoke_gateways(session, copilot)
    tun_map = get_tunnel_map(session, copilot)

    if args.gateway:
        spokes = [g for g in spokes if g.get("gw_name") == args.gateway]
        if not spokes:
            print(f"[ERROR] Gateway '{args.gateway}' not found among spoke gateways.",
                  file=sys.stderr)
            sys.exit(1)

    print(f"[INFO] {len(spokes)} spoke gateway(s), period={days}d", file=sys.stderr)

    results = []
    for gw in spokes:
        name = gw.get("gw_name")
        tuns = tun_map.get(name, [])
        print(f"[INFO] {name}  tunnels={len(tuns)}", file=sys.stderr)

        interfaces = get_interface_metrics(session, copilot, name, start_iso, end_iso)
        if not interfaces:
            print(f"  [WARN] No metrics for {name}", file=sys.stderr)
            continue

        data = compute_gateway(interfaces, tuns)
        results.append({
            "gateway": name,
            "tunnels": tuns,
            "data": data,
            "account_name": gw.get("account_name", ""),
            "vpc_id": gw.get("vpc_id", ""),
            "vpc_name": gw.get("vpc_name", ""),
            "vpc_region": gw.get("vpc_region", ""),
            "vendor_name": gw.get("vendor_name", ""),
            "transit_gw_name": gw.get("transit_gw_name", ""),
            "group_name": gw.get("group_name", ""),
        })

    # Render output
    if args.output == "json":
        print(render_json(results, start_time, end_time, days))
    elif args.output == "csv":
        print(render_csv(results), end="")
    else:
        print(render_text(results, start_time, end_time, days, group_by=args.group_by))


if __name__ == "__main__":
    main()
