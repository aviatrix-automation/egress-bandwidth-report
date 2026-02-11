# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Two scripts for analyzing spoke gateway egress traffic via Aviatrix CoPilot:

1. **`spoke_bandwidth_report.py`** — per-spoke Internal vs Egress bandwidth using interface counters. Answers: "How much traffic is internal east-west vs internet-bound, per spoke?"
2. **`flowiq_top_talkers.py`** — top external destinations and internal sources using FlowIQ flow records. Answers: "Who is my network talking to on the internet, and which hosts generate that traffic?"

Both are single-file, single-dependency (`requests`), share the same env/auth patterns, and use stderr for progress / stdout for output.


## Aviatrix Environment

Credentials in `.env.avx.local` (variables: `COPILOT_URL`, `CONTROLLER_URL`, `USERNAME`, `PASSWORD` — read-only demo account). The script auto-detects both naming conventions (`COPILOT_URL` / `AVIATRIX_COPILOT_IP`).

## Method — Interface Counters

Authenticates to CoPilot via `POST /api/login` (cookie-based session). Uses three API calls per gateway:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/gateways` | GET | List gateways, filter `$gw_type == "spoke"` |
| `/api/cloud-routes/routes/gateways` | GET | Extract `tun-*` interfaces from route tables |
| `/api/reports/report/performance` | POST | Cumulative `rx_bytes`/`tx_bytes` per interface |

**Formulas** (delta = max - min over the period):
```
Internal RX = Σ(tun_rx)                    — bytes from other VPCs into this spoke
Internal TX = Σ(tun_tx)                    — bytes from this spoke to other VPCs
Egress RX   = eth0_rx - Σ(tun_rx + tun_tx) — non-tunnel bytes arriving at gateway
Egress TX   = eth0_tx - Σ(tun_rx + tun_tx) — non-tunnel bytes leaving gateway
```

The delta between Egress RX and TX is IPsec encap/decap overhead + control-plane traffic. This gap narrows proportionally as real traffic volume increases.

**Why this works**: eth0 is the only physical interface. Tunnel traffic appears on eth0 twice (original + encapsulated). Subtracting tunnel counters from each eth0 direction isolates the non-tunnel (egress) portion of each counter independently.

## Commands

```bash
# Default: 30-day text report, all spokes
python3 spoke_bandwidth_report.py

# Time period
python3 spoke_bandwidth_report.py --days 7
python3 spoke_bandwidth_report.py --days 90

# Single gateway
python3 spoke_bandwidth_report.py --gateway marketing-azure-spoke-all

# Output formats
python3 spoke_bandwidth_report.py --output text    # human-readable (default)
python3 spoke_bandwidth_report.py --output csv     # for Excel (includes all attributes)
python3 spoke_bandwidth_report.py --output json    # machine-readable

# Group-by (text output) — rolls up gateways by attribute
python3 spoke_bandwidth_report.py --group-by account   # cloud account / BU
python3 spoke_bandwidth_report.py --group-by region    # VPC region
python3 spoke_bandwidth_report.py --group-by cloud     # AWS / Azure / GCP / OCI
python3 spoke_bandwidth_report.py --group-by transit   # attached transit gateway
python3 spoke_bandwidth_report.py --group-by vpc       # VPC name
python3 spoke_bandwidth_report.py --group-by group     # Aviatrix gateway group

# Env file (default: .env.avx.local)
python3 spoke_bandwidth_report.py --env /path/to/.env

# Pipe-friendly: stderr has progress, stdout has report
python3 spoke_bandwidth_report.py --output csv > report.csv 2>/dev/null

# Dependency
pip install requests
```

## CSV Columns

The CSV includes gateway attributes for pivot tables / group-by in Excel:
`gateway`, `account_name`, `vpc_name`, `vpc_id`, `vpc_region`, `vendor_name`, `transit_gw_name`, `group_name`, plus raw byte counts and human-readable values for internal/egress RX/TX.

## Key Design Decisions (spoke_bandwidth_report.py)

- Single file, single dependency (`requests`).
- `requests.Session` with `verify=False` (self-signed CoPilot certs).
- stderr for progress/status, stdout for structured output (pipe-friendly).
- Counter rollover handled (max < min → uses max as approximation).
- Gateway attributes (account, VPC, region, cloud, transit, group) carried through all output formats for flexible grouping.

## Method — FlowIQ Top Talkers

Authenticates to CoPilot via `POST /api/login`. Uses two API endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/gateways` | GET | List gateways, filter `$gw_type == "spoke"` |
| `/api/flowiq/field_agg` | GET | Top-N aggregation by field (src/dst addr) |

**Bidirectional queries**: flow records can appear in either direction, so the script runs two queries per scope and normalizes:
- Outbound (RFC1918→public): `dst_addr` = external IP, `src_addr` = internal IP
- Inbound (public→RFC1918): `src_addr` = external IP, `dst_addr` = internal IP

Results are merged by IP (summing bytes) and re-ranked. Each sub-query over-fetches at `top * 3` to reduce missed borderline IPs during merge.

**Egress CIDR filter**: `src_addr:(RFC1918) AND NOT dst_addr:(RFC1918 OR CGNAT)` for outbound; inverse for inbound. Excludes east-west (RFC1918↔RFC1918) and CGNAT (100.64.0.0/10).

## Commands (flowiq_top_talkers.py)

```bash
# Default: 30-day text report, all spokes, top 10
python3 flowiq_top_talkers.py

# Time period / result count
python3 flowiq_top_talkers.py --days 7
python3 flowiq_top_talkers.py --top 20

# Single gateway
python3 flowiq_top_talkers.py --gateway marketing-azure-spoke-all

# Per-spoke breakdown
python3 flowiq_top_talkers.py --per-spoke

# Group per-spoke by attribute
python3 flowiq_top_talkers.py --per-spoke --group-by account
python3 flowiq_top_talkers.py --per-spoke --group-by vpc

# Output formats
python3 flowiq_top_talkers.py --output text    # human-readable (default)
python3 flowiq_top_talkers.py --output csv     # for Excel (includes CoPilot links)
python3 flowiq_top_talkers.py --output json    # machine-readable

# Pipe-friendly
python3 flowiq_top_talkers.py --output csv > top_talkers.csv 2>/dev/null
```

## CSV Columns (flowiq_top_talkers.py)

Per-spoke: `gateway`, `account_name`, `vpc_name`, `vpc_id`, `vpc_region`, `vendor_name`, `transit_gw_name`, `group_name`, then: `rank`, `direction` (destination/source), `ip`, `bytes`, `human_readable`, `is_cgnat`, `flowiq_filter`, `copilot_url`.

Global: `direction`, `rank`, `ip`, `bytes`, `human_readable`, `is_cgnat`, `flowiq_filter`, `copilot_url`.

The `copilot_url` column links to FlowIQ; `flowiq_filter` is the IP to paste into the CoPilot filter bar (CoPilot doesn't support deep-linked filter URLs).

## Key Design Decisions (flowiq_top_talkers.py)

- Single file, single dependency (`requests`), same patterns as spoke_bandwidth_report.py.
- Bidirectional merge captures full conversation volume per IP.
- Over-fetches `top * 3` from each sub-query before merge to reduce rank drift.
- `--group-by` auto-enables `--per-spoke` for convenience.
- CoPilot FlowIQ link + filter string included in all output formats.
- CGNAT (100.64.0.0/10) flagged on every IP entry.

