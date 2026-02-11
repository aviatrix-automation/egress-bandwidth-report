# Aviatrix Egress Bandwidth Reports

See how much of your spoke gateway traffic is internal (east-west) vs internet-bound, and find out which external IPs your network talks to the most.

| Script | What it tells you | Egress model |
|--------|-------------------|---------------|
| `spoke_bandwidth_report.py` | Internal vs Egress bandwidth per spoke gateway | Local egress (Single-IP SNAT) only |
| `flowiq_top_talkers.py` | Top external destinations and top internal sources by bytes | Local or centralized egress |

## Quick Start

**1. Install Python 3.7+** — download from [python.org](https://www.python.org/downloads/) if you don't have it.

**2. Install the one dependency:**

```bash
pip install requests
```

**3. Create a credentials file** named `.env` in this folder:

```
COPILOT_URL=https://your-copilot.example.com
USERNAME=your-username
PASSWORD=your-password
```

> Your CoPilot URL is the full address you use to log into CoPilot in your browser. Use a read-only account if possible.

**4. Run a report:**

```bash
# Bandwidth breakdown (internal vs egress) for all spokes, last 30 days
python3 spoke_bandwidth_report.py --env .env

# Top external IPs and top internal sources, last 30 days
python3 flowiq_top_talkers.py --env .env
```

That's it. Output prints to your terminal. Add `--output csv > report.csv` to save as CSV for Excel.

---

## Spoke Bandwidth Report

Shows how much traffic on each spoke gateway is **internal** (transit/east-west between VPCs) vs **egress** (internet-bound).

> **Requires local egress with Single-IP SNAT enabled on the spoke gateway.** This script measures egress by subtracting tunnel traffic from eth0 counters, which only works when the spoke itself handles internet-bound traffic. It will not produce meaningful egress numbers for centralized egress deployments where internet traffic routes through the transit/firenet.

### Sample Output

```
======================================================================
Spoke Gateway Bandwidth Report
Period: 2026-01-11 to 2026-02-10 (30 days)
======================================================================

accounting-aws-spoke-dev:
  Internal:  RX 207.3 MB, TX 49.1 MB
  Egress:    RX 4.32 GB, TX 2.85 GB
  Total:     7.42 GB

operations-aws-spoke-k8s:
  Internal:  RX 131.4 MB, TX 230.4 MB
  Egress:    RX 72.67 GB, TX 53.16 GB
  Total:     126.18 GB

----------------------------------------------------------------------
AGGREGATE (all spokes)
----------------------------------------------------------------------
  Internal:  RX 1.73 GB, TX 2.37 GB
  Egress:    RX 354.00 GB, TX 246.60 GB
  Total:     604.70 GB
======================================================================
```

A sample CSV is in [`sample reports/spoke_bandwidth_7d.csv`](sample%20reports/spoke_bandwidth_7d.csv).

### Common Options

| Flag | What it does | Example |
|------|-------------|---------|
| `--days N` | Change the time period (default 30) | `--days 7` |
| `--gateway NAME` | Report on a single spoke | `--gateway my-spoke-gw` |
| `--group-by ATTR` | Roll up by `account`, `region`, `cloud`, `transit`, `vpc`, or `group` | `--group-by account` |
| `--output FORMAT` | `text` (default), `csv`, or `json` | `--output csv > report.csv` |
| `--env PATH` | Path to credentials file (default `.env.avx.local`) | `--env .env` |

---

## FlowIQ Top Talkers Report

Ranks the top external IP addresses your network talks to and the top internal hosts generating that traffic, using FlowIQ flow records.

> Requires FlowIQ to be enabled in CoPilot. Works with both **local egress** and **centralized egress** deployments.

### Sample Output

```
======================================================================
FlowIQ Top Talkers Report
Period: 2026-01-12 to 2026-02-11 (30 days)
======================================================================

TOP 10 DESTINATIONS (Egress)
----------------------------------------------------------------------
    1. 23.185.0.3                  109.04 GB
    2. 47.91.64.21                  61.78 GB
    3. 23.39.42.173                 52.95 GB
    4. 23.39.40.90                  22.80 GB
    5. 216.150.1.1                  21.10 GB

TOP 10 SOURCES (Internal → Egress)
----------------------------------------------------------------------
    1. 10.2.2.100                  140.65 GB
    2. 10.2.2.40                    81.72 GB
    3. 10.2.2.70                    54.83 GB
    4. 10.1.5.46                    25.65 GB
    5. 10.1.5.12                    25.64 GB

Method: FlowIQ field_agg (bidirectional, CIDR-based egress filter)
CoPilot: https://cplt.example.com/monitor/flow-iq/flowiq/overview
Tip: paste any IP into the FlowIQ filter bar to drill down
======================================================================
```

A sample CSV is in [`sample reports/top_talkers_7d.csv`](sample%20reports/top_talkers_7d.csv).

### Common Options

| Flag | What it does | Example |
|------|-------------|---------|
| `--days N` | Change the time period (default 30) | `--days 7` |
| `--top N` | Number of results (default 10) | `--top 20` |
| `--gateway NAME` | Report on a single spoke | `--gateway my-spoke-gw` |
| `--per-spoke` | Show results per spoke instead of aggregate | `--per-spoke` |
| `--group-by ATTR` | Group per-spoke results by `account`, `region`, `cloud`, `transit`, or `vpc` | `--group-by account` |
| `--output FORMAT` | `text` (default), `csv`, or `json` | `--output csv > report.csv` |
| `--env PATH` | Path to credentials file (default `.env.avx.local`) | `--env .env` |

---

## Configuration

Both scripts accept either naming convention in the `.env` file:

```
# Convention A
COPILOT_URL=https://cplt.example.com
USERNAME=admin
PASSWORD=secret

# Convention B
AVIATRIX_COPILOT_IP=cplt.example.com
AVIATRIX_USERNAME=admin
AVIATRIX_PASSWORD=secret
```

---

## How It Works

### Spoke Bandwidth Report — Interface Counters

The script queries three CoPilot APIs:

1. **`GET /api/gateways`** — lists gateways, filters to spokes
2. **`GET /api/cloud-routes/routes/gateways`** — finds tunnel interfaces per gateway
3. **`POST /api/reports/report/performance`** — gets cumulative byte counters per interface

Each spoke has one physical interface (`eth0`) and zero or more tunnel interfaces (`tun-*`). The script computes deltas (max - min) over the period:

```
Internal RX = Σ(tun_rx)                      — bytes from other VPCs into this spoke
Internal TX = Σ(tun_tx)                      — bytes from this spoke to other VPCs
Egress RX   = eth0_rx - Σ(tun_rx + tun_tx)  — non-tunnel bytes arriving at gateway
Egress TX   = eth0_tx - Σ(tun_rx + tun_tx)  — non-tunnel bytes leaving gateway
```

### FlowIQ Top Talkers — Bidirectional Flow Aggregation

Flow records can appear in either direction, so the script runs two queries per scope and merges:

- **Outbound** (RFC1918 → public): external IP = `dst_addr`
- **Inbound** (public → RFC1918): external IP = `src_addr`

Results are merged by IP (summing bytes) and re-ranked. East-west (RFC1918 ↔ RFC1918) and CGNAT (100.64.0.0/10) traffic is excluded.

---

## CSV Column Reference

### spoke_bandwidth_report.py

| Column | Description |
|--------|-------------|
| `gateway` | Gateway name |
| `account_name` | Cloud account |
| `vpc_name` | VPC name |
| `vpc_id` | VPC identifier |
| `vpc_region` | Cloud region |
| `vendor_name` | Cloud provider (AWS, Azure ARM, Gcloud, OCI) |
| `transit_gw_name` | Attached transit gateway |
| `group_name` | Aviatrix gateway group |
| `internal_rx_bytes` / `internal_tx_bytes` | Internal traffic (raw bytes) |
| `egress_rx_bytes` / `egress_tx_bytes` | Egress traffic (raw bytes) |
| `internal_rx` / `internal_tx` | Internal traffic (human-readable) |
| `egress_rx` / `egress_tx` | Egress traffic (human-readable) |

### flowiq_top_talkers.py

| Column | Description |
|--------|-------------|
| `gateway`* | Gateway name (*per-spoke only*) |
| `account_name`* | Cloud account (*per-spoke only*) |
| `vpc_name`* | VPC name (*per-spoke only*) |
| `vpc_id`* | VPC identifier (*per-spoke only*) |
| `vpc_region`* | Cloud region (*per-spoke only*) |
| `vendor_name`* | Cloud provider (*per-spoke only*) |
| `transit_gw_name`* | Attached transit gateway (*per-spoke only*) |
| `group_name`* | Aviatrix gateway group (*per-spoke only*) |
| `rank` | Position in top-N |
| `direction` | `destination` (external IP) or `source` (internal IP) |
| `ip` | IP address |
| `bytes` | Raw byte count |
| `human_readable` | Formatted bytes (e.g., "109.04 GB") |
| `is_cgnat` | Whether IP is in CGNAT range |
| `flowiq_filter` | IP to paste into CoPilot FlowIQ filter bar |
| `copilot_url` | Link to CoPilot FlowIQ page |
