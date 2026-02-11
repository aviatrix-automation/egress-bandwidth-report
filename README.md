# Aviatrix Egress Bandwidth Reports

Two complementary scripts for analyzing spoke gateway egress traffic via Aviatrix CoPilot.

| Script | Method | Best for |
|--------|--------|----------|
| `spoke_bandwidth_report.py` | Interface counters (eth0 - tunnels) | Total Internal vs Egress bandwidth per spoke |
| `flowiq_top_talkers.py` | FlowIQ field aggregation | Top external destinations & internal sources by bytes |

## Requirements

- Python 3.7+
- `requests` library (`pip install requests`)
- Aviatrix CoPilot with API access (FlowIQ enabled for top talkers)

## Configuration

Create a `.env` file (or use `--env` to point to one):

```
# Either naming convention works:
COPILOT_URL=https://cplt.example.com
USERNAME=admin
PASSWORD=secret

# Or:
AVIATRIX_COPILOT_IP=cplt.example.com
AVIATRIX_USERNAME=admin
AVIATRIX_PASSWORD=secret
```

---

# Spoke Gateway Bandwidth Report

Per-spoke-gateway breakdown of **Internal (transit)** vs **Egress (internet)** traffic with RX/TX, using Aviatrix CoPilot interface counters.

```bash
python3 spoke_bandwidth_report.py --env .env.avx.local --days 30
```

## Usage

```bash
# Text report (default) — all spokes, 30 days
python3 spoke_bandwidth_report.py

# CSV for Excel
python3 spoke_bandwidth_report.py --output csv > report.csv 2>/dev/null

# JSON
python3 spoke_bandwidth_report.py --output json

# Custom time period
python3 spoke_bandwidth_report.py --days 7
python3 spoke_bandwidth_report.py --days 90

# Single gateway
python3 spoke_bandwidth_report.py --gateway my-spoke-gw

# Group by cloud account, region, provider, transit, VPC, or gateway group
python3 spoke_bandwidth_report.py --group-by account
python3 spoke_bandwidth_report.py --group-by region
python3 spoke_bandwidth_report.py --group-by cloud
python3 spoke_bandwidth_report.py --group-by transit
python3 spoke_bandwidth_report.py --group-by vpc
python3 spoke_bandwidth_report.py --group-by group
```

## Example Output

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

### Grouped by cloud provider

```
python3 spoke_bandwidth_report.py --group-by cloud
```

```
AWS:  (8 spokes)
  Internal:  RX 1.01 GB, TX 954.2 MB
  Egress:    RX 100.33 GB, TX 71.98 GB
  Total:     174.26 GB
  Gateways:  accounting-aws-spoke-dev, ...

Azure ARM:  (2 spokes)
  Internal:  RX 430.7 MB, TX 1.14 GB
  Egress:    RX 231.18 GB, TX 158.54 GB
  Total:     391.28 GB
  Gateways:  marketing-azure-spoke-all, operations-azure-spoke-k8s
```

## How It Works

### Data Sources

The script queries three CoPilot APIs:

1. **`GET /api/gateways`** — lists all gateways, filters to `$gw_type == "spoke"`
2. **`GET /api/cloud-routes/routes/gateways`** — extracts `tun-*` tunnel interfaces per gateway
3. **`POST /api/reports/report/performance`** — fetches cumulative `rx_bytes`/`tx_bytes` counters per interface

### Calculation

Each spoke gateway has one physical interface (`eth0`) and zero or more tunnel interfaces (`tun-*`). Over the reporting period, the script computes counter deltas (max - min):

```
Internal RX = Σ(tun_rx)                      — bytes from other VPCs into this spoke
Internal TX = Σ(tun_tx)                      — bytes from this spoke to other VPCs
Egress RX   = eth0_rx - Σ(tun_rx + tun_tx)  — non-tunnel bytes arriving at gateway
Egress TX   = eth0_tx - Σ(tun_rx + tun_tx)  — non-tunnel bytes leaving gateway
```

**Why this works**: eth0 carries all traffic — both direct (internet/egress) and encapsulated (tunnel/transit). Tunnel traffic appears on eth0 twice: once as the original packet (VPC-side) and once as the IPsec-encapsulated packet. The tunnel interface counters (`tun_rx`, `tun_tx`) measure only the unencapsulated payload. Subtracting the sum of tunnel counters from each eth0 direction isolates the egress component of that direction.

### Egress RX vs TX delta

In production environments with significant traffic, Egress RX and Egress TX converge to nearly equal values — each represents total egress from its respective counter's perspective. The small remaining delta is IPsec encapsulation overhead (~50-100 bytes/packet). In low-traffic environments, control-plane and broadcast traffic inflates the gap.

## CSV Schema

The CSV output includes all gateway attributes for pivot tables:

| Column | Description |
|--------|-------------|
| `gateway` | Gateway name |
| `account_name` | Cloud account / business unit |
| `vpc_name` | VPC name |
| `vpc_id` | Full VPC identifier |
| `vpc_region` | Cloud region |
| `vendor_name` | Cloud provider (AWS, Azure ARM, Gcloud, OCI) |
| `transit_gw_name` | Attached transit gateway |
| `group_name` | Aviatrix gateway group |
| `internal_rx_bytes` | Internal RX (raw bytes) |
| `internal_tx_bytes` | Internal TX (raw bytes) |
| `egress_rx_bytes` | Egress RX (raw bytes) |
| `egress_tx_bytes` | Egress TX (raw bytes) |
| `internal_rx` | Internal RX (human-readable) |
| `internal_tx` | Internal TX (human-readable) |
| `egress_rx` | Egress RX (human-readable) |
| `egress_tx` | Egress TX (human-readable) |

---

# FlowIQ Top Talkers Report

Top external destinations and internal sources ranked by bytes transferred, using FlowIQ flow records. Answers: "Who is my network talking to on the internet, and which internal hosts are generating that traffic?"

```bash
python3 flowiq_top_talkers.py --env .env.avx.local --days 30
```

## Usage

```bash
# Global top talkers (all spokes, aggregate)
python3 flowiq_top_talkers.py

# Custom time period
python3 flowiq_top_talkers.py --days 7
python3 flowiq_top_talkers.py --days 90

# More results
python3 flowiq_top_talkers.py --top 20

# Single gateway
python3 flowiq_top_talkers.py --gateway marketing-azure-spoke-all

# Per-spoke breakdown
python3 flowiq_top_talkers.py --per-spoke

# Group per-spoke results by attribute
python3 flowiq_top_talkers.py --per-spoke --group-by account
python3 flowiq_top_talkers.py --per-spoke --group-by vpc
python3 flowiq_top_talkers.py --per-spoke --group-by region
python3 flowiq_top_talkers.py --per-spoke --group-by cloud
python3 flowiq_top_talkers.py --per-spoke --group-by transit

# Output formats
python3 flowiq_top_talkers.py --output text    # human-readable (default)
python3 flowiq_top_talkers.py --output csv > top_talkers.csv 2>/dev/null
python3 flowiq_top_talkers.py --output json | python3 -m json.tool
```

## Example Output

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
    ...

TOP 10 SOURCES (Internal → Egress)
----------------------------------------------------------------------
    1. 10.2.2.100                  140.65 GB
    2. 10.2.2.40                    81.72 GB
    3. 10.2.2.70                    54.83 GB
    4. 10.1.5.46                    25.65 GB
    5. 10.1.5.12                    25.64 GB
    ...

Method: FlowIQ field_agg (bidirectional, CIDR-based egress filter)
CoPilot: https://cplt.example.com/monitor/flow-iq/flowiq/overview
Tip: paste any IP into the FlowIQ filter bar to drill down
======================================================================
```

## How It Works

### Bidirectional query

Flow records can appear in either direction — the request might show `10.x → public` while the response shows `public → 10.x`. The script runs two queries and normalizes:

| Query | External IP field | Internal IP field |
|-------|-------------------|-------------------|
| Outbound: RFC1918 src → public dst | `dst_addr` | `src_addr` |
| Inbound: public src → RFC1918 dst | `src_addr` | `dst_addr` |

Results are merged by IP (summing bytes) and re-ranked, so each external IP gets credit for the full conversation volume regardless of flow direction.

### Egress filter (CIDR-based)

```
Outbound: netflow.src_addr:(RFC1918) AND NOT netflow.dst_addr:(RFC1918 OR CGNAT)
Inbound:  NOT netflow.src_addr:(RFC1918 OR CGNAT) AND netflow.dst_addr:(RFC1918)
```

This captures RFC1918 ↔ Internet traffic (true egress), excluding east-west (RFC1918 ↔ RFC1918) and CGNAT (100.64.0.0/10).

### CoPilot links

Each report includes a link to the CoPilot FlowIQ page. CoPilot's FlowIQ UI doesn't support deep-linked filter URLs, but any IP from the report can be pasted directly into the FlowIQ filter bar to drill down into individual flow records.

## CSV Schema

| Column | Description |
|--------|-------------|
| `gateway`* | Gateway name (per-spoke only) |
| `account_name`* | Cloud account (per-spoke only) |
| `vpc_name`* | VPC name (per-spoke only) |
| `vpc_id`* | Full VPC identifier (per-spoke only) |
| `vpc_region`* | Cloud region (per-spoke only) |
| `vendor_name`* | Cloud provider (per-spoke only) |
| `transit_gw_name`* | Attached transit gateway (per-spoke only) |
| `group_name`* | Aviatrix gateway group (per-spoke only) |
| `rank` | Position in top-N |
| `direction` | `destination` (external IP) or `source` (internal IP) |
| `ip` | IP address |
| `bytes` | Raw byte count |
| `human_readable` | Formatted bytes (e.g., "109.04 GB") |
| `is_cgnat` | Whether IP is in CGNAT range (100.64.0.0/10) |
| `flowiq_filter` | IP to paste into CoPilot FlowIQ filter bar |
| `copilot_url` | Link to CoPilot FlowIQ page |

