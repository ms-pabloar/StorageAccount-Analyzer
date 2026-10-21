# Storage Account Analyzer

**Read-only Azure Storage Account cost & performance optimizer with an interactive HTML report.**

**Current release:** v3.1

> **This script is read-only and does NOT create, modify, or delete any Azure resource.** Every recommendation is materialized as a text remediation script that YOU review and execute manually. Your environment is completely unchanged after execution.

---

## What It Does

Deep, parallelized analysis of every Storage Account visible to the authenticated principal, cross-referencing configuration with real Azure Monitor metrics (transactions, capacity, ingress/egress, availability) from the last N days to detect cost-impacting misconfigurations across **16 finding categories**:

| # | Category | Detects |
|---|---|---|
| 1 | **GPv1 Pre-Migration** | Classic StorageV1 accounts (`Kind = Storage`) still to be upgraded to GPv2 |
| 2 | **Tier Optimization** | Wrong access tier for the observed workload (Cool workload projects cheaper on Hot, or vice-versa) |
| 3 | **Small-Blob Penalty** | Avg blob size below the 128 KB minimum billable in Cool/Cold/Archive |
| 4 | **Redundancy** | RA-GRS with zero secondary reads → GRS ; LRS ≥ 500 GB → ZRS upgrade |
| 5 | **Performance Tier** | Premium block blob or FileStorage with low transactions → Standard |
| 6 | **File Service** | Premium file share over-provisioned (used < 30% of quota) |
| 7 | **SFTP Protocol** | SFTP enabled but zero transfers |
| 8 | **Lifecycle Management** | Missing lifecycle policy on large accounts (Hot ≥ 30 GB) |
| 9 | **Archive Tier** | Small blobs on Archive, or high egress from Archive |
| 10 | **Legacy Logging** | Classic Storage Analytics (`$logs` container) still enabled |
| 11 | **Data Protection** | Long soft-delete windows, unbounded versioning, high change-feed retention |
| 12 | **Storage Bloat** *(new in v3.1)* | Multiplicative-model estimate of billed capacity inflation from soft-delete + versioning + PITR |
| 13 | **Blob Inventory** *(new in v3.1)* | Inventory policy enabled — reminds to add lifecycle on the destination container |
| 14 | **Networking** *(new in v3.1)* | Orphan Private Endpoints on idle accounts (~$7.30/mo standing charge each) |
| 15 | **Idle Resources** | Empty or dormant accounts with zero transactions in the window |
| 16 | **Reserved Capacity** | Aggregate 100 TB+ groups per (region + tier + SKU) that qualify for 1-yr / 3-yr reservations |

### Key capabilities

- **Interactive HTML report** — self-contained single file, Microsoft Fluent light theme, tabs for Overview / Findings / Accounts / Methodology.
- **Global scope selector** — filter the whole report by subscription or view the full tenant.
- **Parallel execution** — `ForEach-Object -Parallel` with per-subscription batching. ~5-7× speedup on 700-account tenants.
- **Batched Azure Monitor calls** — 4 API calls per account: UsedCapacity, Availability (isolated so a failure never discards capacity), Transactions + Ingress + Egress batched, and one call for the ApiName split.
- **Validated read/write breakdown** — the ApiName split is classified with the Azure Blob operation-to-price mapping and reconciled against the unsplit transaction total **day by day**. If recent days do not reconcile (Azure Monitor sometimes holds transactions without an ApiName), the longest recent window that does is used and reported; if none reconciles (±5 %), the account shows `n/a` instead of `0`, no tier / replication projection is produced, and a *Data Quality* finding explains why.
- **Self-verification** — the Methodology tab lists, per account, the Azure Monitor total, the classified total, the coverage and the window used; the same data is written to `StorageOptimizer_metrics_validation_<runid>.csv` so the customer can compare it with the portal (Transactions split by API name).
- **HTTP 429 backoff** — automatic 3-attempt retry with 2-8s jitter on Azure Monitor throttling.
- **Transparent cost math** — every recommendation lists the data source, the metrics used, the formula, and the projected savings. `<details>` toggles inside every finding show the raw metrics.
- **Bulk actions card** — findings grouped by (category + normalized recommendation) with a "Download all remediations (.sh)" button so 700-account tenants can act at scale.
- **Snapshot compare** — `-CompareWith <prior.html>` marks each finding as `open`, `new`, or `resolved` and shows month-over-month growth.
- **Reserved Capacity aggregation** — sums capacity per (region + tier + SKU) across the whole tenant and surfaces 100 TB+ opportunities.
- **Capacity growth forecast** — linear regression on the daily `UsedCapacity` series with R² confidence.
- **Optional real-cost annotation** — `-IncludeRealCost` tries `Az.Billing` first, then falls back to `Az.CostManagement`.
- **Customer-negotiated pricing** — `-PricingOverride <path.json>` merges EA / MCA / MPN prices into the model so savings become real, not list-price directional.
- **Dry-run preview** — `-DryRun` prints the plan (subscriptions, accounts, ETA, pricing source) and exits without doing per-account analysis.
- **SHA-256 tamper-evidence** — a sidecar `.sha256` file is written next to the HTML; the report footer shows the exact verify command.
- **Resume from checkpoint** — `-Resume` picks up a partial run without re-analyzing already-processed accounts.

---

## Output Files

The script writes to `$HOME/clouddrive/StorageAccount_Optimizer/` (Cloud Shell persistent share) or the current directory:

| File | Description |
|---|---|
| `StorageOptimizer_<runid>.html` | Interactive report — Overview / Findings / Accounts / Methodology tabs |
| `StorageOptimizer_<runid>.html.sha256` | SHA-256 integrity hash of the report (verify with `Get-FileHash`) |
| `StorageOptimizer_snapshot_<runid>.json` | Structured snapshot for `-CompareWith` on the next run |
| `checkpoint.json` | Incremental checkpoint written after each subscription; used by `-Resume` |

All output is **self-contained** — no external dependencies, no internet required to view the report. Just open the HTML in any modern browser.

---

## Requirements

### Runtime

- **PowerShell 7.0+** (cross-platform; Cloud Shell default)
- **Az PowerShell Modules** — `Az.Accounts`, `Az.Storage`, `Az.Monitor`, `Az.ResourceGraph` (auto-installed if missing). Optional: `Az.Billing`, `Az.CostManagement` for `-IncludeRealCost`.

### Permissions

The script needs **read-only** access.

| Permission | Scope | Required? | Purpose |
|---|---|---|---|
| **Reader** | Each subscription | **Yes** | Enumerate accounts, read blob-service properties, lifecycle policies |
| **Monitoring Reader** | Each subscription | **Yes** | Read Azure Monitor metrics (UsedCapacity, Transactions, Ingress, Egress) |
| **Cost Management Reader** | Each subscription | Optional | `-IncludeRealCost` for actual billed cost annotations |
| **Storage Account Contributor** | Each account | **NO** | The script never writes; this role is NOT required |

> **Minimum viable**: `Reader` + `Monitoring Reader` at the subscription level. Everything else degrades gracefully.

---

## Usage

### Azure Cloud Shell (recommended)

```powershell
# 1. Upload the script via the Cloud Shell "Upload" button.

# 2. Full tenant scan with parallel workers.
./Invoke-StorageAccountOptimizer.ps1 -MetricsDays 30 -ThrottleLimit 16

# 3. Download the report (and its integrity hash) when complete.
download $HOME/clouddrive/StorageAccount_Optimizer/StorageOptimizer_*.html
download $HOME/clouddrive/StorageAccount_Optimizer/StorageOptimizer_*.html.sha256
```

### Preview before running (dry-run)

```powershell
# See how many subscriptions, accounts, and expected minutes BEFORE committing.
./Invoke-StorageAccountOptimizer.ps1 -SubscriptionId '<sub>' -DryRun
```

Output:

```
=========== DRY RUN PLAN ===========
Subscriptions to scan     : 4
Storage accounts found    : 712
  - Modern (analyzed)     : 704
  - Classic ASM (skipped) : 8
  - GPv1 (flagged)        : 27
Metrics window            : 30 days
Parallel workers          : 16
Real-cost lookup          : disabled (list price only)
Pricing source            : Public list price (East US baseline)
Estimated duration        : ~9.2 min
Output folder             : /home/user/clouddrive/StorageAccount_Optimizer
===================================
```

### Common invocations

```powershell
# Recommended for large tenants (700+ accounts).
./Invoke-StorageAccountOptimizer.ps1 `
    -SubscriptionId '<sub>' `
    -MetricsDays 30 `
    -ThrottleLimit 16 `
    -OutputPath "$HOME/report.html"

# Month-over-month diff (adds open/new/resolved badges + growth widget).
./Invoke-StorageAccountOptimizer.ps1 `
    -SubscriptionId '<sub>' `
    -CompareWith "$HOME/last-month.html" `
    -OutputPath "$HOME/this-month.html"

# With customer-negotiated EA / MCA prices (savings become real, not list-price).
./Invoke-StorageAccountOptimizer.ps1 `
    -SubscriptionId '<sub>' `
    -PricingOverride "$HOME/customer-ea-pricing.json" `
    -OutputPath "$HOME/report.html"

# With real billed cost annotations (needs Cost Management Reader).
./Invoke-StorageAccountOptimizer.ps1 -SubscriptionId '<sub>' -IncludeRealCost

# Resume an interrupted run.
./Invoke-StorageAccountOptimizer.ps1 -SubscriptionId '<sub>' -Resume

# Skip metrics for a fast configuration-only scan.
./Invoke-StorageAccountOptimizer.ps1 -SubscriptionId '<sub>' -SkipMetrics
```

### Pricing override file format

```json
{
    "CapacityGBMonth_Hot":  0.0165,
    "CapacityGBMonth_Cool": 0.0088,
    "TxWrite_Hot":          0.045,
    "RedundancyMultiplier": {
        "Standard_RAGRS": 2.20,
        "Standard_GRS":   1.85
    }
}
```

Only keys present in the file override the defaults. Unknown keys are silently ignored — the customer's file does not need to know every internal name.

### All parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-SubscriptionId` | string[] | *(all enabled)* | One or more subscription IDs |
| `-OutputPath` | string | `$HOME/clouddrive/StorageAccount_Optimizer` | Output folder |
| `-MetricsDays` | int (1-90) | `30` | Azure Monitor lookback window |
| `-ThrottleLimit` | int (1-32) | `8` | Parallel workers per subscription batch |
| `-SkipMetrics` | switch | off | Configuration-only scan (skips Azure Monitor) |
| `-Resume` | switch | off | Resume from `checkpoint.json` |
| `-CompareWith` | string | — | Prior snapshot JSON for diff (open / new / resolved badges + growth widget) |
| `-IncludeRealCost` | switch | off | Query `Az.Billing` (Consumption API) then fall back to `Az.CostManagement` Query API |
| `-PricingOverride` | string | — | JSON file overriding one or more pricing table entries |
| `-DryRun` | switch | off | Print the plan and exit without analyzing |

---

## Integrity verification

The script writes a SHA-256 sidecar next to the HTML. To verify the report was not tampered with in transit:

```powershell
Get-FileHash -Algorithm SHA256 './StorageOptimizer_<runid>.html'
# Compare to the value in ./StorageOptimizer_<runid>.html.sha256
```

---

## Safety guarantees

- **Read-only cmdlets only.** The script never calls `Set-Az*`, `Update-Az*`, `Remove-Az*`, `New-Az*` (except the internal `New-Finding`), or `Delete-*`. All remediations are text — you review and execute them manually.
- **No durability downgrades.** GRS / GZRS accounts are NEVER recommended to downgrade to LRS / ZRS purely for cost. The only two SKU changes recommended:
  - **RA-GRS → GRS** when secondary read tx = 0 (marked `safe` — bit-for-bit same durability).
  - **LRS ≥ 500 GB → ZRS** (marked `upgrade` — this *costs more*, not less; it's a resiliency recommendation).
- **Data protection is never disabled.** The script only ever recommends *enabling* soft-delete / versioning / TLS 1.2 minimums.

---

## Known limitations

The audit found no correctness bugs, but these are inherent modeling limits:

1. **List price is directional.** Defaults are Azure public list prices (East US baseline, checked against the Azure Retail Prices API on 2026-10-21). Use `-PricingOverride` to inject the customer's EA / MCA prices.
2. **No blob-level tier distribution.** `UsedCapacity` is account-level. If a policy already moved 40 % of blobs to Archive, tier-projection math still uses the account-level number (conservative simplification).
3. **No cross-region egress cost.** If storage is in East US and consumer is in West Europe, egress bandwidth is not modeled here.
4. **Small-blob penalty derives avg blob size** from `IngressBytes / write-operation count` (PutBlob, PutBlock, AppendBlock, ...). For workloads dominated by block uploads, that is an approximation.
5. **SFTP idle detection uses total transactions.** A polling script without transfers may false-positive; the recommendation says *"validate before disabling"*.
6. **Storage Bloat multiplier** uses documented empirical factors (soft-delete +0.30×N/30, container soft-delete +0.10×N/30, versioning without lifecycle +1.5). Actual inflation depends on write pattern.
7. **Table / Queue / File operations are not priced.** They are reported separately (`NonBlobMonthly`) and excluded from the blob read / write / other meters used in the tier and replication projections.
8. **Cool / Cold data retrieval is estimated from `Egress`.** The metric also includes egress within Azure, so it is an upper-bound proxy for GB read.
9. **Changing the default access tier is itself billed** (write operations when moving to a cooler tier, read operations plus retrieval when moving to a warmer one for blobs with an inferred tier). That one-time cost is not part of the monthly savings.

---

## Version history

- **v3.2 (script v1.1.0)** — Fixed the ApiName parsing that reported 0 reads / 0 writes (the dimension name is `Metadatavalues[].Name.Value`, not `.Name`); billing-accurate operation classification; breakdown reconciled against the total and withheld (`n/a`) when unavailable; metric failures surfaced instead of swallowed; added "other operations" and Cool/Cold data-retrieval cost; refreshed list prices and redundancy multipliers; `-PricingOverride` now reaches the parallel workers; failed / classic accounts listed in the report banner; dollar amounts restored in finding text; overlapping savings no longer double counted.
- **v3.1** — Storage Bloat / Blob Inventory / Orphan PE findings, HTTP 429 backoff with jitter, `-PricingOverride`, `-DryRun`, SHA-256 sidecar (paradox-free), `Az.CostManagement` fallback, ETA in progress bar. 30+ automated audit checks.
- **v3.0** — Parallel `ForEach-Object -Parallel` with per-subscription batching, batched Get-AzMetric (3 calls instead of 6), scope selector on the Overview screen.
- **v2.x** — Bulk actions card, remediation `.sh` bundle, snapshot compare, capacity forecast widget, real-cost via `Az.Billing`, checkpoint + `-Resume`.
- **v1.x** — Initial 15 findings (tier, redundancy, lifecycle, data protection, idle) with structured recommendations.

---

## License

[MIT](LICENSE) — © 2026 Pablo Araya Fonseca
