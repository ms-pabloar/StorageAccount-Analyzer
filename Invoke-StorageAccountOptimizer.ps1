<#
.SYNOPSIS
    Azure Storage Account Cost Optimizer & Configuration Validator (read-only).

.DESCRIPTION
    Deep, read-only analysis of every Storage Account visible to the currently
    authenticated principal. Cross-references configuration with real Azure Monitor
    metrics (transactions, capacity, ingress/egress, availability) from the last N
    days to detect cost-impacting misconfigurations such as:

        * Cool / Cold / Archive tiers with high transactional traffic  -> Hot tier
        * Hot tier with cold, dormant data                             -> Cool / Cold
        * GRS / RA-GRS with no cross-region read activity              -> LRS / ZRS
        * LRS on production-critical accounts (large capacity)         -> ZRS / GZRS
        * Legacy StorageV1 / Classic accounts                          -> StorageV2
        * Premium performance without matching workload                -> Standard
        * Missing lifecycle management on large accounts
        * Excessive soft-delete retention windows
        * Blob versioning without cleanup policy
        * Public blob / container anonymous access enabled
        * HTTPS not enforced, outdated TLS versions
        * Firewall wide open (public network access)
        * Missing diagnostic settings
        * Empty / idle / orphan storage accounts

    Results are rendered to a self-contained interactive HTML report (Tailwind +
    Chart.js + SheetJS) with per-section Excel export, saved to the Cloud Shell
    persistent share (~/clouddrive) so it is retained and easy to download.

    The script is strictly READ-ONLY: it does NOT create, modify or delete any
    Azure resource.

.PARAMETER SubscriptionId
    Optional list of subscription IDs to scope the assessment. Defaults to every
    subscription reachable by the current account.

.PARAMETER OutputPath
    Optional folder to write the HTML report. Defaults to ~/clouddrive (Cloud
    Shell persistent share) if available, otherwise the current directory.

.PARAMETER MetricsDays
    Look-back window in days for Azure Monitor metrics. Default: 30 (max 93 for
    1-hour granularity in most namespaces).

.PARAMETER ThrottleLimit
    Maximum parallel accounts processed at once. Default: 8.

.PARAMETER SkipMetrics
    Skip Azure Monitor metric collection (much faster, but disables usage-based
    recommendations). Default: metrics enabled.

.EXAMPLE
    # Cloud Shell one-liner
    PS> ./Invoke-StorageAccountOptimizer.ps1

.EXAMPLE
    PS> ./Invoke-StorageAccountOptimizer.ps1 -SubscriptionId 'xxx','yyy' -MetricsDays 60

.NOTES
    Author  : DSE-AI FY27
    Version : 1.0.0
    Modules : Az.Accounts, Az.Storage, Az.Monitor, Az.ResourceGraph (>= latest)
    Runtime : PowerShell 7.2+ (Cloud Shell default)
#>

[CmdletBinding()]
param(
    [string[]] $SubscriptionId,
    [string]   $OutputPath,
    [ValidateRange(1, 90)]
    [int]      $MetricsDays = 30,
    [ValidateRange(1, 32)]
    [int]      $ThrottleLimit = 8,
    [switch]   $SkipMetrics,
    # Resume a previous interrupted run using the checkpoint file in $OutputPath.
    # For very large tenants (700+ accounts), a partial run can be picked up
    # without re-analyzing the accounts already processed.
    [switch]   $Resume,
    # Compare against a previously-saved snapshot JSON (adds resolved/new indicators
    # in the report). Provide the full path to StorageOptimizer_snapshot_<runid>.json.
    [string]   $CompareWith,
    # Best-effort: pull real 30-day cost per account from Azure Cost Management.
    # Requires appropriate Cost Management reader role. Silently degrades if unavailable.
    [switch]   $IncludeRealCost,
    # Optional JSON file overriding one or more entries in $script:Pricing. Use this
    # to inject EA / MCA / MPN negotiated prices so the savings numbers become real
    # rather than "list-price directional". Only keys present in the file are overridden.
    [string]   $PricingOverride,
    # Discover subscriptions + accounts and print a preview (subscription count,
    # account count, expected duration) then EXIT without doing per-account analysis.
    [switch]   $DryRun
)

#region ------------------------------------------------------------- Bootstrap

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'Continue'
$script:StartTime      = Get-Date
$script:ScriptVersion  = '1.0.0'

function Write-Log {
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK', 'STEP')] [string] $Level = 'INFO'
    )
    $ts     = (Get-Date).ToString('HH:mm:ss')
    $color  = @{ INFO='Gray'; WARN='Yellow'; ERROR='Red'; OK='Green'; STEP='Cyan' }[$Level]
    Write-Host ("[{0}] [{1}] {2}" -f $ts, $Level, $Message) -ForegroundColor $color
}

function Install-RequiredModule {
    param([string[]] $Name)
    foreach ($n in $Name) {
        if (-not (Get-Module -ListAvailable -Name $n)) {
            Write-Log "Installing module $n (CurrentUser scope)..." STEP
            Install-Module -Name $n -Scope CurrentUser -Force -AllowClobber -Repository PSGallery | Out-Null
        }
        Import-Module $n -ErrorAction Stop -Force -DisableNameChecking | Out-Null
    }
}

Write-Log "Azure Storage Account Optimizer v$script:ScriptVersion" STEP
Write-Log "Verifying required modules..." STEP
Install-RequiredModule -Name @('Az.Accounts', 'Az.Storage', 'Az.Monitor', 'Az.ResourceGraph')

# Ensure we have an authenticated context (Cloud Shell already provides one).
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx -or -not $ctx.Account) {
    Write-Log "No Azure context detected. Prompting for interactive login..." WARN
    Connect-AzAccount -UseDeviceAuthentication | Out-Null
    $ctx = Get-AzContext
}
Write-Log "Authenticated as: $($ctx.Account.Id)  |  Tenant: $($ctx.Tenant.Id)" OK

# Resolve subscriptions
if ($SubscriptionId) {
    $subs = Get-AzSubscription -TenantId $ctx.Tenant.Id | Where-Object { $_.Id -in $SubscriptionId }
} else {
    $subs = Get-AzSubscription -TenantId $ctx.Tenant.Id | Where-Object { $_.State -eq 'Enabled' }
}
if (-not $subs) { throw "No enabled subscriptions available for the current account." }
Write-Log ("Scope: {0} subscription(s)" -f $subs.Count) OK

# Resolve output folder (prefer Cloud Shell persistent share)
if (-not $OutputPath) {
    $cloudDrive = Join-Path $HOME 'clouddrive'
    if (Test-Path $cloudDrive) {
        $OutputPath = Join-Path $cloudDrive 'StorageAccount_Optimizer'
    } else {
        $OutputPath = Join-Path (Get-Location) 'StorageAccount_Optimizer'
    }
}
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
Write-Log "Output folder: $OutputPath" INFO

#endregion Bootstrap

#region ------------------------------------------------------------- Discovery

Write-Log "Discovering storage accounts via Azure Resource Graph..." STEP

$graphQuery = @"
resources
| where type =~ 'microsoft.storage/storageaccounts' or type =~ 'microsoft.classicstorage/storageaccounts'
| project id, name, type, kind, sku=tostring(sku.name), tier=tostring(sku.tier),
          location, resourceGroup, subscriptionId, tags,
          properties, creationTime=tostring(properties.creationTime)
"@

$allAccounts = @()
$subIds = $subs.Id
# Resource Graph paginates at 1000 rows (Skip must be >= 1, so we omit it on the first call).
$skip = 0
do {
    if ($skip -eq 0) {
        $page = Search-AzGraph -Query $graphQuery -Subscription $subIds -First 1000
    } else {
        $page = Search-AzGraph -Query $graphQuery -Subscription $subIds -First 1000 -Skip $skip
    }
    if ($page) { $allAccounts += $page }
    $skip += 1000
} while ($page -and $page.Count -eq 1000)

Write-Log ("Found {0} storage account(s)" -f $allAccounts.Count) OK

if (-not $allAccounts) {
    Write-Log "Nothing to analyze. Exiting." WARN
    return
}

# -DryRun: preview the plan (subscription count, account count, expected duration,
# pricing source, real-cost mode) and exit without doing per-account analysis.
if ($DryRun) {
    $classicN  = ($allAccounts | Where-Object { $_.type -like '*classicstorage*' }).Count
    $modernN   = $allAccounts.Count - $classicN
    $gpv1N     = ($allAccounts | Where-Object { $_.kind -eq 'Storage' }).Count
    $subN      = ($allAccounts | Select-Object -ExpandProperty subscriptionId -Unique).Count
    # Empirical model derived from the parallelization work: ~2.2s/account at throttle=1,
    # scaling near-linearly with -ThrottleLimit up to ~16. Add 5% for report rendering.
    $secPerAcct = 2.2
    $etaSec     = [math]::Ceiling(($modernN * $secPerAcct) / [math]::Max(1,$ThrottleLimit) * 1.05)
    $etaMin     = [math]::Round($etaSec / 60.0, 1)

    Write-Host ""
    Write-Host "=========== DRY RUN PLAN ===========" -ForegroundColor Yellow
    Write-Host ("Subscriptions to scan     : {0}" -f $subN)
    Write-Host ("Storage accounts found    : {0}" -f $allAccounts.Count)
    Write-Host ("  - Modern (analyzed)     : {0}" -f $modernN)
    Write-Host ("  - Classic ASM (skipped) : {0}" -f $classicN)
    Write-Host ("  - GPv1 (flagged)        : {0}" -f $gpv1N)
    Write-Host ("Metrics window            : {0} days" -f $MetricsDays)
    Write-Host ("Parallel workers          : {0}" -f $ThrottleLimit)
    Write-Host ("Real-cost lookup          : {0}" -f $(if ($IncludeRealCost) { 'Az.Billing / Az.CostManagement' } else { 'disabled (list price only)' }))
    Write-Host ("Pricing source            : {0}" -f $(if ($script:PricingOverrideApplied) { "OVERRIDE from $($script:PricingOverrideApplied.Path) ($($script:PricingOverrideApplied.KeysApplied) keys)" } else { 'Public list price (East US baseline)' }))
    Write-Host ("Estimated duration        : ~{0} min" -f $etaMin)
    Write-Host ("Output folder             : {0}" -f $OutputPath)
    Write-Host "===================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Log "Dry-run complete. Re-run without -DryRun to execute the analysis." OK
    return
}

#endregion Discovery

#region ------------------------------------------------------------- Analysis helpers

# Approx public list prices (USD, East US, Hot LRS) used ONLY as directional
# indicators for potential-savings estimates. Real billing depends on region,
# reservations, EA/CSP discounts, etc. The report clearly labels these as
# ESTIMATES.
$script:Pricing = [ordered]@{
    CapacityGBMonth_Hot     = 0.0184
    CapacityGBMonth_Cool    = 0.0100
    CapacityGBMonth_Cold    = 0.0036
    CapacityGBMonth_Archive = 0.00099
    # per 10,000 ops
    TxWrite_Hot     = 0.0500
    TxWrite_Cool    = 0.1000
    TxWrite_Cold    = 0.1800
    TxWrite_Archive = 0.1000
    TxRead_Hot      = 0.0040
    TxRead_Cool     = 0.0100
    TxRead_Cold     = 0.0100
    TxRead_Archive  = 6.5000
    # Cool / Cold billing minimums per PUT operation (blob smaller than this is billed as if it were this big).
    # Source: Azure Blob Storage pricing pages. This is the trap that hit the BOLD case.
    MinBillableBlobKB_Cool = 128
    MinBillableBlobKB_Cold = 128
    # Minimum retention days per tier. If you delete or move data before this window
    # elapses, you are billed for the FULL window regardless. Hot has no minimum.
    MinRetentionDays_Cool    = 30
    MinRetentionDays_Cold    = 90
    MinRetentionDays_Archive = 180
    # Azure Storage Reserved Capacity: 1-year and 3-year commitments with published
    # discount ranges. Minimum eligible size = 100 TB per (region, tier, redundancy).
    ReservedCapacity_MinTB     = 100
    ReservedCapacity_1YrDiscount = 0.20
    ReservedCapacity_3YrDiscount = 0.38
    # Redundancy uplift multipliers vs LRS capacity price
    RedundancyMultiplier = @{
        'Standard_LRS'   = 1.00
        'Standard_ZRS'   = 1.25
        'Standard_GRS'   = 2.00
        'Standard_RAGRS' = 2.50
        'Standard_GZRS'  = 2.50
        'Standard_RAGZRS'= 3.13
        'Premium_LRS'    = 1.00
        'Premium_ZRS'    = 1.25
    }
    # Geo-write transaction multiplier: geo-redundant SKUs replicate every write, so write ops
    # are billed against BOTH primary + secondary regions (~2x for GRS/RAGRS/GZRS/RAGZRS).
    GeoWriteMultiplier = @{
        'Standard_LRS'   = 1.00
        'Standard_ZRS'   = 1.00
        'Standard_GRS'   = 2.00
        'Standard_RAGRS' = 2.00
        'Standard_GZRS'  = 2.00
        'Standard_RAGZRS'= 2.00
        'Premium_LRS'    = 1.00
        'Premium_ZRS'    = 1.00
    }
}

# Apply -PricingOverride: shallow merge of top-level keys, and one level deep for
# the RedundancyMultiplier / GeoWriteMultiplier nested tables. Silently ignores
# unknown keys so the customer's file does not need to know all internal names.
if ($PricingOverride) {
    if (-not (Test-Path -LiteralPath $PricingOverride)) {
        throw "PricingOverride file not found: $PricingOverride"
    }
    try {
        $override = Get-Content -Raw -LiteralPath $PricingOverride | ConvertFrom-Json
        $applied = 0
        foreach ($prop in $override.PSObject.Properties) {
            $k = $prop.Name; $v = $prop.Value
            if ($script:Pricing.Contains($k)) {
                if ($v -is [pscustomobject] -and $script:Pricing[$k] -is [hashtable]) {
                    foreach ($sub in $v.PSObject.Properties) {
                        if ($script:Pricing[$k].ContainsKey($sub.Name)) { $script:Pricing[$k][$sub.Name] = [double]$sub.Value; $applied++ }
                    }
                } else {
                    $script:Pricing[$k] = $v; $applied++
                }
            }
        }
        $script:PricingOverrideApplied = @{ Path = (Resolve-Path $PricingOverride).Path; KeysApplied = $applied }
    } catch { throw "Failed to load PricingOverride: $($_.Exception.Message)" }
}

function Get-TierCapacityPrice {
    param([string] $Tier)
    switch ($Tier) {
        'Hot'     { return $script:Pricing.CapacityGBMonth_Hot }
        'Cool'    { return $script:Pricing.CapacityGBMonth_Cool }
        'Cold'    { return $script:Pricing.CapacityGBMonth_Cold }
        'Archive' { return $script:Pricing.CapacityGBMonth_Archive }
        default   { return $script:Pricing.CapacityGBMonth_Hot }
    }
}

function Get-TierCostBreakdown {
    <#
        Estimates the monthly $ cost of a Standard StorageV2 account at a given tier,
        given observed capacity (GB), monthly reads/writes, monthly ingress bytes
        (for the 128 KB minimum-billable penalty) and the redundancy SKU.

        Also estimates the "early-deletion penalty" for Cool/Cold tiers: any data
        moved into Cool/Cold and then deleted or moved back before the minimum
        retention window (Cool=30d, Cold=90d) is still billed for the full window.

        Returns a pscustomobject with per-line-item breakdown.
    #>
    param(
        [Parameter(Mandatory)] [ValidateSet('Hot','Cool','Cold')] [string] $Tier,
        [double] $CapacityGB      = 0,
        [double] $MonthlyReads    = 0,
        [double] $MonthlyWrites   = 0,
        [double] $MonthlyIngressBytes = 0,
        [double] $MonthlyEgressBytes  = 0,       # used to estimate delete/overwrite churn
        [string] $Sku             = 'Standard_LRS'
    )

    $capPrice      = Get-TierCapacityPrice $Tier
    $redundMult    = if ($script:Pricing.RedundancyMultiplier[$Sku])   { $script:Pricing.RedundancyMultiplier[$Sku] }   else { 1.0 }
    $geoWriteMult  = if ($script:Pricing.GeoWriteMultiplier[$Sku])     { $script:Pricing.GeoWriteMultiplier[$Sku] }     else { 1.0 }

    $capacityCost  = $CapacityGB * $capPrice * $redundMult

    $writePrice = switch ($Tier) { 'Hot' { $script:Pricing.TxWrite_Hot } 'Cool' { $script:Pricing.TxWrite_Cool } 'Cold' { $script:Pricing.TxWrite_Cold } }
    $readPrice  = switch ($Tier) { 'Hot' { $script:Pricing.TxRead_Hot  } 'Cool' { $script:Pricing.TxRead_Cool  } 'Cold' { $script:Pricing.TxRead_Cold  } }

    $writeOpsCost = ($MonthlyWrites / 10000.0) * $writePrice * $geoWriteMult
    $readOpsCost  = ($MonthlyReads  / 10000.0) * $readPrice

    # 128 KB minimum-billable-blob penalty for Cool/Cold write CAPACITY.
    # We estimate the average blob size written in the month from Ingress / write ops.
    $smallWritePenalty = 0.0
    $avgBlobKB         = $null
    if ($Tier -in @('Cool','Cold') -and $MonthlyWrites -gt 0 -and $MonthlyIngressBytes -gt 0) {
        $avgBlobKB = [math]::Round(($MonthlyIngressBytes / $MonthlyWrites) / 1024.0, 2)
        $minKB     = if ($Tier -eq 'Cool') { $script:Pricing.MinBillableBlobKB_Cool } else { $script:Pricing.MinBillableBlobKB_Cold }
        if ($avgBlobKB -lt $minKB -and $avgBlobKB -gt 0) {
            $extraKB    = ($minKB - $avgBlobKB) * $MonthlyWrites
            $extraGB    = $extraKB / (1024.0 * 1024.0)
            $smallWritePenalty = $extraGB * $capPrice * $redundMult
        }
    }

    # Minimum-retention penalty (Cool = 30 days, Cold = 90 days).
    # We approximate "churn rate" as monthly Ingress / current capacity: if a
    # sizeable fraction of the data is being rewritten each month, chunks are
    # likely being deleted / overwritten before their retention window elapses.
    # Penalty = (churned GB) * (retention_days / 30) * capacity_price. This is
    # an approximation; the real penalty depends on the exact overwrite pattern.
    $retentionPenalty = 0.0
    $churnRate        = 0.0
    if ($Tier -in @('Cool','Cold') -and $CapacityGB -gt 0 -and $MonthlyIngressBytes -gt 0) {
        $ingressGB  = $MonthlyIngressBytes / 1GB
        $churnRate  = [math]::Round($ingressGB / $CapacityGB, 2)  # 1.0 = full-capacity rewrite per month
        if ($churnRate -gt 0.1) {                                 # ignore trivial churn
            $retDays = if ($Tier -eq 'Cool') { $script:Pricing.MinRetentionDays_Cool } else { $script:Pricing.MinRetentionDays_Cold }
            $churnedGB = [math]::Min($ingressGB, $CapacityGB * 2)  # cap at 2x safety
            $retentionPenalty = $churnedGB * ($retDays / 30.0) * $capPrice * $redundMult * 0.5   # 0.5 = only half of churn typically hits the penalty
        }
    }

    [pscustomobject]@{
        Tier               = $Tier
        Sku                = $Sku
        CapacityGB         = [math]::Round($CapacityGB, 2)
        AvgBlobSizeKB      = $avgBlobKB
        ChurnRate          = $churnRate
        CapacityCost       = [math]::Round($capacityCost, 2)
        ReadOpsCost        = [math]::Round($readOpsCost, 2)
        WriteOpsCost       = [math]::Round($writeOpsCost, 2)
        SmallWritePenalty  = [math]::Round($smallWritePenalty, 2)
        RetentionPenalty   = [math]::Round($retentionPenalty, 2)
        TotalCost          = [math]::Round($capacityCost + $readOpsCost + $writeOpsCost + $smallWritePenalty + $retentionPenalty, 2)
    }
}

function Get-TierRecommendationReason {
    <#
        Returns a structured, plain-language explanation of WHY a specific tier is
        the cheapest for the observed workload. Includes:
         - DataSource:     where the numbers came from (Azure Monitor metric names)
         - Observations:   plain-language facts about the workload
         - Interpretation: why that pattern favors the recommended tier
         - Projections:    hashtable of monthly $ per tier
         - Action:         concrete "do X" statement
         - Reason:         single-line flat text for tooltips / exports
    #>
    param(
        [Parameter(Mandatory)] $Projections,           # array of 3 Get-TierCostBreakdown outputs (Hot,Cool,Cold)
        [Parameter(Mandatory)] [string] $CurrentTier,
        [double] $MonthlyReads   = 0,
        [double] $MonthlyWrites  = 0,
        [double] $CapacityGB     = 0,
        [int]    $MetricsDays    = 30
    )
    $sorted    = $Projections | Sort-Object TotalCost
    $best      = $sorted[0]
    $current   = $Projections | Where-Object Tier -eq $CurrentTier | Select-Object -First 1
    if (-not $current) { $current = $best }

    $delta       = [math]::Round($current.TotalCost - $best.TotalCost, 2)
    $mTx         = $MonthlyReads + $MonthlyWrites
    $txPerGB     = if ($CapacityGB -gt 0) { $mTx / $CapacityGB } else { 0 }
    $writeShare  = if ($mTx -gt 0) { $MonthlyWrites / $mTx } else { 0 }
    $avgKB       = $best.AvgBlobSizeKB

    # --- Data source: short one-liner. Full metric definition lives in $metricsUsed
    #     so the UI can hide it under a "View metrics used" toggle.
    $dataSource = "Azure Monitor metrics from the last $MetricsDays days, extrapolated to a 30-day month."

    # --- Observations: plain-language bullets, no API-name noise ---
    $obs = New-Object System.Collections.Generic.List[string]
    $obs.Add(("Data stored: {0:N2} GB." -f $CapacityGB))
    $obs.Add(("Read operations: {0:N0} per month." -f $MonthlyReads))
    $obs.Add(("Write operations: {0:N0} per month." -f $MonthlyWrites))
    if ($avgKB -and $MonthlyWrites -gt 0) {
        $obs.Add(("Average size per written blob: {0:N1} KB (Ingress bytes divided by write operations)." -f $avgKB))
    }
    if ($CapacityGB -gt 0 -and $mTx -gt 0) {
        $obs.Add(("Access intensity: {0:N1} operations per GB of stored data." -f $txPerGB))
    }
    if ($writeShare -gt 0) {
        $obs.Add(("Write share: {0:P0} of all operations are writes." -f $writeShare))
    }

    # --- Full metric reference (Azure Monitor names + ApiName filters). Rendered
    #     under a collapsible <details> block by the JS so it does not clutter the
    #     main explanation.
    $metricsUsed = @(
        "Namespace: Microsoft.Storage/storageAccounts",
        "UsedCapacity - aggregation Average, last daily value in the observation window.",
        "Transactions - aggregation Total, split by the ApiName dimension:",
        "  * Read APIs classified: GetBlob, ListBlobs, GetBlobProperties, GetBlobMetadata, GetContainerProperties, GetContainerACL, GetTableEntity, QueryEntities, QueryTable, GetMessage, PeekMessage.",
        "  * Write APIs classified: PutBlob, PutBlock, PutBlockList, SetBlobProperties, SetBlobMetadata, SetBlobTier, WriteFile, CreateFile, InsertEntity, UpdateEntity, MergeEntity, PutMessage, CreateContainer, SetContainerACL, SetContainerMetadata.",
        "  * Anything else is counted as Other and excluded from the read/write ratios above.",
        "Ingress - aggregation Total, in bytes. Used to estimate average written blob size.",
        "Observation window: last $MetricsDays days. Monthly totals shown in the report are the observed sums scaled to 30 days."
    )

    # --- Interpretation (why the observed pattern favors the recommended tier) ---
    $interp = switch ($best.Tier) {
        'Hot' {
            $t = "The workload is chatty: with {0:N0} operations per month against only {1:N2} GB of stored data, each operation matters more than each GB. Cool and Cold tiers charge roughly {2}x per read and {3}-{4}x per write compared to Hot, which more than cancels out their cheaper capacity." -f $mTx,$CapacityGB,
                [math]::Round($script:Pricing.TxRead_Cool/$script:Pricing.TxRead_Hot,1),
                [math]::Round($script:Pricing.TxWrite_Cool/$script:Pricing.TxWrite_Hot,1),
                [math]::Round($script:Pricing.TxWrite_Cold/$script:Pricing.TxWrite_Hot,1)
            if ($writeShare -ge 0.5 -and $mTx -gt 100000) {
                $t += " On top of that, this account is write-heavy ({0:P0} of ops are writes), which is exactly the pattern the Cool/Cold surcharges hit hardest." -f $writeShare
            }
            if ($avgKB -and $avgKB -lt 128) {
                $t += " And because the average written blob is only ~{0:N1} KB, well below the 128 KB minimum billable size in Cool/Cold, each small PUT would be billed as if it were 128 KB in those tiers — inflating their capacity totals even further." -f $avgKB
            }
            $t
        }
        'Cool' {
            "The workload is dormant: {0:N2} GB of stored data with only {1:N0} operations per month. At that access rate, Cool's roughly 1.8x cheaper capacity price outweighs its 2x-2.5x higher per-operation price. In practice: the account pays mostly for storage, not for API calls." -f $CapacityGB,$mTx
        }
        'Cold' {
            "The workload is essentially archival: {0:N2} GB of stored data with only {1:N0} operations per month. Cold's roughly 5x cheaper capacity price wins by a wide margin at this access level, even after accounting for the higher per-operation charges and the 128 KB write minimum." -f $CapacityGB,$mTx
        }
    }

    # --- Projections hashtable (so the UI can render a compact table) ---
    $proj = @{}
    foreach ($p in $Projections) { $proj[$p.Tier] = [math]::Round($p.TotalCost, 2) }

    # --- Concrete action ---
    $action = if ($delta -gt 0) {
        'Change the account default access tier from ''{0}'' to ''{1}''. At the observed usage pattern this saves approximately ${2:N2}/month. If the account holds a mix of hot and cold data, keep the default at ''Hot'' and add a lifecycle rule to demote inactive blobs instead of changing the account-level tier.' -f $CurrentTier,$best.Tier,$delta
    } else {
        "Keep the current tier '$CurrentTier'. It is already the cheapest option for the observed usage pattern."
    }

    # --- Flat single-line reason (used in the badge tooltip and the finding description) ---
    $reasonFlat = ("Based on {0}. {1} {2} {3}" -f $dataSource, ($obs -join ' '), $interp, $action)

    [pscustomobject]@{
        RecommendedTier = $best.Tier
        DeltaUsd        = $delta
        DataSource      = $dataSource
        Observations    = @($obs)
        MetricsUsed     = @($metricsUsed)
        Interpretation  = $interp
        Projections     = $proj
        Action          = $action
        Reason          = $reasonFlat
    }
}

function Get-SkuRecommendationReason {
    <#
        Same structured output shape as Get-TierRecommendationReason, but for the
        redundancy / replication SKU (LRS / ZRS / GRS / RA-GRS).

        Guardrails:
          - Never recommend a durability DOWNGRADE (GRS -> LRS/ZRS) purely on cost.
            That is a business decision the customer must make explicitly.
          - Safe recommendation: RA-GRS -> GRS (same durability, saves the read-access
            uplift when the '-secondary' endpoint is not consumed).
          - Informational suggestions for LRS-on-large-accounts (upgrade to ZRS) and
            for GRS/GZRS-on-small accounts (consider ZRS if no cross-region DR need).
    #>
    param(
        [Parameter(Mandatory)] [string] $CurrentSku,
        [Parameter(Mandatory)] [string] $CurrentTier,
        [double] $CapacityGB    = 0,
        [double] $MonthlyReads  = 0,
        [double] $MonthlyWrites = 0,
        [double] $MonthlyIngressBytes = 0,
        [int]    $MetricsDays   = 30
    )

    # Only Standard SKUs are analyzed (Premium is a different pricing model).
    $skuOptions = @('Standard_LRS','Standard_ZRS','Standard_GRS','Standard_RAGRS')
    if ($CurrentSku -notin $skuOptions -and -not $CurrentSku.StartsWith('Standard_')) {
        return $null
    }

    # Compute total monthly cost for the account at each replication option using the current tier.
    $breakdowns = @{}
    foreach ($sku in $skuOptions) {
        $breakdowns[$sku] = Get-TierCostBreakdown -Tier $CurrentTier -CapacityGB $CapacityGB `
            -MonthlyReads $MonthlyReads -MonthlyWrites $MonthlyWrites -MonthlyIngressBytes $MonthlyIngressBytes -Sku $sku
    }

    # ---- Decide recommendation with durability guardrails ----
    $recommended = $CurrentSku
    $rationale   = "Current replication '$CurrentSku' is aligned with the observed workload; no safe change identified without explicit DR review."
    $confidence  = 'informational'

    # Safe: RA-GRS / RA-GZRS -> GRS / GZRS (same durability, drop unused read-access uplift)
    if ($CurrentSku -in @('Standard_RAGRS','Standard_RAGZRS')) {
        $recommended = if ($CurrentSku -eq 'Standard_RAGRS') { 'Standard_GRS' } else { 'Standard_GZRS' }
        $rationale = "This account is on $CurrentSku, which is ~25% more expensive than $recommended. The extra cost only pays for the ability to READ from the '-secondary' regional endpoint. If your application does not read from that secondary endpoint, this uplift is wasted. Switching to $recommended keeps the same durability (async replica in the paired region) and the same failover capability, but stops billing you for a read feature you're not using."
        $confidence = 'safe'
    }

    # Informational: LRS on large accounts -> suggest ZRS as durability upgrade (not cost)
    elseif ($CurrentSku -eq 'Standard_LRS' -and $CapacityGB -ge 500) {
        $recommended = 'Standard_ZRS'
        $rationale = "This account is on $CurrentSku (single-datacenter durability) and holds a significant volume of data ($([math]::Round($CapacityGB,2)) GB). LRS survives disk and node failures, but a full datacenter outage would take the data offline. This is a DURABILITY upgrade suggestion, not a cost saving: Standard_ZRS is ~25% more expensive than LRS but survives an entire Availability Zone loss."
        $confidence = 'upgrade'
    }

    # ---- Structured explanation ----
    $dataSource = "Azure Monitor metrics from the last $MetricsDays days, combined with the Azure Storage public list prices for each replication option (East US baseline)."

    $obs = New-Object System.Collections.Generic.List[string]
    $obs.Add(("Current replication: $CurrentSku."))
    $obs.Add(("Data stored: {0:N2} GB." -f $CapacityGB))
    $obs.Add(("Write operations: {0:N0} per month. Geo-redundant SKUs replicate every write to the paired region, effectively doubling the write-ops line item." -f $MonthlyWrites))

    $metricsUsed = @(
        "Namespace: Microsoft.Storage/storageAccounts",
        "UsedCapacity - aggregation Average, last daily value in the observation window.",
        "Transactions - aggregation Total, split by ApiName to separate read from write operations.",
        "Ingress - aggregation Total, in bytes.",
        "SKU: read from the 'sku.name' property returned by Get-AzStorageAccount.",
        "Observation window: last $MetricsDays days.",
        "Cost per SKU is capacity * tier price * redundancy multiplier + write ops * write price * geo-write multiplier + read ops * read price + small-blob penalty."
    )

    $proj = @{}
    foreach ($k in $skuOptions) { $proj[$k] = $breakdowns[$k].TotalCost }

    $costLines = ($skuOptions | ForEach-Object { '{0}=${1:N2}' -f $_,$breakdowns[$_].TotalCost }) -join ' | '

    $currentTotal = $breakdowns[$CurrentSku].TotalCost
    $recTotal     = $breakdowns[$recommended].TotalCost
    $delta        = [math]::Round($currentTotal - $recTotal, 2)

    $action = if ($confidence -eq 'safe' -and $delta -gt 0) {
        'Change the replication SKU from ''{0}'' to ''{1}''. At the observed usage pattern this saves approximately ${2:N2}/month with NO reduction in durability (same async replica in the paired region). Only the ''-secondary'' read endpoint is removed; make sure no consumer is reading from that endpoint before applying (search your codebase / config for ''.secondary.'' URLs).' -f $CurrentSku,$recommended,$delta
    } elseif ($confidence -eq 'upgrade') {
        'Consider upgrading to ''{0}'' for zone-level durability (survives a full Availability Zone loss). This ADDS approximately ${1:N2}/month, so it is a business decision: only worth it if the workload cannot tolerate a datacenter-scoped outage.' -f $recommended,([math]::Abs($delta))
    } else {
        "Keep the current replication '$CurrentSku'. Do NOT downgrade a geo-redundant SKU to LRS/ZRS based on cost alone — that would remove the ability to survive a regional outage. If you know this workload does not need cross-region durability, review it with your DR/RPO stakeholders before changing."
    }

    $interp = $rationale + ' Monthly cost projections at your current tier and usage: ' + $costLines + '.'

    $reasonFlat = ("Based on {0}. {1} {2} {3}" -f $dataSource, ($obs -join ' '), $interp, $action)

    [pscustomobject]@{
        RecommendedSku = $recommended
        DeltaUsd       = $delta
        Confidence     = $confidence
        DataSource     = $dataSource
        Observations   = @($obs)
        MetricsUsed    = @($metricsUsed)
        Interpretation = $interp
        Projections    = $proj
        Action         = $action
        Reason         = $reasonFlat
    }
}

function Get-RealAccountCost {
    <#
        Best-effort: query real ACTUAL cost for the storage account. Tries Az.Billing
        (Consumption API) first, falls back to Az.CostManagement (Cost Management Query API)
        which is available to a broader set of RBAC roles (e.g. Cost Management Reader
        without EA enrollment access). Silently returns $null if both paths fail.
    #>
    param(
        [Parameter(Mandatory)] [string] $ResourceId
    )
    if (-not $IncludeRealCost) { return $null }

    $end   = (Get-Date).ToUniversalTime().Date
    $start = $end.AddDays(-30)

    # Path 1: Az.Billing / Consumption API (works in EA-billed tenants).
    if (Get-Module -ListAvailable -Name Az.Billing) {
        try {
            Import-Module Az.Billing -ErrorAction SilentlyContinue | Out-Null
            $rows = Get-AzConsumptionUsageDetail -InstanceId $ResourceId -StartDate $start -EndDate $end -ErrorAction Stop
            if ($rows) {
                $sum = ($rows | Measure-Object -Property PretaxCost -Sum).Sum
                return [pscustomobject]@{
                    Last30DaysUsd = [math]::Round([double]$sum, 2)
                    Currency      = ($rows | Select-Object -First 1).Currency
                    Source        = 'Azure Consumption API (Az.Billing)'
                }
            }
        } catch { Write-Verbose "Consumption API failed for $ResourceId : $($_.Exception.Message)" }
    }

    # Path 2: Az.CostManagement / Query API (works for Cost Management Reader roles
    # without EA enrollment access; covers MCA + CSP + Sponsorship tenants).
    if (Get-Module -ListAvailable -Name Az.CostManagement) {
        try {
            Import-Module Az.CostManagement -ErrorAction SilentlyContinue | Out-Null
            $subId = ($ResourceId -split '/')[2]
            $scope = "/subscriptions/$subId"
            $body = @{
                type      = 'ActualCost'
                timeframe = 'Custom'
                timePeriod = @{ from = $start.ToString('o'); to = $end.ToString('o') }
                dataset   = @{
                    granularity = 'None'
                    aggregation = @{ totalCost = @{ name = 'PreTaxCost'; function = 'Sum' } }
                    filter      = @{ dimensions = @{ name = 'ResourceId'; operator = 'In'; values = @($ResourceId) } }
                }
            }
            $q = Invoke-AzCostManagementQuery -Scope $scope -Type 'ActualCost' -Timeframe 'Custom' `
                -TimePeriodFrom $start -TimePeriodTo $end `
                -DatasetGranularity 'None' `
                -DatasetAggregation @{ totalCost = @{ name = 'PreTaxCost'; function = 'Sum' } } `
                -DatasetFilter @{ dimensions = @{ name = 'ResourceId'; operator = 'In'; values = @($ResourceId) } } `
                -ErrorAction Stop
            if ($q -and $q.Row) {
                $cost = [double]($q.Row[0][0])
                $curr = if ($q.Column.Count -gt 1) { $q.Row[0][1] } else { 'USD' }
                return [pscustomobject]@{
                    Last30DaysUsd = [math]::Round($cost, 2)
                    Currency      = $curr
                    Source        = 'Cost Management Query API (Az.CostManagement)'
                }
            }
        } catch { Write-Verbose "Cost Management Query failed for $ResourceId : $($_.Exception.Message)" }
    }

    return $null
}

function Get-CapacityForecast {
    <#
        Fits a simple linear regression to the daily UsedCapacity time series and
        projects capacity at horizons of 6 and 12 months. Returns null if not
        enough data points or if the trend is flat / decreasing.

        Input: array of doubles (one point per day, chronological).
    #>
    param([double[]] $DailyCapacityGB)

    if (-not $DailyCapacityGB -or $DailyCapacityGB.Count -lt 7) { return $null }

    $n     = $DailyCapacityGB.Count
    $xs    = 0..($n - 1)
    $meanX = ($xs | Measure-Object -Average).Average
    $meanY = ($DailyCapacityGB | Measure-Object -Average).Average

    $sxy = 0.0; $sxx = 0.0
    for ($i = 0; $i -lt $n; $i++) {
        $dx  = $xs[$i] - $meanX
        $dy  = $DailyCapacityGB[$i] - $meanY
        $sxy += $dx * $dy
        $sxx += $dx * $dx
    }
    if ($sxx -eq 0) { return $null }

    $slopePerDay = $sxy / $sxx
    $intercept   = $meanY - $slopePerDay * $meanX
    $todayFit    = $intercept + $slopePerDay * ($n - 1)
    $forecast6mo = $todayFit + ($slopePerDay * 30 * 6)
    $forecast12mo = $todayFit + ($slopePerDay * 30 * 12)

    # Coefficient of determination (R^2) — helps callers judge trust.
    $ssTot = 0.0; $ssRes = 0.0
    for ($i = 0; $i -lt $n; $i++) {
        $fit    = $intercept + $slopePerDay * $xs[$i]
        $ssTot += [math]::Pow($DailyCapacityGB[$i] - $meanY, 2)
        $ssRes += [math]::Pow($DailyCapacityGB[$i] - $fit, 2)
    }
    $r2 = if ($ssTot -eq 0) { 1.0 } else { [math]::Max(0.0, 1.0 - ($ssRes / $ssTot)) }

    [pscustomobject]@{
        DailyGrowthGB   = [math]::Round($slopePerDay, 3)
        MonthlyGrowthGB = [math]::Round($slopePerDay * 30, 2)
        CurrentGB       = [math]::Round($todayFit, 2)
        Forecast6MoGB   = [math]::Round([math]::Max(0, $forecast6mo), 2)
        Forecast12MoGB  = [math]::Round([math]::Max(0, $forecast12mo), 2)
        RSquared        = [math]::Round($r2, 3)
        Direction       = if ($slopePerDay -gt 0.01) { 'growing' } elseif ($slopePerDay -lt -0.01) { 'shrinking' } else { 'stable' }
        DataPoints      = $n
    }
}

function Get-AccountMetrics {
    param(
        [Parameter(Mandatory)] [string] $ResourceId,
        [int]  $Days = 30,
        $DefaultProfile
    )
    if ($SkipMetrics) { return $null }

    $end   = (Get-Date).ToUniversalTime()
    $start = $end.AddDays(-1 * $Days)
    # Common cmdlet parameters used on every Get-AzMetric call; -DefaultProfile keeps
    # parallel runspaces bound to the caller's Az context without re-authenticating.
    $common = @{ ResourceId = $ResourceId; TimeGrain = ([TimeSpan]'1.00:00:00'); StartTime = $start; EndTime = $end; WarningAction = 'SilentlyContinue'; ErrorAction = 'Stop' }
    if ($DefaultProfile) { $common['DefaultProfile'] = $DefaultProfile }

    # Retry Get-AzMetric on HTTP 429 / TooManyRequests (up to 3 attempts, 2-8s jitter).
    # Azure Monitor throttles at ~1000 reads/hour per resource type when many parallel
    # workers hammer it, which happens on 700+ accounts with -ThrottleLimit >= 16.
    $invoke = {
        param($extra)
        $attempt = 0
        while ($true) {
            $attempt++
            try { return Get-AzMetric @common @extra }
            catch {
                $msg = $_.Exception.Message
                $isThrottle = ($msg -match '429|TooManyRequests|throttled|rate.?limit')
                if ($isThrottle -and $attempt -lt 3) {
                    Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 8)
                    continue
                }
                throw
            }
        }
    }

    $out = [ordered]@{
        UsedCapacityBytes = $null
        UsedCapacityDailyGB = @()
        Transactions      = 0
        ReadTx            = 0
        WriteTx           = 0
        OtherTx           = 0
        IngressBytes      = 0
        EgressBytes       = 0
        Availability      = $null
        HasActivity       = $false
    }

    # Call #1: Average aggregation for UsedCapacity (daily series) + Availability.
    try {
        $avgSet = & $invoke @{ MetricName = @('UsedCapacity','Availability'); AggregationType = 'Average' }
        foreach ($m in $avgSet) {
            $vals = $m.Data | Where-Object { $null -ne $_.Average }
            switch ($m.Name.Value) {
                'UsedCapacity' {
                    if ($vals) {
                        $out.UsedCapacityBytes   = ($vals | Select-Object -Last 1).Average
                        $out.UsedCapacityDailyGB = @($vals | ForEach-Object { [math]::Round($_.Average / 1GB, 3) })
                    }
                }
                'Availability' {
                    if ($vals) { $out.Availability = [math]::Round((($vals | Measure-Object Average -Average).Average), 3) }
                }
            }
        }
    } catch { Write-Verbose ("Metric(avg) error on {0}: {1}" -f $ResourceId, $_.Exception.Message) }

    # Call #2: Total aggregation for Transactions + Ingress + Egress in a single batched call.
    try {
        $totSet = & $invoke @{ MetricName = @('Transactions','Ingress','Egress'); AggregationType = 'Total' }
        foreach ($m in $totSet) {
            $sum = ($m.Data | Measure-Object Total -Sum).Sum
            if ($null -eq $sum) { continue }
            switch ($m.Name.Value) {
                'Transactions' { $out.Transactions = [int64] $sum }
                'Ingress'      { $out.IngressBytes = [int64] $sum }
                'Egress'       { $out.EgressBytes  = [int64] $sum }
            }
        }
    } catch { Write-Verbose ("Metric(total) error on {0}: {1}" -f $ResourceId, $_.Exception.Message) }

    # Call #3: Transactions split by ApiName dimension to derive read/write mix.
    try {
        $split = & $invoke @{ MetricName = 'Transactions'; AggregationType = 'Total'; MetricFilter = "ApiName eq '*'" }
        foreach ($ts in $split.Timeseries) {
            $api = ($ts.Metadatavalues | Where-Object Name -Match 'ApiName').Value
            $sum = ($ts.Data | Measure-Object Total -Sum).Sum
            if ($null -eq $sum) { continue }
            if ($api -match '^(GetBlob|ReadFile|ListBlobs|GetBlobProperties|GetBlobMetadata|GetContainerProperties|GetContainerACL|GetTableEntity|QueryEntities|QueryTable|GetMessage|PeekMessage)') {
                $out.ReadTx += [int64] $sum
            } elseif ($api -match '^(PutBlob|PutBlock|PutBlockList|SetBlobProperties|SetBlobMetadata|SetBlobTier|WriteFile|CreateFile|SetFileProperties|InsertEntity|UpdateEntity|MergeEntity|InsertOrMergeEntity|InsertOrReplaceEntity|PutMessage|SetQueueACL|CreateContainer|SetContainerACL|SetContainerMetadata)') {
                $out.WriteTx += [int64] $sum
            } else {
                $out.OtherTx += [int64] $sum
            }
        }
    } catch { }

    $out.HasActivity = ($out.Transactions -gt 0) -or (($out.IngressBytes + $out.EgressBytes) -gt 0)
    return $out
}

function New-Finding {
    param(
        [Parameter(Mandatory)] [ValidateSet('Cost','Performance')] [string] $Pillar,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [ValidateSet('Critical','High','Medium','Low','Informational')] [string] $Severity,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Description,
        [Parameter(Mandatory)] [string] $Recommendation,
        [string]   $Impact = '',
        [string]   $Evidence = '',
        [double]   $EstimatedMonthlySavingsUsd = 0,
        [string]   $VerifyCommand = '',
        [string]   $RemediationScript = '',
        [string]   $RemediationGroupKey = ''
    )
    [pscustomobject]@{
        Pillar                     = $Pillar
        Category                   = $Category
        Severity                   = $Severity
        Title                      = $Title
        Description                = $Description
        Recommendation             = $Recommendation
        Impact                     = $Impact
        Evidence                   = $Evidence
        EstimatedMonthlySavingsUsd = [math]::Round($EstimatedMonthlySavingsUsd, 2)
        VerifyCommand              = $VerifyCommand
        RemediationScript          = $RemediationScript
        RemediationGroupKey        = $RemediationGroupKey
    }
}

function Invoke-StorageAccountAnalysis {
    param(
        [Parameter(Mandatory)] $Graph,   # ResourceGraph row
        [Parameter(Mandatory)] $SaObj,   # full SA object from Get-AzStorageAccount
        [Parameter(Mandatory)] $Blob,    # blob service properties (may be $null)
        $Metrics                          # metrics hash (may be $null)
    )

    $findings = New-Object System.Collections.Generic.List[object]
    $sku      = $SaObj.Sku.Name
    $kind     = $SaObj.Kind
    $tier     = $SaObj.AccessTier
    if (-not $tier) { $tier = 'Hot' }

    $capBytes = 0
    if ($Metrics -and $Metrics.UsedCapacityBytes) { $capBytes = [double]$Metrics.UsedCapacityBytes }
    $capGB = [math]::Round($capBytes / 1GB, 2)

    $txTotal = if ($Metrics) { [int64]$Metrics.Transactions } else { 0 }
    $txRead  = if ($Metrics) { [int64]$Metrics.ReadTx }       else { 0 }
    $txWrite = if ($Metrics) { [int64]$Metrics.WriteTx }      else { 0 }

    # Monthly extrapolation factor
    $factor  = 30.0 / [double]$MetricsDays
    $mTx     = $txTotal * $factor
    $mRead   = $txRead  * $factor
    $mWrite  = $txWrite * $factor
    $mIngBytes = if ($Metrics) { [double]$Metrics.IngressBytes * $factor } else { 0 }

    # ---- 1. GPv1 pre-migration guidance -------------------------------------
    # Not a Modernization audit finding — this is a Cost warning for the customer
    # BEFORE they upgrade to GPv2 (the BOLD scenario: GPv1 -> GPv2 default Cool tier
    # + high tx + geo redundancy multiplied costs 100x+).
    if ($kind -in @('Storage','BlobStorage')) {
        $findings.Add((New-Finding `
            -Pillar 'Cost' -Category 'GPv1 Pre-Migration' -Severity 'High' `
            -Title "Account is still GPv1 (kind=$kind) — validate tier & redundancy BEFORE upgrading" `
            -Description ("This account uses the legacy GPv1 pricing model. GPv2 uses tier-based per-transaction pricing that is 2-5x higher than GPv1 for Cool/Cold tiers. If GPv2 is enabled with an access tier that does not match the workload's read/write pattern, the monthly bill can jump by 10x-150x (real customer case). Observed monthly load: ~{0:N0} tx ({1:N0} reads + {2:N0} writes), capacity {3:N2} GB, SKU={4}." -f $mTx,$mRead,$mWrite,$capGB,$sku) `
            -Recommendation "Before enabling GPv2: (1) confirm the correct access tier for the actual workload using the 'Tier optimization' finding for this account; (2) if writes/reads are high-frequency, keep Hot tier at all cost — do NOT accept the GPv2 default; (3) if SKU is geo-redundant (GRS/RA-GRS/GZRS/RA-GZRS), remember every WRITE op is also billed for the secondary region; (4) run this optimizer BEFORE and AFTER migration and compare." `
            -Impact "GPv1 -> GPv2 with the wrong tier is the #1 cause of unexpected storage bill spikes in the field." `
            -Evidence ("Kind=$kind | SKU=$sku | Tier=$tier | Tx/mo={0:N0} | Cap={1:N2} GB" -f $mTx,$capGB) `
            -VerifyCommand ("az storage account show -n {0} -g {1} --query 'kind'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
    }

    # ---- 2. Tier optimization based on observed cost math -------------------
    # For GPv2 accounts: compute what the monthly cost WOULD be at Hot / Cool / Cold
    # using the ACTUAL observed read+write+capacity, then recommend the tier with the
    # lowest total. This is what turns a generic "wrong tier" alert into a defensible,
    # numeric recommendation.
    if (-not $SkipMetrics -and $Metrics -and $kind -eq 'StorageV2' -and $capGB -ge 0.01) {
        $hot  = Get-TierCostBreakdown -Tier Hot  -CapacityGB $capGB -MonthlyReads $mRead -MonthlyWrites $mWrite -MonthlyIngressBytes $mIngBytes -Sku $sku
        $cool = Get-TierCostBreakdown -Tier Cool -CapacityGB $capGB -MonthlyReads $mRead -MonthlyWrites $mWrite -MonthlyIngressBytes $mIngBytes -Sku $sku
        $cold = Get-TierCostBreakdown -Tier Cold -CapacityGB $capGB -MonthlyReads $mRead -MonthlyWrites $mWrite -MonthlyIngressBytes $mIngBytes -Sku $sku
        $projections = @($hot,$cool,$cold)
        $cheapest = $projections | Sort-Object TotalCost | Select-Object -First 1
        $current  = switch ($tier) { 'Hot' { $hot } 'Cool' { $cool } 'Cold' { $cold } default { $hot } }
        $delta    = [math]::Round($current.TotalCost - $cheapest.TotalCost, 2)
        $reasonInfo = Get-TierRecommendationReason -Projections $projections -CurrentTier $tier -MonthlyReads $mRead -MonthlyWrites $mWrite -CapacityGB $capGB -MetricsDays $MetricsDays

        # Always fire a finding when the recommendation differs from the current tier,
        # regardless of $ savings magnitude. This way the "Recommended: → X" badge in
        # the UI is always backed by a click-through explanation.
        if ($cheapest.Tier -ne $tier) {
            $sev = if ($delta -ge 50) { 'Critical' } elseif ($delta -ge 10) { 'High' } elseif ($delta -ge 3) { 'Medium' } elseif ($delta -ge 0.5) { 'Low' } else { 'Informational' }
            $sizeNote = ''
            if ($current.AvgBlobSizeKB -and $current.AvgBlobSizeKB -lt 128 -and $tier -in @('Cool','Cold')) {
                $sizeNote = (" | Avg written blob ~{0:N1} KB (< 128 KB, triggers minimum-billable-blob penalty of \${1:N2}/mo)" -f $current.AvgBlobSizeKB,$current.SmallWritePenalty)
            }

            # Structured, sectioned description so the customer sees "where the numbers come from"
            # and "what they mean" separately, without wading through one long paragraph.
            $descBuilder = New-Object System.Text.StringBuilder
            $null = $descBuilder.AppendLine("Data source. $($reasonInfo.DataSource)")
            $null = $descBuilder.AppendLine('')
            $null = $descBuilder.AppendLine('Observed pattern:')
            foreach ($o in $reasonInfo.Observations) { $null = $descBuilder.AppendLine("  - $o") }
            $null = $descBuilder.AppendLine('')
            $null = $descBuilder.AppendLine("Why this matters. $($reasonInfo.Interpretation)")
            $null = $descBuilder.AppendLine('')
            $null = $descBuilder.AppendLine(('Cost projection at your usage (capacity + read ops + write ops + Cool/Cold small-blob penalty): Hot=${0:N2} | Cool=${1:N2} | Cold=${2:N2}.' -f $hot.TotalCost,$cool.TotalCost,$cold.TotalCost))
            $description = $descBuilder.ToString()

            $findings.Add((New-Finding `
                -Pillar 'Cost' -Category 'Tier Optimization' -Severity $sev `
                -Title ("Tier '$tier' is not the cheapest for this workload — recommend '{0}' (save ~\${1:N2}/mo)" -f $cheapest.Tier,$delta) `
                -Description $description `
                -Recommendation ($reasonInfo.Action) `
                -Impact "Access-tier mismatch is the #1 driver of Storage bill anomalies after GPv1->GPv2 migrations. The mismatch multiplies every future read and write." `
                -Evidence ("Current tier=$tier | Cap={0:N2} GB | Reads/mo={1:N0} | Writes/mo={2:N0} | SKU=$sku | Hot=\${3:N2} Cool=\${4:N2} Cold=\${5:N2}{6}" -f $capGB,$mRead,$mWrite,$hot.TotalCost,$cool.TotalCost,$cold.TotalCost,$sizeNote) `
                -EstimatedMonthlySavingsUsd $delta `
                -VerifyCommand ("az storage account show -n {0} -g {1} --query 'accessTier'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName) `
                -RemediationGroupKey ("tier:{0}->{1}" -f $tier,$cheapest.Tier) `
                -RemediationScript (("az storage account update -n {0} -g {1} --access-tier {2}") -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName,$cheapest.Tier)))
        }

        # ---- 2b. Small-blob write penalty (BOLD trap) --------------------------
        # Independent finding so it also fires when the customer refuses to change tier
        # and just needs to know why Cool/Cold is expensive at their blob size.
        if ($tier -in @('Cool','Cold') -and $current.AvgBlobSizeKB -ne $null -and $current.AvgBlobSizeKB -lt 128 -and $current.SmallWritePenalty -gt 1) {
            $findings.Add((New-Finding `
                -Pillar 'Cost' -Category 'Small-Blob Penalty' -Severity 'High' `
                -Title ("Small-blob writes on '$tier' tier are billed against a 128 KB minimum") `
                -Description ("Every PUT/write of a blob smaller than 128 KB is billed for CAPACITY as if it were 128 KB in the Cool and Cold tiers. Estimated average written blob size is {0:N1} KB, which inflates monthly capacity billing by approximately \${1:N2}." -f $current.AvgBlobSizeKB,$current.SmallWritePenalty) `
                -Recommendation "Either (1) move the account back to Hot tier (no minimum-blob penalty), or (2) batch the small writes into larger objects (e.g., append blobs, batching to >=128 KB per PUT), or (3) route the small-object workload to a separate Hot-tier account and keep only the large archived objects in Cool/Cold." `
                -Impact "This penalty is invisible in the portal's default cost views and is the hidden multiplier behind many GPv1->GPv2 Cool-tier bill spikes." `
                -Evidence ("Tier=$tier | Writes/mo={0:N0} | Avg blob size~{1:N1} KB | Min billable=128 KB | Extra capacity cost~\${2:N2}/mo" -f $mWrite,$current.AvgBlobSizeKB,$current.SmallWritePenalty) `
                -EstimatedMonthlySavingsUsd $current.SmallWritePenalty `
                -VerifyCommand ("az monitor metrics list --resource {0} --metric Transactions Ingress --interval PT1H" -f $SaObj.Id) `
                -RemediationGroupKey ("tier:{0}->Hot" -f $tier) `
                -RemediationScript (("# Small-blob penalty on '{2}' tier. Either move the account to Hot OR add lifecycle to batch small writes.`n# Option 1 (simplest): revert to Hot tier.`naz storage account update -n {0} -g {1} --access-tier Hot") -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName,$tier)))
        }
    }

    # ---- 3. Redundancy vs. real usage ---------------------------------------
    if ($sku -like '*GRS*' -or $sku -eq 'Standard_RAGRS' -or $sku -eq 'Standard_RAGZRS') {
        # Estimate the transactional overhead: geo-redundant SKUs replicate every write,
        # so each write op is billed against BOTH regions (~2x).
        $writePrice   = switch ($tier) { 'Hot' { $script:Pricing.TxWrite_Hot } 'Cool' { $script:Pricing.TxWrite_Cool } 'Cold' { $script:Pricing.TxWrite_Cold } default { $script:Pricing.TxWrite_Hot } }
        $geoWriteExtra = ($mWrite / 10000.0) * $writePrice  # the extra region-billed write cost
        if (-not $SkipMetrics -and $Metrics -and $capGB -ge 1) {
            $baseCap = $capGB * (Get-TierCapacityPrice $tier)
            $mult    = $script:Pricing.RedundancyMultiplier[$sku]
            if (-not $mult) { $mult = 2.0 }
            $extra   = $baseCap * ($mult - 1)
            if ($sku -in @('Standard_RAGRS','Standard_RAGZRS')) {
                $findings.Add((New-Finding `
                    -Pillar 'Cost' -Category 'Redundancy' -Severity 'Medium' `
                    -Title "Read-access geo-redundancy ($sku) — verify secondary reads are actually used" `
                    -Description ("RA-GRS / RA-GZRS costs ~25% more than GRS/GZRS. If the application never reads from the '-secondary' endpoint, that read-access uplift is wasted. Additionally, every write operation is billed against the secondary region, adding ~\${0:N2}/mo in geo-write transaction charges at the observed write rate ({1:N0} writes/month)." -f $geoWriteExtra,$mWrite) `
                    -Recommendation "If no consumer reads from the '-secondary' endpoint, switch to GRS (or GZRS) to remove the read-access uplift. For write-heavy workloads without a strict cross-region DR requirement, consider ZRS (zonal, ~25% uplift over LRS) instead of GRS (~100% uplift + geo-write ops)." `
                    -Impact "Read-access uplift is billed even when the secondary endpoint is never contacted. Geo-write ops charge is invisible in the portal's default cost split." `
                    -Evidence ("SKU=$sku | Capacity={0:N2} GB | Writes/mo={1:N0} | Extra geo-write cost≈\${2:N2}/mo" -f $capGB,$mWrite,$geoWriteExtra) `
                    -EstimatedMonthlySavingsUsd ($baseCap * 0.25) `
                    -VerifyCommand ("az storage account show -n {0} -g {1} --query 'sku.name'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName) `
                    -RemediationGroupKey ("sku:{0}->{1}" -f $sku,($sku -replace 'RAG','G')) `
                    -RemediationScript (("az storage account update -n {0} -g {1} --sku {2}") -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName,($sku -replace 'RAG','G'))))
            } else {
                $findings.Add((New-Finding `
                    -Pillar 'Cost' -Category 'Redundancy' -Severity 'Low' `
                    -Title "Geo-redundant SKU ($sku) — confirm DR requirement" `
                    -Description ("GRS/GZRS doubles capacity cost vs. LRS/ZRS AND doubles write-transaction cost (every write is replicated to the secondary region). At the observed write rate ({0:N0} writes/month) that is ~\${1:N2}/mo in extra transaction charges alone, on top of ~\${2:N2}/mo in extra capacity charges." -f $mWrite,$geoWriteExtra,$extra) `
                    -Recommendation "Only keep GRS/GZRS if the workload has a real cross-region DR/RPO requirement. For non-critical workloads (dev/test, logs, cache, ephemeral data), use LRS or ZRS. For zonal HA without cross-region cost, use ZRS." `
                    -Impact "Geo-redundancy roughly doubles both the capacity AND the write-transaction bill." `
                    -Evidence ("SKU=$sku | Capacity={0:N2} GB | Writes/mo={1:N0} | Extra capacity≈\${2:N2}/mo | Extra geo-write≈\${3:N2}/mo" -f $capGB,$mWrite,$extra,$geoWriteExtra) `
                    -EstimatedMonthlySavingsUsd ($extra * 0.5 + $geoWriteExtra * 0.5) `
                    -VerifyCommand ("az storage account show -n {0} -g {1} --query 'sku.name'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName) `
                    -RemediationGroupKey "sku:review-dr-requirement" `
                    -RemediationScript (("# DR / RPO review required. Only apply after confirming no cross-region durability requirement.`n# az storage account update -n {0} -g {1} --sku Standard_LRS  # or Standard_ZRS for AZ-durable") -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
            }
        }
    }
    if ($sku -eq 'Standard_LRS' -and $capGB -ge 500) {
        $findings.Add((New-Finding `
            -Pillar 'Cost' -Category 'Redundancy' -Severity 'Medium' `
            -Title "Large production-size account on LRS (single-datacenter durability)" `
            -Description ("Account holds {0:N2} GB on LRS. LRS survives disk failures but not a datacenter outage." -f $capGB) `
            -Recommendation "If this account backs production data, evaluate ZRS (zone-redundant) — only ~25% more than LRS and survives an entire AZ loss." `
            -Impact "Datacenter-level incidents cause data unavailability with LRS." `
            -Evidence ("SKU=$sku | Capacity={0:N2} GB" -f $capGB) `
            -VerifyCommand ("az storage account show -n {0} -g {1} --query 'sku.name'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName) `
            -RemediationGroupKey "sku:LRS->ZRS" `
            -RemediationScript (("az storage account update -n {0} -g {1} --sku Standard_ZRS") -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
    }

    # ---- 3. Legacy account kinds & Diagnostic-settings checks removed:
    #        This tool is scoped to Cost / Performance / Security optimization,
    #        not to broader modernization or observability auditing.

    # ---- 4. Premium performance sanity check --------------------------------
    if ($sku -like 'Premium_*' -and $kind -eq 'StorageV2') {
        if (-not $SkipMetrics -and $mTx -lt 100000 -and $capGB -ge 1) {
            $findings.Add((New-Finding `
                -Pillar 'Performance' -Category 'Performance Tier' -Severity 'Medium' `
                -Title "Premium performance tier with modest workload" `
                -Description ("Premium block blob / general-purpose Premium accounts have ~10x the base capacity price of Standard. Observed load: ~{0:N0} tx/month, {1:N2} GB." -f $mTx,$capGB) `
                -Recommendation "If sub-millisecond latency or very high IOPS is not required, migrate the workload to a Standard StorageV2 account." `
                -Impact "Premium capacity price is billed regardless of utilization." `
                -Evidence ("SKU=$sku | Kind=$kind | Tx/mo=$([math]::Round($mTx))" -f $mTx) `
                -VerifyCommand ("az storage account show -n {0} -g {1} --query '[sku.name, kind]'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
        }
    }

    # ---- 4b. Premium FileStorage under-utilized -----------------------------
    #        Premium file shares cost ~5-10x standard. If the observed transaction
    #        rate on the account is very low, the workload is over-provisioned.
    if ($kind -eq 'FileStorage' -and $sku -like 'Premium_*') {
        if (-not $SkipMetrics -and $mTx -lt 500000 -and $capGB -ge 1) {
            $findings.Add((New-Finding `
                -Pillar 'Performance' -Category 'File Service' -Severity 'Medium' `
                -Title "Premium FileStorage account with low transaction volume" `
                -Description ("Premium file shares are billed at a flat ~15c/GB-month for provisioned capacity, regardless of usage. Observed monthly transactions: ~{0:N0}. If your workload does not need <1ms latency, Standard FileStorage is roughly 8-10x cheaper." -f $mTx) `
                -Recommendation "Migrate the file share to a Standard StorageV2 account (transaction-optimized or Hot). Premium is only justified for IOPS-bound workloads (SQL data files, transactional workloads that require SSD-backed shares)." `
                -Impact "Premium capacity is billed regardless of utilization; a large idle Premium share can cost hundreds of USD/mo unnecessarily." `
                -Evidence ("SKU=$sku | Kind=$kind | Tx/mo=$([math]::Round($mTx))") `
                -VerifyCommand ("az storage account show -n {0} -g {1} --query '[sku.name, kind]'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
        }
    }

    # ---- 4c. Premium File Share over-provisioning (share-level) --------------
    #         Premium file shares bill you for PROVISIONED capacity (ShareQuota),
    #         not used capacity. A 5 TiB provisioned share with 500 GB used still
    #         costs the full 5 TiB * ~$0.16/GB-month = ~$800/mo.
    if ($kind -eq 'FileStorage' -and $sku -like 'Premium_*') {
        try {
            $shares = Get-AzRmStorageShare -ResourceGroupName $SaObj.ResourceGroupName -StorageAccountName $SaObj.StorageAccountName -ErrorAction Stop
            foreach ($sh in $shares) {
                if ($null -eq $sh.QuotaGiB -or $sh.QuotaGiB -le 0) { continue }
                $usedGB = if ($sh.ShareUsageBytes) { [math]::Round($sh.ShareUsageBytes / 1GB, 2) } else { 0 }
                $utilization = $usedGB / [double]$sh.QuotaGiB
                if ($sh.QuotaGiB -ge 500 -and $utilization -lt 0.4) {
                    $suggestedGiB = [math]::Max(100, [int][math]::Ceiling(($usedGB * 1.3) / 100) * 100)   # 30% headroom, round to 100 GiB
                    $wastedGiB    = $sh.QuotaGiB - $suggestedGiB
                    $wastedUsd    = $wastedGiB * 0.16
                    $findings.Add((New-Finding `
                        -Pillar 'Cost' -Category 'File Service' -Severity $(if ($wastedUsd -ge 200) { 'High' } else { 'Medium' }) `
                        -Title ("Premium file share '{0}' over-provisioned ({1} GiB used of {2} GiB)" -f $sh.Name,$usedGB,$sh.QuotaGiB) `
                        -Description ("Premium file shares bill for provisioned capacity (ShareQuota), not for used bytes. This share is provisioned at {0} GiB but only {1} GiB is in use ({2:P0} utilization).`n`nBilling model: {0} GiB x ~`$0.16/GiB-month = ~`$$([math]::Round($sh.QuotaGiB * 0.16, 2))/month regardless of usage." -f $sh.QuotaGiB,$usedGB,$utilization) `
                        -Recommendation ("Reduce the provisioned quota to about {0} GiB (30% headroom over current usage). Provisioned capacity can be shrunk at any time via 'az storage share-rm update --quota'." -f $suggestedGiB) `
                        -Impact "Provisioned capacity is billed monthly regardless of usage — one of the highest-ROI single fixes on Premium file shares." `
                        -Evidence ("Share='$($sh.Name)' | Provisioned=$($sh.QuotaGiB) GiB | Used=$usedGB GiB | Utilization=$([math]::Round($utilization*100,1))%") `
                        -EstimatedMonthlySavingsUsd ([math]::Round($wastedUsd, 2)) `
                        -VerifyCommand ("az storage share-rm show -n {0} -g {1} --storage-account {2} --query '[quota, shareUsageBytes]'" -f $sh.Name,$SaObj.ResourceGroupName,$SaObj.StorageAccountName) `
                        -RemediationGroupKey ("fileshare:right-size") `
                        -RemediationScript ("az storage share-rm update -n {0} -g {1} --storage-account {2} --quota {3}" -f $sh.Name,$SaObj.ResourceGroupName,$SaObj.StorageAccountName,$suggestedGiB)))
                }
            }
        } catch {
            Write-Verbose "File share enumeration failed for $($SaObj.StorageAccountName): $($_.Exception.Message)"
        }
    }

    # ---- 4d. SFTP protocol enabled but unused --------------------------------
    #         Enabling SFTP on a storage account adds a fixed ~$0.30/hour charge
    #         (~$219/month) regardless of any transfer volume. If SFTP is turned
    #         on but the workload does not need it, that is pure waste.
    $sftpEnabled = $false
    try { $sftpEnabled = [bool]$SaObj.EnableSftp } catch { }
    if ($sftpEnabled) {
        $sev = if ($mTx -lt 10000) { 'High' } else { 'Medium' }
        $findings.Add((New-Finding `
            -Pillar 'Cost' -Category 'SFTP Protocol' -Severity $sev `
            -Title "SFTP protocol is enabled on the account" `
            -Description ("SFTP support on a storage account is billed at a flat ~`$0.30/hour endpoint fee, regardless of transferred bytes, on top of the normal storage charges. That is approximately `$219/month per account. Observed monthly transactions on this account: ~{0:N0}.`n`nIf your team does not actually need SFTP for this workload, disabling it removes the fixed hourly fee." -f $mTx) `
            -Recommendation "If no consumer connects via SFTP, disable the protocol: 'az storage account update -n <name> -g <rg> --enable-sftp false'. Keep SFTP only when a real client (partner file drop, legacy tooling) requires it." `
            -Impact "Fixed hourly fee applies whether SFTP is used or not; leaving it on 'just in case' is the most common cause of surprise storage account bills." `
            -Evidence ("EnableSftp=True | Tx/mo=$([math]::Round($mTx))") `
            -EstimatedMonthlySavingsUsd 219.0 `
            -VerifyCommand ("az storage account show -n {0} -g {1} --query 'enableSftp'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName) `
            -RemediationGroupKey "sftp:disable" `
            -RemediationScript ("az storage account update -n {0} -g {1} --enable-sftp false" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
    }

    # ---- 5. Lifecycle management --------------------------------------------
    $hasLifecycle = $false
    try {
        $lc = Get-AzStorageAccountManagementPolicy -ResourceGroupName $SaObj.ResourceGroupName -StorageAccountName $SaObj.StorageAccountName -ErrorAction Stop
        if ($lc -and $lc.Policy -and $lc.Policy.Rules.Count -gt 0) { $hasLifecycle = $true }
    } catch { }
    if (-not $hasLifecycle -and $kind -eq 'StorageV2' -and $capGB -ge 50) {
        $save = $capGB * 0.3 * ($script:Pricing.CapacityGBMonth_Hot - $script:Pricing.CapacityGBMonth_Cool)  # assume 30% cools naturally
        $findings.Add((New-Finding `
            -Pillar 'Cost' -Category 'Lifecycle Management' -Severity 'High' `
            -Title "No lifecycle management policy on a non-trivial account" `
            -Description ("Account has {0:N2} GB but no blob lifecycle policy. Data ages in the tier it was created in, so cold data keeps paying Hot-tier rates." -f $capGB) `
            -Recommendation "Add a lifecycle policy with three complementary rules: (1) move base blobs to Cool after ~30 days without access; (2) move to Cold or Archive after ~90-180 days, BUT only if you can accept the 180-day minimum retention and rehydration cost; (3) DELETE non-current blob versions and snapshots after N days (e.g., 90) so they do not accumulate indefinitely under versioning. Rule 3 is the #1 forgotten one and is where snapshot bloat hides." `
            -Impact "Missing tiering automation is the #1 avoidable cost driver on blob storage." `
            -Evidence "No management policy rules found." `
            -EstimatedMonthlySavingsUsd $save `
            -VerifyCommand ("az storage account management-policy show -n {0} -g {1}" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName) `
            -RemediationGroupKey "lifecycle:add-default-policy" `
            -RemediationScript (("# Add a lifecycle policy that demotes cool blobs after 30d and archives after 180d.`n# Save as policy.json and apply with:`n# az storage account management-policy create -n {0} -g {1} --policy @policy.json`ncat > policy.json <<EOF`n{{`n  `"rules`": [{{`n    `"enabled`": true, `"name`": `"default-demote`", `"type`": `"Lifecycle`",`n    `"definition`": {{`n      `"filters`": {{`"blobTypes`":[`"blockBlob`"]}},`n      `"actions`": {{`"baseBlob`": {{`
        `"tierToCool`": {{`"daysAfterModificationGreaterThan`": 30}},`n        `"tierToArchive`": {{`"daysAfterModificationGreaterThan`": 180}}}}}}}}}}]`n}}`nEOF`naz storage account management-policy create -n {0} -g {1} --policy @policy.json") -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
    }

    # ---- 5b. Archive tier misuse via lifecycle policy --------------------
    #         If a lifecycle rule tiers blobs to Archive, warn about the three
    #         hidden costs: 180-day minimum retention, small-blob penalty,
    #         and rehydration read cost (up to $22/GB high-priority).
    if ($hasLifecycle) {
        try {
            $archiveRule = $null
            foreach ($rule in $lc.Policy.Rules) {
                $baseBlob = $rule.Definition.Actions.BaseBlob
                if ($baseBlob -and $baseBlob.TierToArchive) { $archiveRule = $rule; break }
                $ver = $rule.Definition.Actions.Version
                if ($ver -and $ver.TierToArchive) { $archiveRule = $rule; break }
            }
            if ($archiveRule) {
                $findings.Add((New-Finding `
                    -Pillar 'Cost' -Category 'Archive Tier' -Severity 'Medium' `
                    -Title "Lifecycle policy moves blobs to Archive tier - review the three hidden Archive costs" `
                    -Description ("Rule '{0}' promotes blobs to the Archive tier. Archive storage is very cheap for capacity (~`$0.001/GB-mo) but has THREE cost multipliers people frequently underestimate:`n`n" -f $archiveRule.Name) `
                                 + "  1. Minimum retention: 180 days. Any blob deleted or re-tiered before that is billed for the full 180 days.`n" `
                                 + "  2. Rehydration reads: `$0.02-`$0.05/GB (Standard priority) or up to ~`$22/GB (High priority) just to move data back to Hot/Cool before you can read it.`n" `
                                 + "  3. 128 KB minimum blob size for capacity billing: same rule as Cool/Cold, but Archive amplifies it because retention is 6x longer." `
                    -Recommendation "Archive is right when: blob is large (>= a few MB), you can wait hours to read it, and it stays at rest for at least 180 days. If you rehydrate frequently, keep the data in Cool/Cold instead. Review the applications that read from this account and quantify how often they need blobs younger than 180 days." `
                    -Impact "Unplanned rehydration and early-deletion penalties routinely turn Archive into the MOST expensive tier per blob for churning workloads." `
                    -Evidence ("LifecycleRule='$($archiveRule.Name)' | TierToArchive present") `
                    -VerifyCommand ("az storage account management-policy show -n {0} -g {1} --query 'policy.rules[?definition.actions.baseBlob.tierToArchive]'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
            }
        } catch { }
    }

    # ---- 5c. Storage Analytics classic logging ($logs container) ----------
    #         Storage Analytics v1 writes log blobs into an implicit $logs
    #         container that has no automatic retention. Long-lived accounts
    #         can accumulate hundreds of GB of logs no one ever reads.
    if ($Blob) {
        try {
            $legacyLogging = $false
            $legacyDetail  = ''
            $ctx = $null
            try { $ctx = New-AzStorageContext -StorageAccountName $SaObj.StorageAccountName -UseConnectedAccount -ErrorAction Stop } catch { }
            if ($ctx) {
                $svc = @('blob','queue','table') | ForEach-Object {
                    try {
                        $props = Get-AzStorageServiceLoggingProperty -ServiceType $_ -Context $ctx -ErrorAction Stop
                        if ($props -and ($props.LoggingOperations -ne 'None')) { $_ }
                    } catch { }
                }
                if ($svc) {
                    $legacyLogging = $true
                    $legacyDetail  = ("Enabled for: {0}" -f ($svc -join ', '))
                }
            }
            if ($legacyLogging) {
                $findings.Add((New-Finding `
                    -Pillar 'Cost' -Category 'Legacy Logging' -Severity 'Medium' `
                    -Title "Classic Storage Analytics logging is enabled (writes to hidden '`$logs' container)" `
                    -Description ("Classic Storage Analytics v1 writes log entries to a hidden container named '`$logs'. Those log blobs count as normal capacity and can grow unbounded because no default retention applies. Older accounts frequently accumulate tens or hundreds of GB of logs no one consumes anymore.`n`nStatus: $legacyDetail.`n`nMicrosoft recommends replacing classic Storage Analytics with Azure Monitor 'Diagnostic settings' + Log Analytics, which have proper retention controls.") `
                    -Recommendation "1) Set a retention policy on classic logging with 'Set-AzStorageServiceLoggingProperty -RetentionDays 30' for each enabled service. 2) Delete the '`$logs' container blobs older than N days. 3) Migrate to Azure Monitor Diagnostic Settings which provides central retention and richer schemas." `
                    -Impact "Old '`$logs' containers routinely add tens of GB of charged capacity per account with zero business value." `
                    -Evidence ("Classic Analytics logging: $legacyDetail") `
                    -VerifyCommand ("az storage logging show --account-name {0} --auth-mode login" -f $SaObj.StorageAccountName) `
                    -RemediationGroupKey "logs:classic-analytics-disable" `
                    -RemediationScript ("# Disable classic logging on all services and cap retention at 30 days.`nfor svc in blob queue table; do`n  az storage logging update --services `${svc:0:1} --log rwd --retention 30 --account-name {0} --auth-mode login`ndone`n# Optional: hard-delete accumulated logs`n# az storage blob delete-batch --source '`$logs' --account-name {0} --auth-mode login" -f $SaObj.StorageAccountName)))
            }
        } catch { }
    }

    # ---- 6. Soft delete / versioning ----------------------------------------
    if ($Blob) {
        if ($Blob.DeleteRetentionPolicy -and $Blob.DeleteRetentionPolicy.Enabled -and $Blob.DeleteRetentionPolicy.Days -gt 30) {
            $findings.Add((New-Finding `
                -Pillar 'Cost' -Category 'Data Protection' -Severity 'Low' `
                -Title ("Blob soft-delete retention is {0} days" -f $Blob.DeleteRetentionPolicy.Days) `
                -Description "Long soft-delete windows keep deleted blobs (and their versions) billable for the entire retention period." `
                -Recommendation "Right-size the retention to your recovery need (7-30 days is typical unless compliance says otherwise)." `
                -Impact "You pay for 'deleted' data for the full retention window." `
                -Evidence ("BlobSoftDeleteDays={0}" -f $Blob.DeleteRetentionPolicy.Days) `
                -VerifyCommand ("az storage account blob-service-properties show -n {0} -g {1} --query 'deleteRetentionPolicy'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
        }
        if ($Blob.IsVersioningEnabled -and -not $hasLifecycle) {
            $findings.Add((New-Finding `
                -Pillar 'Cost' -Category 'Data Protection' -Severity 'Medium' `
                -Title "Blob versioning enabled without lifecycle cleanup" `
                -Description "Versioning keeps every prior version indefinitely and each version is billed like a full blob. Without a lifecycle rule to age out non-current versions, capacity grows unboundedly." `
                -Recommendation "Add a lifecycle rule to move non-current versions to Cool/Cold and delete them after N days (e.g. 90)." `
                -Impact "Non-current versions can easily double or triple capacity bills." `
                -Evidence "IsVersioningEnabled=True; no management policy present." `
                -VerifyCommand ("az storage account blob-service-properties show -n {0} -g {1} --query 'isVersioningEnabled'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
        }
        if ($Blob.ChangeFeed -and $Blob.ChangeFeed.Enabled -and $Blob.ChangeFeed.RetentionInDays -gt 90) {
            $findings.Add((New-Finding `
                -Pillar 'Cost' -Category 'Data Protection' -Severity 'Low' `
                -Title ("Change feed retention is {0} days" -f $Blob.ChangeFeed.RetentionInDays) `
                -Description "Change feed logs are stored as blobs and billed like any other data." `
                -Recommendation "Reduce change feed retention to the minimum required for downstream consumers." `
                -Evidence ("ChangeFeedRetentionDays={0}" -f $Blob.ChangeFeed.RetentionInDays) `
                -VerifyCommand ("az storage account blob-service-properties show -n {0} -g {1} --query 'changeFeed'" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
        }
    }

    # ---- 7. Security checks removed: this tool is scoped to Cost & Performance
    #        optimization only. HTTPS / TLS / public access / firewall audit
    #        belongs in a dedicated security assessment.

    # ---- 6b. Storage Bloat: versioning + soft-delete + implicit snapshots -----
    #          Combined finding that estimates the "inflation multiplier" imposed
    #          by data-protection features on the billed capacity. This is where
    #          the #1 forgotten cost hides in GPv2 accounts migrated from GPv1.
    #
    #          Model (multiplicative, conservative):
    #            billed_capacity = visible_capacity * (1 + f_softDelete) * (1 + f_containerSoftDelete) * (1 + f_versioning)
    #          where:
    #            f_softDelete   = 0.30 * softDeleteDays/30  (~30% at 30d, capped at 3.0)
    #            f_container    = 0.10 * containerSoftDeleteDays/30
    #            f_versioning   = 1.5 if versioning is ON without a lifecycle policy, else 0
    #
    #          These factors are empirical mid-range estimates for write-heavy workloads,
    #          documented in the finding Description so the customer can challenge them.
    if ($Blob -and $capGB -ge 10) {
        $sdDays     = if ($Blob.DeleteRetentionPolicy -and $Blob.DeleteRetentionPolicy.Enabled) { [int]$Blob.DeleteRetentionPolicy.Days } else { 0 }
        $csDays     = if ($Blob.ContainerDeleteRetentionPolicy -and $Blob.ContainerDeleteRetentionPolicy.Enabled) { [int]$Blob.ContainerDeleteRetentionPolicy.Days } else { 0 }
        $verOn      = [bool]$Blob.IsVersioningEnabled
        $ptRestore  = [bool]$Blob.RestorePolicy.Enabled

        $fSd        = [math]::Min(3.0, 0.30 * $sdDays / 30.0)
        $fCs        = [math]::Min(1.0, 0.10 * $csDays / 30.0)
        $fVer       = if ($verOn -and -not $hasLifecycle) { 1.5 } else { 0.0 }
        $mult       = (1 + $fSd) * (1 + $fCs) * (1 + $fVer)

        $reasonParts = @()
        if ($sdDays -gt 0)  { $reasonParts += ("blob soft-delete {0}d (+{1:P0})" -f $sdDays, $fSd) }
        if ($csDays -gt 0)  { $reasonParts += ("container soft-delete {0}d (+{1:P0})" -f $csDays, $fCs) }
        if ($fVer -gt 0)    { $reasonParts += ("versioning ON without lifecycle (+{0:P0})" -f $fVer) }
        if ($ptRestore)     { $reasonParts += "PITR restore enabled (implies change feed retention)" }

        if ($mult -gt 1.1) {
            $inflatedGB   = $capGB * $mult
            $extraGB      = $inflatedGB - $capGB
            $tierPrice    = Get-TierCapacityPrice $tier
            $redundMult   = if ($script:Pricing.RedundancyMultiplier[$sku]) { $script:Pricing.RedundancyMultiplier[$sku] } else { 1.0 }
            $sobrecosto   = [math]::Round($extraGB * $tierPrice * $redundMult, 2)
            $severity     = if ($sobrecosto -ge 100) { 'High' } elseif ($sobrecosto -ge 10) { 'Medium' } else { 'Low' }
            $findings.Add((New-Finding `
                -Pillar 'Cost' -Category 'Storage Bloat' -Severity $severity `
                -Title ("Data-protection inflation estimated at ~{0:P0} over billed capacity" -f ($mult - 1)) `
                -Description ("Configuration inflates billed capacity beyond the visible 'UsedCapacity' value:`n  - {0}`n`nModel (multiplicative, conservative): billed = visible x (1 + f_softDelete) x (1 + f_containerSoftDelete) x (1 + f_versioning). Factors: soft-delete 0.30 x N/30, container soft-delete 0.10 x N/30, versioning without lifecycle +1.5.`n`nProjected billed capacity: {1:N2} GB (vs {2:N2} GB visible)." -f ($reasonParts -join '; '), $inflatedGB, $capGB) `
                -Recommendation "Right-size retention windows, add a lifecycle rule to delete non-current blob versions after N days (90 is typical), and cap container soft-delete to 7-14 days unless compliance requires more." `
                -Impact ("Estimated hidden monthly cost: ~`${0:N2} on top of the visible {1} tier capacity price." -f $sobrecosto, $tier) `
                -Evidence ("SoftDelete={0}d | ContainerSoftDelete={1}d | Versioning={2} | Lifecycle={3} | Multiplier={4:N2}x" -f $sdDays,$csDays,$verOn,$hasLifecycle,$mult) `
                -EstimatedMonthlySavingsUsd ($sobrecosto * 0.7) `
                -VerifyCommand ("az storage account blob-service-properties show -n {0} -g {1}" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName) `
                -RemediationGroupKey "bloat:add-version-cleanup-lifecycle" `
                -RemediationScript ("# Add lifecycle rule to age out non-current blob versions after 90 days.`n# WARNING: review with the data owner before applying - deleting versions is irreversible.`ncat <<'EOF' > /tmp/policy-{0}.json`n{{`n  `"rules`": [`n    {{`n      `"enabled`": true,`n      `"name`": `"cleanup-noncurrent-versions`",`n      `"type`": `"Lifecycle`",`n      `"definition`": {{`n        `"filters`": {{ `"blobTypes`": [`"blockBlob`"] }},`n        `"actions`": {{ `"version`": {{ `"delete`": {{ `"daysAfterCreationGreaterThan`": 90 }} }} }}`n      }}`n    }}`n  ]`n}}`nEOF`naz storage account management-policy create -n {0} -g {1} --policy @/tmp/policy-{0}.json" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
        }
    }

    # ---- 6c. Blob Inventory reports without lifecycle on output container ----
    #          Inventory policies create huge JSON/CSV reports weekly. Without a
    #          lifecycle rule on the destination container they accumulate forever.
    try {
        $inv = Get-AzStorageBlobInventoryPolicy -ResourceGroupName $SaObj.ResourceGroupName -StorageAccountName $SaObj.StorageAccountName -ErrorAction Stop
        if ($inv -and $inv.Enabled -and $inv.Policy -and $inv.Policy.Rules) {
            $destContainers = @($inv.Policy.Rules | ForEach-Object { $_.Destination } | Sort-Object -Unique)
            $findings.Add((New-Finding `
                -Pillar 'Cost' -Category 'Blob Inventory' -Severity 'Low' `
                -Title ("Blob Inventory policy is enabled - verify lifecycle on destination container(s)") `
                -Description ("Blob Inventory writes weekly reports (often GB-sized on large accounts) into the destination container(s): {0}. If those containers do not have their own lifecycle rule, reports accumulate indefinitely." -f ($destContainers -join ', ')) `
                -Recommendation "Add a lifecycle rule to the destination container that deletes report blobs older than 90 days (or the window your BI pipeline needs)." `
                -Impact "Silent capacity growth on the inventory destination. Easy fix, easy miss." `
                -Evidence ("InventoryEnabled=True | Destinations=[{0}]" -f ($destContainers -join ', ')) `
                -VerifyCommand ("az storage account blob-inventory-policy show -n {0} -g {1}" -f $SaObj.StorageAccountName,$SaObj.ResourceGroupName)))
        }
    } catch { }

    # ---- 6d. Orphan Private Endpoint (PE with 0 transactions) ----------------
    #          Each private endpoint costs ~$7.30/mo in standing charges (excluding
    #          data-processing). Idle PEs on unused accounts are pure waste.
    if ($SaObj.PrivateEndpointConnections -and $SaObj.PrivateEndpointConnections.Count -gt 0 -and $Metrics -and -not $Metrics.HasActivity) {
        $peCount = $SaObj.PrivateEndpointConnections.Count
        $peSavings = [math]::Round($peCount * 7.30, 2)
        $findings.Add((New-Finding `
            -Pillar 'Cost' -Category 'Networking' -Severity 'Medium' `
            -Title ("{0} Private Endpoint(s) attached to an idle account" -f $peCount) `
            -Description ("The account has {0} Private Endpoint connection(s) but no transactions in the last {1} days. Each Private Endpoint has a standing charge of ~`$7.30/month regardless of usage." -f $peCount, $MetricsDays) `
            -Recommendation "Confirm no consumers still reference the PE(s), then remove them along with the underlying network interfaces. If the account itself is unused, delete both." `
            -Impact ("Standing charge waste: ~`${0:N2}/mo across {1} endpoint(s)." -f $peSavings, $peCount) `
            -Evidence ("PECount={0} | Tx(30d)={1}" -f $peCount, $Metrics.Transactions) `
            -EstimatedMonthlySavingsUsd $peSavings `
            -VerifyCommand ("az network private-endpoint list --query `"[?privateLinkServiceConnections[?privateLinkServiceId=='{0}']].name`" -o tsv" -f $SaObj.Id) `
            -RemediationGroupKey "networking:remove-orphan-pe" `
            -RemediationScript ("# List PE(s) attached to this account, then remove after review.`naz network private-endpoint list --query `"[?privateLinkServiceConnections[?privateLinkServiceId=='{0}']].{{name:name,rg:resourceGroup}}`" -o tsv`n# Delete each returned PE:`n# az network private-endpoint delete -n <name> -g <rg>" -f $SaObj.Id)))
    }

    # ---- 8. Idle / empty accounts -------------------------------------------
    if (-not $SkipMetrics -and $Metrics) {
        if ($capBytes -le 1MB -and -not $Metrics.HasActivity) {
            $findings.Add((New-Finding `
                -Pillar 'Cost' -Category 'Idle Resources' -Severity 'Medium' `
                -Title "Empty and idle storage account" `
                -Description ("No measurable capacity and no transactions over the last {0} days." -f $MetricsDays) `
                -Recommendation "If confirmed unused, delete the account to remove the minimum billing footprint. Verify no SAS URIs, connection strings, or Azure services still point to it before deletion." `
                -Evidence ("Capacity={0} bytes | Tx={1}" -f $capBytes,$Metrics.Transactions) `
                -EstimatedMonthlySavingsUsd 1 `
                -VerifyCommand ("az monitor metrics list --resource {0} --metric Transactions --interval PT1H" -f $SaObj.Id)))
        } elseif ($capGB -ge 10 -and -not $Metrics.HasActivity) {
            $save = $capGB * (Get-TierCapacityPrice $tier)
            $findings.Add((New-Finding `
                -Pillar 'Cost' -Category 'Idle Resources' -Severity 'High' `
                -Title ("Dormant account holding {0:N2} GB with no activity" -f $capGB) `
                -Description ("Data is present but there have been no transactions in the last {0} days." -f $MetricsDays) `
                -Recommendation "Archive to Cold/Archive tier if data must be retained, or delete after confirming there are no consumers." `
                -Evidence ("Capacity={0:N2} GB | Tx={1}" -f $capGB,$Metrics.Transactions) `
                -EstimatedMonthlySavingsUsd ($save * 0.8) `
                -VerifyCommand ("az monitor metrics list --resource {0} --metric Transactions --interval PT1H" -f $SaObj.Id)))
        }
    }

    # ---- 9. Diagnostic-settings check removed (not a Cost/Perf/Security concern).

    return , $findings.ToArray()
}

#endregion Analysis helpers

#region ------------------------------------------------------------- Main loop

Write-Log "Beginning per-account deep analysis (throttle=$ThrottleLimit)..." STEP

# Extract the entire "Analysis helpers" region as a text block so each parallel
# runspace can dot-source it once and get every helper + the $script:Pricing table
# without duplicating code.
$script:HelpersText = ''
try {
    $selfPath = $PSCommandPath
    if (-not $selfPath) { $selfPath = $MyInvocation.MyCommand.Path }
    $rawSelf = Get-Content -Raw -LiteralPath $selfPath
    $m = [regex]::Match($rawSelf, '(?s)#region[^\r\n]*Analysis helpers.*?#endregion Analysis helpers')
    if ($m.Success) { $script:HelpersText = $m.Value }
} catch { }
if (-not $script:HelpersText) {
    Write-Log "Could not extract helpers text for parallel workers; falling back to serial mode." WARN
}

$checkpointPath = Join-Path $OutputPath 'checkpoint.json'
$results = New-Object System.Collections.Generic.List[object]
$processedIds = @{}

# Resume mode: load previously-processed accounts and skip them in the loop.
if ($Resume -and (Test-Path $checkpointPath)) {
    try {
        $ck = Get-Content -Raw -LiteralPath $checkpointPath | ConvertFrom-Json
        foreach ($r in $ck) {
            $results.Add($r) | Out-Null
            $processedIds[$r.ResourceId] = $true
        }
        Write-Log ("Resume: loaded {0} previously processed accounts from checkpoint." -f $results.Count) OK
    } catch {
        Write-Log ("Resume: failed to load checkpoint ({0}). Starting fresh." -f $_.Exception.Message) WARN
    }
}

$totalToDo = ($allAccounts | Where-Object { -not $processedIds.ContainsKey($_.id) -and $_.type -notlike '*classicstorage*' }).Count
$done      = 0
$loopStart = Get-Date

# Group by subscription to switch context once per group and to keep per-subscription
# parallel batches isolated (each thread only ever talks to a single subscription).
$grouped = $allAccounts | Group-Object subscriptionId
$helpersText = $script:HelpersText

foreach ($g in $grouped) {
    $subId   = $g.Name
    $subName = ($subs | Where-Object Id -eq $subId).Name
    Write-Log "-> Subscription: $subName ($subId) - $($g.Count) account(s)" STEP
    try { Set-AzContext -SubscriptionId $subId -WarningAction SilentlyContinue | Out-Null } catch { continue }

    $todo = @($g.Group | Where-Object { -not $processedIds.ContainsKey($_.id) -and $_.type -notlike '*classicstorage*' })
    if (-not $todo) { continue }

    $partial = $todo | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $row = $_
        $ErrorActionPreference = 'Stop'
        Import-Module Az.Accounts, Az.Storage, Az.Monitor -DisableNameChecking -ErrorAction SilentlyContinue | Out-Null
        try { $null = Set-AzContext -SubscriptionId $using:subId -WarningAction SilentlyContinue -ErrorAction Stop } catch { return $null }
        . ([scriptblock]::Create($using:helpersText))

        $MetricsDays     = $using:MetricsDays
        $SkipMetrics     = $using:SkipMetrics
        $IncludeRealCost = $using:IncludeRealCost
        $subId           = $using:subId
        $subName         = $using:subName

        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $row.resourceGroup -Name $row.name -ErrorAction Stop
            $blob = $null
            try { $blob = Get-AzStorageBlobServiceProperty -ResourceGroupName $row.resourceGroup -StorageAccountName $row.name -ErrorAction Stop } catch { }

            $metrics = $null
            if (-not $SkipMetrics) { $metrics = Get-AccountMetrics -ResourceId $sa.Id -Days $MetricsDays }

            $findingsArr = Invoke-StorageAccountAnalysis -Graph $row -SaObj $sa -Blob $blob -Metrics $metrics

            $lcCount = 0
            try {
                $lc = Get-AzStorageAccountManagementPolicy -ResourceGroupName $row.resourceGroup -StorageAccountName $row.name -ErrorAction Stop
                if ($lc -and $lc.Policy) { $lcCount = $lc.Policy.Rules.Count }
            } catch { }

            $factor = 30.0 / [double]$MetricsDays
            $capGB  = if ($metrics -and $metrics.UsedCapacityBytes) { [math]::Round($metrics.UsedCapacityBytes/1GB,2) } else { 0 }
            $inGB   = if ($metrics) { [math]::Round(($metrics.IngressBytes/1GB)*$factor,2) } else { 0 }
            $egGB   = if ($metrics) { [math]::Round(($metrics.EgressBytes/1GB)*$factor,2)  } else { 0 }
            $mRead  = if ($metrics) { [double]$metrics.ReadTx  * $factor } else { 0 }
            $mWrite = if ($metrics) { [double]$metrics.WriteTx * $factor } else { 0 }
            $mIngB  = if ($metrics) { [double]$metrics.IngressBytes * $factor } else { 0 }

            $forecast = if ($metrics -and $metrics.UsedCapacityDailyGB) { Get-CapacityForecast -DailyCapacityGB $metrics.UsedCapacityDailyGB } else { $null }
            $realCost = Get-RealAccountCost -ResourceId $sa.Id

            $tierProjections = $null; $recommendedTier = $null; $tierReason = $null; $tierReasonRich = $null
            $skuProjections  = $null; $recommendedSku  = $null; $skuReason  = $null; $skuReasonRich  = $null
            if ($sa.Kind -eq 'StorageV2' -and $capGB -ge 0.01) {
                $projHot  = Get-TierCostBreakdown -Tier Hot  -CapacityGB $capGB -MonthlyReads $mRead -MonthlyWrites $mWrite -MonthlyIngressBytes $mIngB -Sku $sa.Sku.Name
                $projCool = Get-TierCostBreakdown -Tier Cool -CapacityGB $capGB -MonthlyReads $mRead -MonthlyWrites $mWrite -MonthlyIngressBytes $mIngB -Sku $sa.Sku.Name
                $projCold = Get-TierCostBreakdown -Tier Cold -CapacityGB $capGB -MonthlyReads $mRead -MonthlyWrites $mWrite -MonthlyIngressBytes $mIngB -Sku $sa.Sku.Name
                $tierProjections = @($projHot, $projCool, $projCold)
                $curTier         = if ($sa.AccessTier) { $sa.AccessTier } else { 'Hot' }
                $reasonInfo      = Get-TierRecommendationReason -Projections $tierProjections -CurrentTier $curTier -MonthlyReads $mRead -MonthlyWrites $mWrite -CapacityGB $capGB -MetricsDays $MetricsDays
                $recommendedTier = $reasonInfo.RecommendedTier
                $tierReason      = $reasonInfo.Reason
                $tierReasonRich  = [pscustomobject]@{
                    DataSource     = $reasonInfo.DataSource
                    Observations   = $reasonInfo.Observations
                    MetricsUsed    = $reasonInfo.MetricsUsed
                    Interpretation = $reasonInfo.Interpretation
                    Action         = $reasonInfo.Action
                }

                $skuRec = Get-SkuRecommendationReason -CurrentSku $sa.Sku.Name -CurrentTier $curTier `
                    -CapacityGB $capGB -MonthlyReads $mRead -MonthlyWrites $mWrite -MonthlyIngressBytes $mIngB -MetricsDays $MetricsDays
                if ($skuRec) {
                    $recommendedSku  = $skuRec.RecommendedSku
                    $skuReason       = $skuRec.Reason
                    $skuProjections  = @($skuRec.Projections.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Sku = $_.Key; TotalCost = $_.Value } })
                    $skuReasonRich   = [pscustomobject]@{
                        DataSource     = $skuRec.DataSource
                        Observations   = $skuRec.Observations
                        MetricsUsed    = $skuRec.MetricsUsed
                        Interpretation = $skuRec.Interpretation
                        Action         = $skuRec.Action
                        Confidence     = $skuRec.Confidence
                    }
                }
            }

            return [pscustomobject]@{
                SubscriptionId      = $subId
                SubscriptionName    = $subName
                Name                = $sa.StorageAccountName
                ResourceGroup       = $sa.ResourceGroupName
                Location            = $sa.Location
                Kind                = $sa.Kind
                Sku                 = $sa.Sku.Name
                RecommendedSku      = $recommendedSku
                SkuRecommendationReason  = $skuReason
                SkuRecommendationDetails = $skuReasonRich
                SkuProjections      = $skuProjections
                AccessTier          = $sa.AccessTier
                RecommendedTier     = $recommendedTier
                TierRecommendationReason  = $tierReason
                TierRecommendationDetails = $tierReasonRich
                TierProjections     = $tierProjections
                UsedCapacityGB      = $capGB
                TransactionsMonthly = if ($metrics) { [int64]($metrics.Transactions * $factor) } else { 0 }
                ReadMonthly         = if ($metrics) { [int64]($metrics.ReadTx       * $factor) } else { 0 }
                WriteMonthly        = if ($metrics) { [int64]($metrics.WriteTx      * $factor) } else { 0 }
                IngressGBMonthly    = $inGB
                EgressGBMonthly     = $egGB
                Availability        = if ($metrics) { $metrics.Availability } else { $null }
                HttpsOnly           = $sa.EnableHttpsTrafficOnly
                MinimumTls          = $sa.MinimumTlsVersion
                PublicBlobAccess    = $sa.AllowBlobPublicAccess
                PublicNetwork       = $sa.PublicNetworkAccess
                Firewall            = if ($sa.NetworkRuleSet) { $sa.NetworkRuleSet.DefaultAction } else { 'Allow' }
                LifecycleRules      = $lcCount
                SoftDeleteDays      = if ($blob -and $blob.DeleteRetentionPolicy) { $blob.DeleteRetentionPolicy.Days } else { 0 }
                Versioning          = if ($blob) { [bool]$blob.IsVersioningEnabled } else { $false }
                CapacityForecast    = $forecast
                RealCost            = $realCost
                Findings            = $findingsArr
                ResourceId          = $sa.Id
                Tags                = ($row.tags | ConvertTo-Json -Compress -Depth 4)
            }
        } catch {
            Write-Warning ("Failed {0}: {1}" -f $row.name, $_.Exception.Message)
            return $null
        }
    }

    foreach ($r in $partial) {
        if ($null -eq $r) { continue }
        $results.Add($r) | Out-Null
        $done++
    }
    # ETA: extrapolate from observed throughput so operators know how long to wait.
    $elapsedSec = ((Get-Date) - $loopStart).TotalSeconds
    $rate       = if ($done -gt 0) { $done / $elapsedSec } else { 0 }
    $remaining  = [math]::Max(0, $totalToDo - $done)
    $etaSec     = if ($rate -gt 0) { [int]($remaining / $rate) } else { 0 }
    $etaLabel   = if ($etaSec -ge 60) { ("{0}m {1}s" -f ([int]($etaSec/60)), ($etaSec%60)) } else { ("{0}s" -f $etaSec) }
    Write-Progress -Activity "Analyzing storage accounts" `
        -Status ("$subName complete - $done of $totalToDo done (ETA " + $etaLabel + ")") `
        -PercentComplete ([int](($done * 100.0) / [math]::Max(1,$totalToDo)))

    # Incremental checkpoint after each subscription so a mid-run failure keeps progress.
    try { $results | ConvertTo-Json -Depth 8 -Compress | Set-Content -LiteralPath $checkpointPath -Encoding UTF8 } catch { }
}
Write-Progress -Activity "Analyzing storage accounts" -Completed

# Clear the checkpoint on successful completion.
if (Test-Path $checkpointPath) { try { Remove-Item -LiteralPath $checkpointPath -Force } catch { } }

Write-Log ("Analysis complete: {0} accounts, {1} findings" -f $results.Count, (($results | ForEach-Object { $_.Findings.Count }) | Measure-Object -Sum).Sum) OK

#region ------------------------------------------------------------- Reserved Capacity aggregation
# Reserved Capacity for Azure Storage is sold in 100 TB and 1 PB blocks per
# (region, tier, redundancy) with 20% (1-year) or 38% (3-year) discount.
# When a customer has >100 TB of steady-state capacity in the SAME (region+tier+SKU family)
# they leave real money on the table. Aggregating across accounts surfaces this opportunity.

Write-Log "Aggregating reserved-capacity opportunities across accounts..." STEP
$rcMinTB = $script:Pricing.ReservedCapacity_MinTB
$rcGroups = $results | Where-Object { $_.Kind -eq 'StorageV2' -and $_.UsedCapacityGB -gt 0 } |
    Group-Object { "$($_.Location)|$($_.AccessTier)|$($_.Sku)" }

$rcOpportunities = New-Object System.Collections.Generic.List[object]
foreach ($g in $rcGroups) {
    $parts    = $g.Name -split '\|'
    $region   = $parts[0]
    $tier     = $parts[1]
    $sku      = $parts[2]
    $totalGB  = ($g.Group | Measure-Object -Property UsedCapacityGB -Sum).Sum
    $totalTB  = [math]::Round($totalGB / 1024.0, 2)
    if ($totalTB -lt $rcMinTB) { continue }

    $accounts     = @($g.Group | ForEach-Object { $_.Name })
    $tierPrice    = if ($tier) { Get-TierCapacityPrice $tier } else { $script:Pricing.CapacityGBMonth_Hot }
    $redundMult   = if ($script:Pricing.RedundancyMultiplier[$sku]) { $script:Pricing.RedundancyMultiplier[$sku] } else { 1.0 }
    $onDemandMo   = $totalGB * $tierPrice * $redundMult
    $save1Yr      = $onDemandMo * $script:Pricing.ReservedCapacity_1YrDiscount
    $save3Yr      = $onDemandMo * $script:Pricing.ReservedCapacity_3YrDiscount

    $rcOpportunities.Add([pscustomobject]@{
        Region       = $region
        Tier         = $tier
        Sku          = $sku
        TotalTB      = $totalTB
        AccountCount = $accounts.Count
        Accounts     = $accounts
        OnDemandMo   = [math]::Round($onDemandMo, 2)
        Save1YrMo    = [math]::Round($save1Yr, 2)
        Save3YrMo    = [math]::Round($save3Yr, 2)
    })
}

if ($rcOpportunities.Count -gt 0) {
    Write-Log ("Reserved Capacity: {0} opportunity groups found (>= {1} TB each)." -f $rcOpportunities.Count,$rcMinTB) OK
    foreach ($opp in $rcOpportunities) {
        Write-Log ("  - {0} / {1} / {2}: {3} TB across {4} accounts | save 1yr=`${5:N2}/mo, 3yr=`${6:N2}/mo" -f `
            $opp.Region,$opp.Tier,$opp.Sku,$opp.TotalTB,$opp.AccountCount,$opp.Save1YrMo,$opp.Save3YrMo) INFO

        # Anchor the finding to the largest account in the group so users have
        # a natural entry point when clicking through from the Findings table.
        $anchor = $opp.Accounts[0]
        $anchorResult = $results | Where-Object { $_.Name -eq $anchor } | Select-Object -First 1
        if (-not $anchorResult) { continue }

        $desc = "Data source. Aggregated 'UsedCapacity' from Azure Monitor across the accounts listed below.`n`n" `
              + "Observed pattern:`n" `
              + ("  - Region: {0}`n" -f $opp.Region) `
              + ("  - Access tier: {0}`n" -f $opp.Tier) `
              + ("  - Redundancy SKU: {0}`n" -f $opp.Sku) `
              + ("  - Combined stored data: {0} TB across {1} accounts`n" -f $opp.TotalTB,$opp.AccountCount) `
              + ("  - Accounts in group: {0}`n" -f ($opp.Accounts -join ', ')) `
              + "`n" `
              + "Why this matters. Azure Storage Reserved Capacity gives 20% (1-year) or 38% (3-year) off the on-demand capacity price when you commit to a minimum of 100 TB in a single (region, tier, redundancy family). Your combined footprint in this group exceeds that threshold today.`n`n" `
              + ("Cost projection: On-demand=`${0:N2}/mo | 1-year reservation=`${1:N2}/mo saved | 3-year reservation=`${2:N2}/mo saved." -f $opp.OnDemandMo,$opp.Save1YrMo,$opp.Save3YrMo)

        $recommendation = "Purchase an Azure Storage Reserved Capacity of at least $($opp.TotalTB) TB for '$($opp.Region) / $($opp.Tier) / $($opp.Sku)' via the Portal (Reservations blade) or CLI. Reserved Capacity is billing-only — you do not need to migrate data or change account configuration. It applies automatically to the eligible accounts in that region."

        $remCmd = "# Reservation purchase requires the Portal or the Azure Reservations REST API (no direct 'az' command).`n" `
                + "# Portal path: Home > Reservations > Add > Storage.`n" `
                + "# Recommended reservation:`n" `
                + "#   Region:  $($opp.Region)`n" `
                + "#   Tier:    $($opp.Tier)`n" `
                + "#   SKU:     $($opp.Sku)`n" `
                + "#   Size:    at least $([math]::Ceiling($opp.TotalTB / 100.0) * 100) TB   (bought in 100 TB blocks)`n" `
                + "#   Term:    3-year for maximum saving, 1-year for flexibility."

        $rcFinding = New-Finding `
            -Pillar 'Cost' -Category 'Reserved Capacity' `
            -Severity $(if ($opp.Save1YrMo -ge 500) { 'Critical' } elseif ($opp.Save1YrMo -ge 100) { 'High' } elseif ($opp.Save1YrMo -ge 20) { 'Medium' } else { 'Low' }) `
            -Title ("Reserved Capacity opportunity: {0} TB in {1} / {2} / {3} - save up to `${4:N2}/mo" -f $opp.TotalTB,$opp.Region,$opp.Tier,$opp.Sku,$opp.Save3YrMo) `
            -Description $desc `
            -Recommendation $recommendation `
            -Impact "Reserved Capacity is one of the highest-ROI cost optimizations for Storage. The savings are billing-only (no service change required) and apply automatically." `
            -Evidence ("Region=$($opp.Region) | Tier=$($opp.Tier) | SKU=$($opp.Sku) | TB=$($opp.TotalTB) | Accounts=$($opp.AccountCount)") `
            -EstimatedMonthlySavingsUsd $opp.Save1YrMo `
            -VerifyCommand "# Reservations blade: az reservations reservation-order list" `
            -RemediationGroupKey ("reservation:{0}|{1}|{2}" -f $opp.Region,$opp.Tier,$opp.Sku) `
            -RemediationScript $remCmd

        # Attach to the anchor account's findings so the Findings tab shows it.
        $newList = @($anchorResult.Findings) + $rcFinding
        $anchorResult.Findings = $newList
    }
} else {
    Write-Log ("Reserved Capacity: no (region+tier+SKU) group exceeds {0} TB of stored data." -f $rcMinTB) INFO
}
#endregion Reserved Capacity aggregation

#endregion Main loop

#region ------------------------------------------------------------- HTML report

Write-Log "Rendering HTML report..." STEP

# Load prior snapshot for comparison if -CompareWith is provided.
$compareData = $null
if ($CompareWith) {
    if (Test-Path $CompareWith) {
        try {
            $compareData = Get-Content -Raw -LiteralPath $CompareWith | ConvertFrom-Json
            $priorFC = if ($compareData.Findings) { $compareData.Findings.Count } else { 0 }
            Write-Log ("CompareWith: loaded snapshot '{0}' ({1} findings from run {2})." -f $CompareWith,$priorFC,$compareData.RunId) OK
        } catch {
            Write-Log ("CompareWith: failed to load snapshot ({0}). Skipping comparison." -f $_.Exception.Message) WARN
        }
    } else {
        Write-Log ("CompareWith: file not found: $CompareWith. Skipping comparison.") WARN
    }
}

$reportDate    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
$runId         = (Get-Date).ToString('yyyyMMdd_HHmmss')
$reportFile    = Join-Path $OutputPath ("StorageOptimizer_{0}.html" -f $runId)
$totalAccounts = $results.Count
$flatFindings  = @()
foreach ($r in $results) {
    foreach ($f in $r.Findings) {
        $flatFindings += [pscustomobject]@{
            SubscriptionName            = $r.SubscriptionName
            SubscriptionId              = $r.SubscriptionId
            Account                     = $r.Name
            ResourceGroup               = $r.ResourceGroup
            Location                    = $r.Location
            Pillar                      = $f.Pillar
            Category                    = $f.Category
            Severity                    = $f.Severity
            Title                       = $f.Title
            Description                 = $f.Description
            Recommendation              = $f.Recommendation
            Impact                      = $f.Impact
            Evidence                    = $f.Evidence
            EstimatedMonthlySavingsUsd  = $f.EstimatedMonthlySavingsUsd
            VerifyCommand               = $f.VerifyCommand
            RemediationScript           = $f.RemediationScript
            RemediationGroupKey         = $f.RemediationGroupKey
            ResourceId                  = $r.ResourceId
        }
    }
}

$sevCounts = @{ Critical=0; High=0; Medium=0; Low=0; Informational=0 }
foreach ($f in $flatFindings) { $sevCounts[$f.Severity]++ }
$totalSavings = [math]::Round((($flatFindings | Measure-Object EstimatedMonthlySavingsUsd -Sum).Sum), 2)

# JSON payloads — helper guarantees an array shape regardless of element count.
function ConvertTo-JsonArray {
    param($InputObject, [int] $Depth = 6)
    $arr = @($InputObject)
    if ($arr.Count -eq 0) { return '[]' }
    if ($arr.Count -eq 1) { return '[' + ($arr[0] | ConvertTo-Json -Depth $Depth -Compress) + ']' }
    return ($arr | ConvertTo-Json -Depth $Depth -Compress)
}

$accountsJson = ConvertTo-JsonArray ($results | Select-Object * -ExcludeProperty Findings)
$findingsJson = ConvertTo-JsonArray $flatFindings
$subsJson     = ConvertTo-JsonArray ($results | Select-Object SubscriptionId,SubscriptionName -Unique) -Depth 3

# Aggregations (kept: severity + pillar. Removed: kind/sku/tier — low signal, high visual noise).
$byPillar   = @($flatFindings  | Group-Object Pillar   | ForEach-Object { [pscustomobject]@{ label = "$($_.Name)"; value = $_.Count } })
$byCategory = @($flatFindings  | Group-Object Category | ForEach-Object { [pscustomobject]@{ label = "$($_.Name)"; value = $_.Count } })
$bySeverity = @(
    [pscustomobject]@{ label = 'Critical'; value = [int]$sevCounts.Critical }
    [pscustomobject]@{ label = 'High';     value = [int]$sevCounts.High }
    [pscustomobject]@{ label = 'Medium';   value = [int]$sevCounts.Medium }
    [pscustomobject]@{ label = 'Low';      value = [int]$sevCounts.Low }
)
$pillarCounts = @{ Cost = 0; Performance = 0 }
foreach ($f in $flatFindings) { if ($pillarCounts.ContainsKey($f.Pillar)) { $pillarCounts[$f.Pillar]++ } }

$aggObj = [ordered]@{
    byPillar   = (ConvertTo-JsonArray $byPillar)
    byCategory = (ConvertTo-JsonArray $byCategory)
    bySeverity = (ConvertTo-JsonArray $bySeverity)
}
# Manually splice pre-serialized array strings into the parent JSON object.
# NOTE: each element is fully parenthesized because '"k":' + $x, '"k2":' + $y
# would otherwise be parsed as '"k":' + ($x, '"k2":') + $y (array-collapsed via $OFS).
$aggJson = '{' + (@(
    ('"byPillar":'   + $aggObj.byPillar),
    ('"byCategory":' + $aggObj.byCategory),
    ('"bySeverity":' + $aggObj.bySeverity)
) -join ',') + '}'

$htmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Azure Storage Account Optimizer - __RUNID__</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Segoe+UI:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"></script>
<style>
  :root {
    --ms-blue:        #0078D4;
    --ms-blue-dark:   #106EBE;
    --ms-blue-darker: #005A9E;
    --ms-blue-light:  #DEECF9;
    --ms-green:       #107C10;
    --ms-green-light: #DFF6DD;
    --ms-orange:      #D83B01;
    --ms-orange-light:#FED9CC;
    --ms-yellow:      #FFB900;
    --ms-yellow-light:#FFF4CE;
    --ms-red:         #A4262C;
    --ms-red-light:   #FDE7E9;
    --ms-purple:      #5C2D91;
    --ms-purple-light:#EDE1F5;
    --ms-teal:        #038387;
    --ms-teal-light:  #D2F1F5;
    --neutral-0:      #FFFFFF;
    --neutral-10:     #FAF9F8;
    --neutral-20:     #F3F2F1;
    --neutral-30:     #EDEBE9;
    --neutral-40:     #E1DFDD;
    --neutral-60:     #C8C6C4;
    --neutral-100:    #605E5C;
    --neutral-130:    #484644;
    --neutral-160:    #323130;
    --neutral-190:    #201F1E;
    --shadow-sm:      0 1px 2px rgba(0,0,0,.04), 0 1px 3px rgba(0,0,0,.06);
    --shadow-md:      0 3px 8px rgba(0,0,0,.06), 0 8px 20px rgba(0,0,0,.08);
    --shadow-lg:      0 8px 24px rgba(0,0,0,.10), 0 16px 32px rgba(0,0,0,.10);
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--neutral-10); color: var(--neutral-160); font-family: 'Segoe UI', 'Segoe UI Variable', system-ui, -apple-system, sans-serif; font-size: 14px; line-height: 1.5; }
  a { color: var(--ms-blue); text-decoration: none; }
  a:hover { text-decoration: underline; }
  code { font-family: 'Cascadia Code', Consolas, monospace; background: var(--neutral-20); color: var(--ms-blue-darker); padding: 2px 6px; border-radius: 4px; font-size: 12.5px; }
  .container { max-width: 1600px; margin: 0 auto; padding: 24px 32px 48px; }

  /* ---- Header ---- */
  header.app { background: linear-gradient(135deg, var(--ms-blue-darker) 0%, var(--ms-blue) 60%, var(--ms-teal) 100%); color: white; padding: 32px 32px 40px; margin-bottom: -20px; }
  header.app .inner { max-width: 1600px; margin: 0 auto; display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; }
  header.app h1 { margin: 0 0 6px; font-size: 26px; font-weight: 700; letter-spacing: -0.01em; }
  header.app .sub { opacity: .9; font-size: 13px; font-weight: 400; }
  header.app .meta { text-align: right; font-size: 12px; opacity: .95; line-height: 1.7; }
  header.app .meta b { font-weight: 600; }
  header.app .logo { display:inline-flex; align-items:center; gap:10px; font-weight:700; letter-spacing:-0.01em; font-size:13px; text-transform: uppercase; opacity:.85; margin-bottom:8px; }
  header.app .logo::before { content:''; width:22px; height:22px; background: white; border-radius: 3px; display:inline-block;
    background-image: linear-gradient(90deg, #F25022 0 50%, #7FBA00 50% 100%), linear-gradient(90deg, #00A4EF 0 50%, #FFB900 50% 100%);
    background-size: 100% 50%; background-position: 0 0, 0 100%; background-repeat: no-repeat; }

  /* ---- KPI cards ---- */
  .kpi-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 24px; }
  .kpi { background: var(--neutral-0); border: 1px solid var(--neutral-30); border-radius: 8px; padding: 18px 20px; box-shadow: var(--shadow-sm); cursor: pointer; transition: all .18s ease; position: relative; overflow: hidden; }
  .kpi:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); border-color: var(--ms-blue); }
  .kpi::after { content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: var(--accent, var(--ms-blue)); }
  .kpi .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; color: var(--neutral-100); margin-bottom: 6px; }
  .kpi .value { font-size: 32px; font-weight: 700; line-height: 1.1; color: var(--neutral-190); font-variant-numeric: tabular-nums; }
  .kpi .hint  { font-size: 11px; color: var(--neutral-100); margin-top: 6px; }
  .kpi .arrow { position: absolute; top: 18px; right: 18px; opacity: 0; transition: all .18s; color: var(--ms-blue); font-weight: 700; }
  .kpi:hover .arrow { opacity: 1; transform: translateX(2px); }
  .kpi.kpi-total    { --accent: var(--ms-blue); }
  .kpi.kpi-critical { --accent: var(--ms-red); }
  .kpi.kpi-critical .value { color: var(--ms-red); }
  .kpi.kpi-high     { --accent: var(--ms-orange); }
  .kpi.kpi-high .value { color: var(--ms-orange); }
  .kpi.kpi-medium   { --accent: var(--ms-yellow); }
  .kpi.kpi-medium .value { color: #B77900; }
  .kpi.kpi-savings  { --accent: var(--ms-green); }
  .kpi.kpi-savings .value { color: var(--ms-green); }

  /* ---- Pillar mini-cards ---- */
  .pillars { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-bottom: 20px; }
  .pillar { background: var(--neutral-0); border: 1px solid var(--neutral-30); border-radius: 8px; padding: 14px 18px; box-shadow: var(--shadow-sm); cursor: pointer; transition: all .15s ease; display: flex; align-items: center; gap: 14px; }
  .pillar:hover { border-color: var(--pcolor, var(--ms-blue)); transform: translateY(-1px); box-shadow: var(--shadow-md); }
  .pillar .icon { width: 40px; height: 40px; border-radius: 8px; background: var(--pbg, var(--ms-blue-light)); display: flex; align-items: center; justify-content: center; color: var(--pcolor, var(--ms-blue)); font-weight: 700; font-size: 18px; }
  .pillar .txt { flex: 1; }
  .pillar .txt b { display: block; font-size: 13px; color: var(--neutral-190); font-weight: 600; }
  .pillar .txt span { display: block; font-size: 11.5px; color: var(--neutral-100); }
  .pillar .count { font-size: 24px; font-weight: 700; font-variant-numeric: tabular-nums; color: var(--pcolor, var(--ms-blue)); }
  .pillar.cost        { --pcolor: var(--ms-green);  --pbg: var(--ms-green-light); }
  .pillar.performance { --pcolor: var(--ms-purple); --pbg: var(--ms-purple-light); }
  .pillar.security    { --pcolor: var(--ms-blue);   --pbg: var(--ms-blue-light); }

  /* ---- Tabs ---- */
  .tabs { display: flex; gap: 6px; border-bottom: 2px solid var(--neutral-30); margin: 28px 0 22px; padding: 0 4px; }
  .tab-btn {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 12px 20px 14px;
    background: transparent; border: none;
    border-bottom: 3px solid transparent; margin-bottom: -2px;
    font-size: 14.5px; font-weight: 600; color: var(--neutral-100);
    cursor: pointer; transition: all .15s ease;
    font-family: inherit; border-radius: 6px 6px 0 0;
    position: relative;
  }
  .tab-btn .tab-icon { display:inline-flex; width:16px; height:16px; align-items:center; justify-content:center; opacity:.7; transition: opacity .15s ease; }
  .tab-btn .tab-icon svg { width:16px; height:16px; stroke: currentColor; fill: none; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }
  .tab-btn .tab-count {
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 22px; height: 20px; padding: 0 7px;
    background: var(--neutral-20); color: var(--neutral-130);
    font-size: 11px; font-weight: 700; border-radius: 999px;
    line-height: 1; margin-left: 2px;
    transition: all .15s ease;
  }
  .tab-btn:hover { color: var(--ms-blue-darker); background: var(--ms-blue-light); }
  .tab-btn:hover .tab-icon { opacity: 1; }
  .tab-btn:hover .tab-count { background: white; color: var(--ms-blue-darker); }
  .tab-btn.active {
    color: var(--ms-blue-darker);
    background: var(--ms-blue-light);
    border-bottom-color: var(--ms-blue);
  }
  .tab-btn.active .tab-icon { opacity: 1; }
  .tab-btn.active .tab-count { background: var(--ms-blue); color: white; }

  /* ---- Cards ---- */
  .card { background: var(--neutral-0); border: 1px solid var(--neutral-30); border-radius: 8px; box-shadow: var(--shadow-sm); }
  .card + .card { margin-top: 16px; }
  .card .card-head { padding: 16px 20px; border-bottom: 1px solid var(--neutral-30); display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
  .card .card-head h3 { margin: 0; font-size: 15px; font-weight: 600; color: var(--neutral-190); }
  .card .card-body { padding: 16px 20px; }
  .card.chart { padding: 20px; }
  .card.chart h3 { margin: 0 0 12px; font-size: 14px; font-weight: 600; color: var(--neutral-160); }

  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }

  /* ---- Action summary strip (replaces low-signal donut charts) ---- */
  .action-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
  .action { background: var(--neutral-0); border: 1px solid var(--neutral-30); border-radius: 8px; padding: 14px 18px; box-shadow: var(--shadow-sm); transition: all .15s ease; }
  .action[onclick] { cursor: pointer; }
  .action[onclick]:hover { border-color: var(--ms-blue); transform: translateY(-1px); box-shadow: var(--shadow-md); }
  .action .action-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; color: var(--neutral-100); margin-bottom: 6px; }
  .action .action-value { font-size: 24px; font-weight: 700; color: var(--neutral-190); font-variant-numeric: tabular-nums; line-height: 1.1; }
  .action .action-hint  { font-size: 11.5px; color: var(--neutral-100); margin-top: 4px; }
  .sbar { display: flex; align-items: center; gap: 8px; margin-top: 6px; font-size: 12px; }
  .sbar .sbar-label { width: 78px; color: var(--neutral-130); font-weight: 600; }
  .sbar .sbar-track { flex: 1; height: 6px; background: var(--neutral-20); border-radius: 3px; overflow: hidden; }
  .sbar .sbar-fill  { height: 100%; border-radius: 3px; transition: width .3s; }
  .sbar .sbar-val   { min-width: 62px; text-align: right; font-variant-numeric: tabular-nums; color: var(--neutral-190); font-weight: 600; }
  .sbar.cost        .sbar-fill { background: var(--ms-green); }
  .sbar.performance .sbar-fill { background: var(--ms-purple); }
  .sbar.security    .sbar-fill { background: var(--ms-blue); }

  /* ---- Tables ---- */
  table.data { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.data th { background: var(--neutral-10); color: var(--neutral-130); text-align: left; padding: 10px 14px; font-weight: 600; border-bottom: 1px solid var(--neutral-30); font-size: 12px; text-transform: uppercase; letter-spacing: 0.03em; position: sticky; top: 0; z-index: 1; }
  table.data td { padding: 11px 14px; border-bottom: 1px solid var(--neutral-20); vertical-align: top; }
  table.data tbody tr { transition: background .1s; }
  table.data tbody tr:hover { background: var(--ms-blue-light); cursor: pointer; }
  table.data td b { font-weight: 600; color: var(--neutral-190); }
  .scroll { max-height: 68vh; overflow: auto; }

  /* ---- Badges ---- */
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; letter-spacing: 0.02em; }
  .b-crit { background: var(--ms-red-light);    color: var(--ms-red); }
  .b-high { background: var(--ms-orange-light); color: var(--ms-orange); }
  .b-med  { background: var(--ms-yellow-light); color: #8C6900; }
  .b-low  { background: var(--ms-blue-light);   color: var(--ms-blue-darker); }
  .b-info { background: var(--neutral-20);       color: var(--neutral-130); }
  .b-cost        { background: var(--ms-green-light);  color: var(--ms-green); }
  .b-performance { background: var(--ms-purple-light); color: var(--ms-purple); }
  .b-security    { background: var(--ms-blue-light);   color: var(--ms-blue-darker); }
  .b-yes { background: var(--ms-green-light); color: var(--ms-green); }
  .b-no  { background: var(--neutral-20); color: var(--neutral-130); }
  .b-warn { background: var(--ms-orange-light); color: var(--ms-orange); }

  /* ---- Controls ---- */
  input, select { font-family: inherit; font-size: 13px; background: var(--neutral-0); border: 1px solid var(--neutral-40); border-radius: 4px; padding: 7px 10px; color: var(--neutral-190); outline: none; transition: border-color .12s; }
  input:focus, select:focus { border-color: var(--ms-blue); box-shadow: 0 0 0 2px rgba(0,120,212,.2); }
  .toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
  .toolbar .grow { flex: 1; min-width: 220px; }
  .btn { background: var(--ms-blue); color: white; border: none; border-radius: 4px; padding: 8px 16px; font-size: 13px; font-weight: 600; cursor: pointer; font-family: inherit; transition: background .12s; }
  .btn:hover { background: var(--ms-blue-dark); }
  .btn.subtle { background: var(--neutral-0); color: var(--ms-blue); border: 1px solid var(--neutral-40); }
  .btn.subtle:hover { background: var(--neutral-10); }

  /* ---- Drill-down modal ---- */
  .modal-bg { position: fixed; inset: 0; background: rgba(32, 31, 30, 0.55); display: none; align-items: center; justify-content: center; z-index: 100; padding: 24px; }
  .modal-bg.open { display: flex; }
  .modal { background: var(--neutral-0); border-radius: 10px; box-shadow: var(--shadow-lg); max-width: 960px; width: 100%; max-height: 88vh; overflow: auto; }
  .modal-head { padding: 20px 24px; border-bottom: 1px solid var(--neutral-30); display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; background: var(--neutral-0); z-index: 1; }
  .modal-head h3 { margin: 0; font-size: 18px; font-weight: 600; color: var(--neutral-190); }
  .modal-body { padding: 20px 24px; }
  .cfg-grid { display: grid; grid-template-columns: 200px 1fr; gap: 6px 20px; margin-bottom: 20px; font-size: 13.5px; }
  .cfg-grid .k { color: var(--neutral-100); font-weight: 500; }
  .cfg-grid .v { color: var(--neutral-190); font-weight: 500; }

  details.finding { border: 1px solid var(--neutral-30); border-radius: 6px; padding: 12px 16px; margin: 10px 0; background: var(--neutral-0); border-left: 4px solid var(--neutral-60); }
  details.finding[open] { background: var(--neutral-10); }
  details.finding summary { cursor: pointer; font-weight: 600; color: var(--neutral-190); list-style: none; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  details.finding summary::-webkit-details-marker { display: none; }
  details.finding summary::before { content: '›'; font-size: 18px; color: var(--neutral-100); transition: transform .15s; }
  details.finding[open] summary::before { transform: rotate(90deg); }
  details.finding p { margin: 8px 0; font-size: 13px; color: var(--neutral-130); }
  details.crit { border-left-color: var(--ms-red); }
  details.high { border-left-color: var(--ms-orange); }
  details.med  { border-left-color: var(--ms-yellow); }
  details.low  { border-left-color: var(--ms-blue); }

  /* "View metrics used" collapsible inside recommendation callouts */
  details.reveal-metrics summary::-webkit-details-marker { display: none; }
  details.reveal-metrics summary::before {
    content: '\25B8'; display:inline-block;
    margin-right: 6px; color: var(--ms-blue); font-size: 12px;
    transition: transform .15s ease;
  }
  details.reveal-metrics[open] summary::before { transform: rotate(90deg); }
  details.reveal-metrics summary:hover { text-decoration: underline; }

  /* Bulk actions groups (Findings tab) */
  .bulk-group { border-bottom: 1px solid var(--neutral-30); padding: 14px 20px; display: flex; align-items: center; gap: 16px; }
  .bulk-group:last-child { border-bottom: none; }
  .bulk-group:hover { background: var(--neutral-10); }
  .bulk-group .bulk-meta { flex: 1; min-width: 0; }
  .bulk-group .bulk-title { font-weight: 600; color: var(--neutral-190); font-size: 14px; }
  .bulk-group .bulk-sub   { color: var(--neutral-100); font-size: 12px; margin-top: 2px; }
  .bulk-group .bulk-value { font-size: 18px; font-weight: 700; color: var(--ms-green); font-variant-numeric: tabular-nums; min-width: 110px; text-align: right; }
  .bulk-group .bulk-count { display:inline-block; background: var(--neutral-20); color: var(--neutral-130); padding: 2px 10px; border-radius: 10px; font-size: 11px; font-weight: 700; margin-right: 6px; }
  .bulk-group .bulk-actions { display: flex; gap: 6px; }
  .bulk-group .bulk-actions button { padding: 6px 12px; font-size: 12px; }

  /* Growth forecast + real cost panels (drill-down) */
  .kv-panel { display:grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 12px; }
  .kv-panel > div { background: var(--neutral-10); border: 1px solid var(--neutral-30); border-radius: 6px; padding: 10px 12px; }
  .kv-panel .kv-label { font-size: 10.5px; color: var(--neutral-100); text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600; }
  .kv-panel .kv-value { font-size: 16px; font-weight: 700; color: var(--neutral-190); margin-top: 3px; font-variant-numeric: tabular-nums; }
  .kv-panel .kv-hint  { font-size: 10.5px; color: var(--neutral-100); margin-top: 2px; }

  /* Compare-mode indicators */
  .diff-badge { display:inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10.5px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; margin-left: 6px; }
  .diff-new      { background: var(--ms-red-light);   color: var(--ms-red); }
  .diff-resolved { background: var(--ms-green-light); color: var(--ms-green); }
  .diff-open     { background: var(--neutral-20);     color: var(--neutral-100); }

  /* ---- Utility ---- */
  .hidden { display: none !important; }
  .right { text-align: right; }
  .muted { color: var(--neutral-100); }
  .tiny  { font-size: 11.5px; }
  .empty { text-align: center; padding: 40px 20px; color: var(--neutral-100); font-size: 13px; }
  .count-pill { display:inline-block; background: var(--neutral-20); color: var(--neutral-130); padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }

  /* Scope selector (filters everything by subscription or shows the full tenant) */
  .scope-bar { background: #fff; border: 1px solid var(--neutral-30); border-radius: 8px; padding: 12px 18px; margin-bottom: 18px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  .scope-inner { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
  .scope-inner label { color: var(--neutral-130); font-size: 13px; }
  .scope-inner select { min-width: 320px; padding: 6px 10px; border: 1px solid var(--neutral-40); border-radius: 4px; background: #fff; font-size: 13px; color: var(--neutral-190); }
  .scope-inner select:focus { outline: 2px solid var(--ms-blue); outline-offset: 1px; }
  body.scoped .kpi-total { border-left: 3px solid var(--ms-blue); }

  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-thumb { background: var(--neutral-40); border-radius: 8px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--neutral-60); }
</style>
</head>
<body>

<header class="app">
  <div class="inner">
    <div>
      <div class="logo">Microsoft Azure</div>
      <h1>Storage Account Optimizer</h1>
      <div class="sub">Cost and performance optimization report - generated __REPORT_DATE__</div>
    </div>
    <div class="meta">
      <div>Tenant: <b>__TENANT_ID__</b></div>
      <div>Signed-in: <b>__ACCOUNT_ID__</b></div>
      <div>Metrics window: <b>__METRICS_DAYS__ days</b> - Script v__SCRIPT_VERSION__</div>
    </div>
  </div>
</header>

<div class="container">

  <!-- Scope selector: filters KPIs, pillars, Overview table, and tab-level filters
       by a single subscription, or shows the full tenant. -->
  <section class="scope-bar">
    <div class="scope-inner">
      <label for="scopeSel"><b>Scope</b></label>
      <select id="scopeSel">
        <option value="">All tenant</option>
      </select>
      <span class="tiny muted" id="scopeSummary"></span>
    </div>
  </section>

  <!-- KPIs (clickable) -->
  <section class="kpi-row">
    <div class="kpi kpi-total" onclick="focusView('overview')">
      <div class="label">Storage accounts</div>
      <div class="value" id="kpiTotal">__TOTAL_ACCOUNTS__</div>
      <div class="hint">Analyzed in this run</div>
      <div class="arrow">→</div>
    </div>
    <div class="kpi kpi-critical" onclick="focusView('findings',{severity:'Critical'})">
      <div class="label">Critical</div>
      <div class="value" id="kpiCritical">__SEV_CRITICAL__</div>
      <div class="hint">View critical findings</div>
      <div class="arrow">→</div>
    </div>
    <div class="kpi kpi-high" onclick="focusView('findings',{severity:'High'})">
      <div class="label">High</div>
      <div class="value" id="kpiHigh">__SEV_HIGH__</div>
      <div class="hint">View high findings</div>
      <div class="arrow">→</div>
    </div>
    <div class="kpi kpi-medium" onclick="focusView('findings',{severity:'Medium'})">
      <div class="label">Medium</div>
      <div class="value" id="kpiMedium">__SEV_MEDIUM__</div>
      <div class="hint">View medium findings</div>
      <div class="arrow">→</div>
    </div>
    <div class="kpi kpi-savings" onclick="focusView('findings',{sortBy:'savings'})">
      <div class="label">Est. monthly savings</div>
      <div class="value" id="kpiSavings">$__TOTAL_SAVINGS__</div>
      <div class="hint">Directional (public list prices)</div>
      <div class="arrow">→</div>
    </div>
  </section>

  <!-- Pillar cards (clickable filter shortcuts) -->
  <section class="pillars">
    <div class="pillar cost" onclick="focusView('findings',{pillar:'Cost'})">
      <div class="icon">$</div>
      <div class="txt"><b>Cost</b><span>Right-size tier, redundancy, retention</span></div>
      <div class="count" id="pillarCostCount">__PILLAR_COST__</div>
    </div>
    <div class="pillar performance" onclick="focusView('findings',{pillar:'Performance'})">
      <div class="icon">⚡</div>
      <div class="txt"><b>Performance</b><span>Standard vs Premium tier match</span></div>
      <div class="count" id="pillarPerfCount">__PILLAR_PERF__</div>
    </div>
  </section>

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab-btn active" data-tab="overview">
      <span class="tab-icon"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg></span>
      Overview
    </button>
    <button class="tab-btn" data-tab="findings">
      <span class="tab-icon"><svg viewBox="0 0 24 24"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></span>
      Findings
      <span class="tab-count" id="tabCountFindings">0</span>
    </button>
    <button class="tab-btn" data-tab="accounts">
      <span class="tab-icon"><svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v6c0 1.66 4 3 9 3s9-1.34 9-3V5"/><path d="M3 11v6c0 1.66 4 3 9 3s9-1.34 9-3v-6"/></svg></span>
      Accounts
      <span class="tab-count" id="tabCountAccounts">0</span>
    </button>
    <button class="tab-btn" data-tab="methodology">
      <span class="tab-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg></span>
      Methodology
    </button>
  </div>

  <!-- Overview -->
  <section id="tab-overview" class="tab">

    <!-- Action summary: compact clickable widgets that answer "what should I fix and how much do I save?" -->
    <div class="action-row">
      <div class="action" onclick="focusView('findings',{category:'Tier Optimization'})">
        <div class="action-label">Accounts with wrong tier</div>
        <div class="action-value" id="mmTier">0</div>
        <div class="action-hint" id="mmTierHint">All aligned</div>
      </div>
      <div class="action" onclick="focusView('findings',{category:'Redundancy'})">
        <div class="action-label">Replication mismatch</div>
        <div class="action-value" id="mmSku">0</div>
        <div class="action-hint" id="mmSkuHint">All aligned</div>
      </div>
      <div class="action">
        <div class="action-label">Est. monthly savings by pillar</div>
        <div id="savingsBars"></div>
      </div>
      <div class="action" onclick="focusView('findings',{category:'GPv1 Pre-Migration'})">
        <div class="action-label">Still on GPv1</div>
        <div class="action-value" id="mmGpv1">0</div>
        <div class="action-hint">Review before upgrading</div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <h3>Storage account configuration snapshot</h3>
        <button class="btn" onclick="exportExcel('accounts')">Export to Excel</button>
      </div>
      <div class="scroll">
        <table class="data" id="tblOverview">
          <thead><tr>
            <th>Account</th><th>Subscription</th><th>Location</th>
            <th>Kind</th><th>SKU</th><th>Rec SKU</th><th>Tier</th><th>Rec tier</th>
            <th class="right">Capacity GB</th>
            <th class="right">Tx/mo</th>
            <th class="right">Egress GB/mo</th>
            <th>Lifecycle</th><th>Versioning</th><th class="right">Findings</th>
          </tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- Findings -->
  <section id="tab-findings" class="tab hidden">

    <!-- Bulk Actions: findings grouped by (Category + Recommended action) so operators
         with 700 accounts can act at scale instead of one-by-one. -->
    <div class="card" id="bulkActionsCard" style="display:none;">
      <div class="card-head">
        <h3>Bulk actions <span class="tiny muted" style="font-weight:400;">grouped by category + recommendation, sorted by total impact</span></h3>
        <button class="btn" onclick="downloadAllRemediations()">Download all remediations (.sh)</button>
      </div>
      <div id="bulkGroupsList" class="card-body" style="padding:0;"></div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="toolbar" style="width:100%;">
          <input id="fSearch" placeholder="Search account, title, category..." class="grow" />
          <select id="fPillar">
            <option value="">All pillars</option>
            <option>Cost</option><option>Performance</option>
          </select>
          <select id="fSeverity">
            <option value="">All severities</option>
            <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
          </select>
          <select id="fCategory"><option value="">All categories</option></select>
          <select id="fSub"><option value="">All subscriptions</option></select>
          <button class="btn" onclick="exportExcel('findings')">Export to Excel</button>
          <span class="tiny muted" id="fCount"></span>
        </div>
      </div>
      <div class="scroll">
        <table class="data" id="tblFindings">
          <thead><tr>
            <th>Severity</th><th>Pillar</th><th>Category</th><th>Account</th><th>Subscription</th><th>Title</th><th class="right">Est. USD/mo</th>
          </tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- Accounts -->
  <section id="tab-accounts" class="tab hidden">
    <div class="card">
      <div class="card-head">
        <div class="toolbar" style="width:100%;">
          <input id="aSearch" placeholder="Search account, resource group, location..." class="grow" />
          <select id="aSub"><option value="">All subscriptions</option></select>
          <select id="aTier"><option value="">All tiers</option></select>
          <button class="btn" onclick="exportExcel('accounts')">Export to Excel</button>
          <span class="tiny muted" id="aCount"></span>
        </div>
      </div>
      <div class="scroll">
        <table class="data" id="tblAccounts">
          <thead><tr>
            <th>Account</th><th>Subscription</th><th>RG</th><th>Location</th>
            <th>Kind</th><th>SKU</th><th>Rec SKU</th><th>Tier</th><th>Rec tier</th>
            <th class="right">Capacity GB</th>
            <th class="right">Tx/mo</th>
            <th class="right">Egress GB/mo</th>
            <th class="right">Findings</th>
          </tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- Methodology -->
  <section id="tab-methodology" class="tab hidden">
    <div class="card">
      <div class="card-body" style="max-width: 900px;">
        <h3 style="margin-top:0;">How this assessment works</h3>
        <p><b>Scope.</b> Every Storage Account visible to the signed-in principal is discovered via Azure Resource Graph and inspected with the modern <code>Az.Storage</code>, <code>Az.Monitor</code> and <code>Az.Accounts</code> modules. The script is strictly <b>read-only</b> — it never creates, updates or deletes any Azure resource.</p>
        <p><b>Metrics.</b> For each account we pull Azure Monitor metrics for the last <b>__METRICS_DAYS__ days</b>: <code>UsedCapacity</code>, <code>Transactions</code> (split by ApiName into Read / Write / Other), <code>Ingress</code>, <code>Egress</code> and <code>Availability</code>. Monthly figures in the report are the observed totals extrapolated to a 30-day month.</p>
        <p><b>Pillars.</b> Findings are grouped in two pillars aligned to the goal of this tool: <span class="badge b-cost">Cost</span> (access tier vs. transaction pattern, redundancy vs. usage, lifecycle, retention, idle capacity, GPv1 pre-migration guidance) and <span class="badge b-performance">Performance</span> (Premium tier match to workload). This is strictly a cost &amp; performance optimizer; security posture belongs in a dedicated assessment.</p>

        <h3 style="margin-top:20px;">Tier recommendation model</h3>
        <p>For every <code>StorageV2</code> account we compute the projected monthly cost at <b>Hot</b>, <b>Cool</b> and <b>Cold</b> tiers using the actual observed load, then recommend the cheapest tier.</p>
        <p>The math per tier is:</p>
        <pre style="background:#F3F2F1;padding:12px;border-radius:6px;font-size:12.5px;line-height:1.7;">TotalCost = CapacityGB × capacity_price(tier) × redundancy_multiplier(sku)
          + (writes / 10,000) × write_price(tier) × geo_write_multiplier(sku)
          + (reads  / 10,000) × read_price(tier)
          + <b>small_blob_penalty</b>   (Cool/Cold only, see below)</pre>

        <h4>Small-blob write penalty (128 KB minimum billable object size)</h4>
        <p>In the Cool and Cold tiers, <b>every PUT/write of a blob smaller than 128 KB is billed for capacity as if it were 128 KB</b>. If the workload writes many small objects (log records, telemetry, small JSON docs), this penalty can multiply the Cool/Cold capacity bill by 10x-100x and completely eliminate the tier's expected savings. The tool estimates average written blob size as <code>Ingress bytes / write ops</code> and adds the penalty to the projection when &lt; 128 KB.</p>

        <h4>Geo-write transaction multiplier</h4>
        <p>Geo-redundant SKUs (<code>GRS</code>, <code>RA-GRS</code>, <code>GZRS</code>, <code>RA-GZRS</code>) replicate every write to the secondary region. That means <b>every write operation is billed for both regions</b>, effectively doubling the write-ops line item. This is one of the hidden multipliers behind unexpected bill increases and is included in the cost projection.</p>

        <h4>Redundancy uplifts (LRS = 1.00x baseline for capacity)</h4>
        <p><code>ZRS</code> = 1.25x · <code>GRS</code> = 2.00x · <code>RA-GRS</code> = 2.50x · <code>GZRS</code> = 2.50x · <code>RA-GZRS</code> = 3.13x</p>

        <h3 style="margin-top:20px;">GPv1 → GPv2 migration warning</h3>
        <p>GPv2 uses tier-based per-transaction pricing that is <b>2–5x higher</b> than GPv1 for Cool/Cold tiers on the write ops, and it also applies the 128 KB minimum-billable-blob rule. Migrating a GPv1 account to GPv2 <b>without validating the correct access tier for the observed workload</b> is the #1 cause of unexpected bill spikes (a real customer case saw a ~150x jump). For every GPv1 account still in the tenant, a High-severity Cost finding surfaces so the team can plan the migration correctly.</p>

        <h3 style="margin-top:20px;">Estimates and validation</h3>
        <p>Savings are directional and use public list prices (East US region baseline). They do <b>not</b> reflect EA/CSP discounts, reservations, or region-specific meters. Validate every recommendation against the actual bill in <b>Cost Management + Billing</b> before applying changes.</p>
        <p>Every finding includes a <code>Verify command</code> that reproduces the underlying evidence from any authenticated Cloud Shell or CLI, so any change proposal is directly auditable by the customer.</p>

        <p class="tiny muted" style="margin-top:16px;">Report generated by <code>Invoke-StorageAccountOptimizer.ps1</code> v__SCRIPT_VERSION__. The tool is strictly read-only and does not modify any Azure resource.</p>
      </div>
    </div>
  </section>

</div>

<!-- Drill-down modal -->
<div id="drill" class="modal-bg">
  <div class="modal">
    <div class="modal-head">
      <h3 id="drillTitle"></h3>
      <button class="btn subtle" onclick="closeDrill()">Close</button>
    </div>
    <div class="modal-body" id="drillBody"></div>
  </div>
</div>

<!-- Data (inert JSON blocks) -->
<script type="application/json" id="data-accounts">__ACCOUNTS_JSON__</script>
<script type="application/json" id="data-findings">__FINDINGS_JSON__</script>
<script type="application/json" id="data-agg">__AGG_JSON__</script>
<script type="application/json" id="data-subs">__SUBS_JSON__</script>
<script type="application/json" id="data-compare">__COMPARE_JSON__</script>

<script>
window.addEventListener('error', e => console.error('[Optimizer]', e.message, e.filename, e.lineno));

function loadJson(id, fallback) {
  const el = document.getElementById(id);
  if (!el) return fallback;
  try { return JSON.parse(el.textContent); } catch(e) { console.error('loadJson '+id, e); return fallback; }
}
const ACCOUNTS = loadJson('data-accounts', []);
const FINDINGS = loadJson('data-findings', []);
const AGG      = loadJson('data-agg',      { byPillar:[], byCategory:[], bySeverity:[] });
const SUBS     = loadJson('data-subs',     []);
const COMPARE  = loadJson('data-compare',  null);

// Build a set of prior finding keys (Account+Title) so we can flag current findings
// as "new" and prior ones as "resolved" in the UI.
const PRIOR_FINDING_KEYS = (COMPARE && COMPARE.Findings) ? new Set(COMPARE.Findings.map(f => f.Account + '||' + f.Title)) : null;
const CURRENT_FINDING_KEYS = new Set();
function findingKey(f) { return f.Account + '||' + f.Title; }

['byPillar','byCategory','bySeverity'].forEach(k => {
  if (!Array.isArray(AGG[k])) { AGG[k] = AGG[k] ? [AGG[k]] : []; }
});

// ------------- Global impact sort -------------
// Order recommendations by importance so the highest-impact items are always at top.
// Severity outranks $ (a Critical security finding with $0 impact still beats a Low
// $1/mo cost finding), and within the same severity we sort by $ savings desc.
const SEVERITY_RANK = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };
function impactCompare(a, b) {
  const sr = (SEVERITY_RANK[b.Severity]||0) - (SEVERITY_RANK[a.Severity]||0);
  if (sr !== 0) return sr;
  return (b.EstimatedMonthlySavingsUsd||0) - (a.EstimatedMonthlySavingsUsd||0);
}
FINDINGS.sort(impactCompare);

// Pre-compute per-account aggregate savings + max severity so we can sort accounts by
// "attention needed" in every table (Overview and Accounts tab).
const ACCOUNT_IMPACT = {};
FINDINGS.forEach(f => {
  const k = f.ResourceId;
  const cur = ACCOUNT_IMPACT[k] || { savings: 0, maxSev: 0, count: 0 };
  cur.savings += (f.EstimatedMonthlySavingsUsd || 0);
  cur.maxSev   = Math.max(cur.maxSev, SEVERITY_RANK[f.Severity] || 0);
  cur.count   += 1;
  ACCOUNT_IMPACT[k] = cur;
});
function accountImpactCompare(a, b) {
  const ia = ACCOUNT_IMPACT[a.ResourceId] || { savings: 0, maxSev: 0, count: 0 };
  const ib = ACCOUNT_IMPACT[b.ResourceId] || { savings: 0, maxSev: 0, count: 0 };
  if (ib.maxSev !== ia.maxSev) return ib.maxSev - ia.maxSev;
  if (ib.savings !== ia.savings) return ib.savings - ia.savings;
  return (a.Name||'').localeCompare(b.Name||'');
}
ACCOUNTS.sort(accountImpactCompare);

// ------------- Tabs -------------
function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(x => x.classList.toggle('active', x.dataset.tab === name));
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('hidden', x.id !== 'tab-' + name));
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
document.querySelectorAll('.tab-btn').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));

// Populate tab-count badges so users see how much content is in each tab.
(function fillTabCounts() {
  const f = document.getElementById('tabCountFindings'); if (f) f.textContent = FINDINGS.length;
  const a = document.getElementById('tabCountAccounts'); if (a) a.textContent = ACCOUNTS.length;
})();

// ------------- Scope selector (subscription filter that drives the whole report) -------------
// window.__scope = ''  means "All tenant" (default). Otherwise it's a SubscriptionName.
window.__scope = '';
function scopedAccounts() { return window.__scope ? ACCOUNTS.filter(a => a.SubscriptionName === window.__scope) : ACCOUNTS; }
function scopedFindings() { return window.__scope ? FINDINGS.filter(f => f.SubscriptionName === window.__scope) : FINDINGS; }

function applyScope() {
  const accs = scopedAccounts();
  const fnds = scopedFindings();
  const totalSavings = fnds.reduce((s,f) => s + (f.EstimatedMonthlySavingsUsd||0), 0);
  const sev = { Critical:0, High:0, Medium:0, Low:0 };
  fnds.forEach(f => { if (sev[f.Severity] != null) sev[f.Severity]++; });
  const pil = { Cost:0, Performance:0 };
  fnds.forEach(f => { if (pil[f.Pillar] != null) pil[f.Pillar]++; });

  const set = (id,v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  set('kpiTotal',    accs.length);
  set('kpiCritical', sev.Critical);
  set('kpiHigh',     sev.High);
  set('kpiMedium',   sev.Medium);
  set('kpiSavings',  '$' + totalSavings.toFixed(2));
  set('pillarCostCount', pil.Cost);
  set('pillarPerfCount', pil.Performance);
  set('tabCountFindings', fnds.length);
  set('tabCountAccounts', accs.length);

  document.body.classList.toggle('scoped', !!window.__scope);
  const label = window.__scope ? ('Scoped to ' + window.__scope + ' - ' + accs.length + ' account(s), ' + fnds.length + ' finding(s)')
                               : ('Full tenant - ' + accs.length + ' account(s), ' + fnds.length + ' finding(s)');
  set('scopeSummary', label);

  // Sync the per-tab subscription filters so navigating from the KPI cards preserves the scope.
  const fSub = document.getElementById('fSub'); if (fSub) fSub.value = window.__scope || '';
  const aSub = document.getElementById('aSub'); if (aSub) aSub.value = window.__scope || '';

  try { renderOverviewTable(); } catch(e){}
  try { renderActionSummary(); } catch(e){}
  try { renderBulkActions();   } catch(e){}
  try { renderFindings();      } catch(e){}
  try { renderAccounts();      } catch(e){}
}

(function initScopeSelector() {
  const sel = document.getElementById('scopeSel'); if (!sel) return;
  const names = [...new Set(SUBS.map(s => s.SubscriptionName))].sort();
  names.forEach(n => { const o = document.createElement('option'); o.value = n; o.textContent = n; sel.appendChild(o); });
  sel.addEventListener('change', () => { window.__scope = sel.value; applyScope(); });
})();

// Called by clickable KPI cards and action-summary widgets.
// options = {severity, pillar, category, sortBy}
// Subscription scope (window.__scope) is preserved so drilling from KPIs stays scoped.
function focusView(target, options) {
  options = options || {};
  if (target === 'overview') { switchTab('overview'); return; }
  if (target === 'findings') {
    document.getElementById('fSeverity').value = options.severity || '';
    document.getElementById('fPillar').value   = options.pillar   || '';
    document.getElementById('fCategory').value = options.category || '';
    document.getElementById('fSub').value      = window.__scope || '';
    document.getElementById('fSearch').value   = '';
    window.__sortFindingsBySavings = (options.sortBy === 'savings');
    switchTab('findings');
    renderFindings();
  }
}

// ------------- Action summary strip (replaces the two donut charts) -------------
function renderActionSummary() {
  try {
    const accs = scopedAccounts();
    const fnds = scopedFindings();
    const tierMismatch = accs.filter(a => a.RecommendedTier && a.RecommendedTier !== a.AccessTier);
    document.getElementById('mmTier').textContent = tierMismatch.length + ' / ' + accs.length;
    const potentialTierSavings = fnds
      .filter(f => f.Category === 'Tier Optimization')
      .reduce((s,f) => s + (f.EstimatedMonthlySavingsUsd||0), 0);
    document.getElementById('mmTierHint').textContent = tierMismatch.length
      ? ('$' + potentialTierSavings.toFixed(2) + '/mo potential savings')
      : 'All aligned';

    // Replication mismatches (SKU): count only accounts where recommended != current.
    const skuMismatch = accs.filter(a => a.RecommendedSku && a.RecommendedSku !== a.Sku);
    document.getElementById('mmSku').textContent = skuMismatch.length + ' / ' + accs.length;
    const potentialSkuSavings = fnds
      .filter(f => f.Category === 'Redundancy')
      .reduce((s,f) => s + (f.EstimatedMonthlySavingsUsd||0), 0);
    document.getElementById('mmSkuHint').textContent = skuMismatch.length
      ? ('$' + potentialSkuSavings.toFixed(2) + '/mo potential savings')
      : 'All aligned';

    const gpv1 = fnds.filter(f => f.Category === 'GPv1 Pre-Migration').length;
    document.getElementById('mmGpv1').textContent = gpv1;

    // Savings by pillar (horizontal mini-bars) — Cost / Performance only
    const pillarSavings = { Cost: 0, Performance: 0 };
    fnds.forEach(f => { if (pillarSavings[f.Pillar] != null) pillarSavings[f.Pillar] += (f.EstimatedMonthlySavingsUsd||0); });
    const maxVal = Math.max(1, pillarSavings.Cost, pillarSavings.Performance);
    const barsHtml = ['Cost','Performance'].map(p => {
      const v = pillarSavings[p];
      const pct = Math.round((v / maxVal) * 100);
      return '<div class="sbar ' + p.toLowerCase() + '" onclick="event.stopPropagation();focusView(\'findings\',{pillar:\'' + p + '\',sortBy:\'savings\'})" style="cursor:pointer;">'
        + '<span class="sbar-label">' + p + '</span>'
        + '<span class="sbar-track"><span class="sbar-fill" style="width:' + pct + '%;"></span></span>'
        + '<span class="sbar-val">$' + v.toFixed(2) + '</span>'
        + '</div>';
    }).join('');
    document.getElementById('savingsBars').innerHTML = barsHtml;
  } catch(e){ console.error('renderActionSummary', e); }
}
renderActionSummary();

// ------------- Bulk actions (group findings by category + normalized recommendation) -------------
function renderBulkActions() {
  try {
    const withScript = scopedFindings().filter(f => f.RemediationScript && f.RemediationScript.trim().length > 0);
    if (!withScript.length) { document.getElementById('bulkActionsCard').style.display = 'none'; return; }

    const groups = {};
    withScript.forEach(f => {
      const key = f.RemediationGroupKey || (f.Category + '|' + f.Title.replace(/\d+(\.\d+)?/g,'#'));
      if (!groups[key]) groups[key] = { key, category: f.Category, findings: [], savings: 0 };
      groups[key].findings.push(f);
      groups[key].savings += (f.EstimatedMonthlySavingsUsd || 0);
    });
    const list = Object.values(groups).sort((a,b) => b.savings - a.savings);

    document.getElementById('bulkActionsCard').style.display = 'block';
    document.getElementById('bulkGroupsList').innerHTML = list.map((g,idx) => {
      const sampleTitle = g.findings[0].Title;
      const accounts = [...new Set(g.findings.map(f => f.Account))];
      return '<div class="bulk-group">'
        + '<div class="bulk-meta">'
          + '<div class="bulk-title"><span class="bulk-count">' + accounts.length + '</span>' + esc(sampleTitle) + '</div>'
          + '<div class="bulk-sub">Category: ' + esc(g.category) + ' &middot; Accounts: ' + accounts.slice(0,4).map(esc).join(', ') + (accounts.length > 4 ? ', +' + (accounts.length-4) + ' more' : '') + '</div>'
        + '</div>'
        + '<div class="bulk-value">$' + g.savings.toFixed(2) + '/mo</div>'
        + '<div class="bulk-actions">'
          + '<button class="btn subtle" onclick="viewBulkGroup(\'' + encodeURIComponent(g.key) + '\')">View</button>'
          + '<button class="btn" onclick="downloadBulkGroup(\'' + encodeURIComponent(g.key) + '\')">Download .sh</button>'
        + '</div>'
      + '</div>';
    }).join('');
    window.__bulkGroups = list.reduce((o,g) => { o[g.key] = g; return o; }, {});
  } catch(e){ console.error('renderBulkActions', e); }
}
renderBulkActions();

// Bulk-group actions
function viewBulkGroup(encodedKey) {
  const key = decodeURIComponent(encodedKey);
  const g = window.__bulkGroups[key];
  if (!g) return;
  document.getElementById('fCategory').value = g.category;
  document.getElementById('fSearch').value = '';
  document.getElementById('fSeverity').value = '';
  document.getElementById('fPillar').value = '';
  document.getElementById('fSub').value = '';
  renderFindings();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
function buildScriptBundle(findings, header) {
  const lines = [
    '#!/usr/bin/env bash',
    '# Azure Storage Optimizer - remediation script',
    '# Generated: ' + new Date().toISOString(),
    '# ' + (header || ('Contains ' + findings.length + ' remediation commands')),
    '# ',
    '# REVIEW EACH COMMAND BEFORE EXECUTING. Some changes affect billing model',
    '# (RA-GRS -> GRS removes the secondary read endpoint) or durability (LRS -> ZRS).',
    '# Recommended: run the "az storage account show" verify commands first.',
    '',
    'set -e',
    ''
  ];
  findings.forEach((f,i) => {
    lines.push('# ---------- ' + (i+1) + '/' + findings.length + ' ----------');
    lines.push('# Account: ' + f.Account + ' (' + f.ResourceGroup + ') | Subscription: ' + f.SubscriptionName);
    lines.push('# Title:   ' + f.Title);
    lines.push('# Impact:  $' + (f.EstimatedMonthlySavingsUsd||0).toFixed(2) + '/mo (est.)');
    lines.push(f.RemediationScript);
    lines.push('');
  });
  return lines.join('\n');
}
function downloadText(name, text) {
  const blob = new Blob([text], { type: 'text/x-shellscript' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 500);
}
function downloadBulkGroup(encodedKey) {
  const key = decodeURIComponent(encodedKey);
  const g = window.__bulkGroups[key];
  if (!g) return;
  const safeKey = key.replace(/[^a-z0-9]+/gi,'_').slice(0,60);
  downloadText('remediation_' + safeKey + '.sh', buildScriptBundle(g.findings, 'Bulk remediation for group: ' + key));
}
function downloadAllRemediations() {
  const withScript = FINDINGS.filter(f => f.RemediationScript && f.RemediationScript.trim().length > 0);
  downloadText('remediation_all_findings.sh', buildScriptBundle(withScript, 'ALL remediations for this run (sorted by impact)'));
}
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = originalText; }, 1500);
  }).catch(() => alert('Copy failed. Please select the text manually.'));
}

// ------------- Helpers -------------
function esc(v) { return (v==null?'':String(v)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function sevBadge(s) {
  const m = { Critical:'b-crit', High:'b-high', Medium:'b-med', Low:'b-low' };
  return '<span class="badge ' + (m[s]||'b-info') + '">' + s + '</span>';
}
function pillarBadge(p) {
  const m = { Cost:'b-cost', Performance:'b-performance', Security:'b-security' };
  return '<span class="badge ' + (m[p]||'b-info') + '">' + (p||'-') + '</span>';
}
function boolBadge(v, yesLabel, noLabel) {
  if (v === true)  return '<span class="badge b-yes">' + (yesLabel||'Yes') + '</span>';
  if (v === false) return '<span class="badge b-no">'  + (noLabel||'No')  + '</span>';
  return '<span class="muted">-</span>';
}
// Recommendation badge for the tier column. Includes native tooltip (title attribute)
// with the human-readable reason so users see the "why" on hover, and a "?" affordance
// that hints at the click-through drill-down.
function tierRecoBadge(a) {
  if (!a.RecommendedTier) return '<span class="muted">-</span>';
  const reason = a.TierRecommendationReason || '';
  const titleAttr = reason ? ' title="' + reason.replace(/"/g,'&quot;') + '"' : '';
  if (a.AccessTier === a.RecommendedTier) {
    return '<span class="badge b-yes"' + titleAttr + '>' + esc(a.RecommendedTier) + ' (match)</span>';
  }
  return '<span class="badge b-low"' + titleAttr + '>&#8594; ' + esc(a.RecommendedTier)
       + (reason ? ' <span class="tiny" style="opacity:.7;">?</span>' : '') + '</span>';
}
// Recommendation badge for the replication (SKU) column. Same visual language as tier,
// but the "match" state includes the confidence level: 'safe' (RA-GRS -> GRS), 'upgrade'
// (LRS -> ZRS for durability), or 'informational' (keep current, DR is a business call).
function skuRecoBadge(a) {
  if (!a.RecommendedSku) return '<span class="muted">-</span>';
  const reason = a.SkuRecommendationReason || '';
  const titleAttr = reason ? ' title="' + reason.replace(/"/g,'&quot;') + '"' : '';
  const short = s => (s||'').replace('Standard_','');
  if (a.Sku === a.RecommendedSku) {
    return '<span class="badge b-yes"' + titleAttr + '>' + esc(short(a.RecommendedSku)) + ' (match)</span>';
  }
  const conf = a.SkuRecommendationDetails?.Confidence || 'informational';
  const cls = conf === 'safe' ? 'b-low' : (conf === 'upgrade' ? 'b-med' : 'b-info');
  return '<span class="badge ' + cls + '"' + titleAttr + '>&#8594; ' + esc(short(a.RecommendedSku))
       + (reason ? ' <span class="tiny" style="opacity:.7;">?</span>' : '') + '</span>';
}

// ------------- Populate filters -------------
function fillSelect(id, values) {
  const s = document.getElementById(id);
  values.forEach(v => { const o = document.createElement('option'); o.value=v; o.textContent=v; s.appendChild(o); });
}
fillSelect('fCategory', [...new Set(FINDINGS.map(f=>f.Category))].sort());
fillSelect('fSub', SUBS.map(s=>s.SubscriptionName));
fillSelect('aSub', SUBS.map(s=>s.SubscriptionName));
fillSelect('aTier', [...new Set(ACCOUNTS.map(a=>a.AccessTier || 'n/a'))].sort());

// ------------- Findings table -------------
function renderFindings() {
  const q  = document.getElementById('fSearch').value.toLowerCase();
  const sv = document.getElementById('fSeverity').value;
  const pl = document.getElementById('fPillar').value;
  const ct = document.getElementById('fCategory').value;
  const su = document.getElementById('fSub').value;
  let rows = FINDINGS.filter(f =>
    (!q || (f.Account+' '+f.Title+' '+f.Category+' '+(f.Description||'')).toLowerCase().includes(q)) &&
    (!sv || f.Severity === sv) &&
    (!pl || f.Pillar   === pl) &&
    (!ct || f.Category === ct) &&
    (!su || f.SubscriptionName === su)
  );
  if (window.__sortFindingsBySavings) rows = rows.slice().sort((a,b) => (b.EstimatedMonthlySavingsUsd||0)-(a.EstimatedMonthlySavingsUsd||0));
  const tbody = document.querySelector('#tblFindings tbody');
  tbody.innerHTML = rows.map((f,i) => {
    let diff = '';
    if (PRIOR_FINDING_KEYS) {
      CURRENT_FINDING_KEYS.add(findingKey(f));
      diff = PRIOR_FINDING_KEYS.has(findingKey(f)) ? '<span class="diff-badge diff-open">open</span>' : '<span class="diff-badge diff-new">new</span>';
    }
    return '<tr onclick="showFinding('+FINDINGS.indexOf(f)+')">'
      + '<td>' + sevBadge(f.Severity) + '</td>'
      + '<td>' + pillarBadge(f.Pillar) + '</td>'
      + '<td>' + esc(f.Category) + '</td>'
      + '<td><b>' + esc(f.Account) + '</b></td>'
      + '<td>' + esc(f.SubscriptionName) + '</td>'
      + '<td>' + esc(f.Title) + diff + '</td>'
      + '<td class="right">' + (f.EstimatedMonthlySavingsUsd||0).toFixed(2) + '</td>'
      + '</tr>';
  }).join('') || '<tr><td colspan="7" class="empty">No findings match the current filters.</td></tr>';
  document.getElementById('fCount').textContent = rows.length + ' finding(s)';
}
['fSearch','fPillar','fSeverity','fCategory','fSub'].forEach(id => document.getElementById(id).addEventListener('input', () => { window.__sortFindingsBySavings=false; renderFindings(); }));
renderFindings();

function showFinding(i) {
  const f = FINDINGS[i]; if (!f) return;
  document.getElementById('drillTitle').textContent = f.Title;
  let h = '<div style="margin-bottom:12px;">' + sevBadge(f.Severity) + ' ' + pillarBadge(f.Pillar) + ' <span class="badge b-info">' + esc(f.Category) + '</span></div>';
  h += '<p><b>Account:</b> ' + esc(f.Account) + ' (' + esc(f.ResourceGroup) + ') - ' + esc(f.SubscriptionName) + '</p>';
  h += '<div style="margin:8px 0;"><b>Description.</b><div style="white-space:pre-wrap;margin-top:4px;">' + esc(f.Description) + '</div></div>';
  h += '<p><b>Recommendation.</b> ' + esc(f.Recommendation) + '</p>';
  if (f.Impact)   h += '<p><b>Impact.</b> '   + esc(f.Impact)   + '</p>';
  if (f.Evidence) h += '<p><b>Evidence.</b> <code>' + esc(f.Evidence) + '</code></p>';
  if (f.EstimatedMonthlySavingsUsd) h += '<p><b>Estimated monthly savings.</b> <span class="badge b-cost">$' + f.EstimatedMonthlySavingsUsd.toFixed(2) + '</span></p>';
  if (f.VerifyCommand) h += '<p><b>Validate in your console.</b><br><code>' + esc(f.VerifyCommand) + '</code></p>';
  if (f.RemediationScript) {
    const scriptId = 'rem-script-' + i;
    h += '<div style="margin-top:12px;padding:12px;border:1px solid var(--neutral-30);border-radius:6px;background:var(--neutral-10);">'
      + '<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:6px;">'
        + '<b>Remediation command</b>'
        + '<button class="btn subtle" style="font-size:12px;padding:5px 10px;" onclick="copyToClipboard(document.getElementById(\'' + scriptId + '\').textContent, this)">Copy</button>'
      + '</div>'
      + '<pre id="' + scriptId + '" style="margin:0;white-space:pre-wrap;font-size:12px;font-family:\'Cascadia Code\',Consolas,monospace;color:var(--neutral-190);">' + esc(f.RemediationScript) + '</pre>'
      + '</div>';
  }
  h += '<p class="tiny muted" style="margin-top:16px;">Resource ID: <code>' + esc(f.ResourceId) + '</code></p>';
  document.getElementById('drillBody').innerHTML = h;
  document.getElementById('drill').classList.add('open');
}

// ------------- Accounts table -------------
function renderAccounts() {
  const q  = document.getElementById('aSearch').value.toLowerCase();
  const su = document.getElementById('aSub').value;
  const tr = document.getElementById('aTier').value;
  const rows = ACCOUNTS.filter(a =>
    (!q || (a.Name+' '+a.ResourceGroup+' '+a.Location).toLowerCase().includes(q)) &&
    (!su || a.SubscriptionName === su) && (!tr || (a.AccessTier||'n/a') === tr)
  );
  const findByAcc = {};
  FINDINGS.forEach(f => { findByAcc[f.ResourceId] = (findByAcc[f.ResourceId]||0) + 1; });
  const tbody = document.querySelector('#tblAccounts tbody');
  tbody.innerHTML = rows.map(a =>
    '<tr onclick="showAccount(\'' + a.ResourceId + '\')">'
    + '<td><b>' + esc(a.Name) + '</b></td>'
    + '<td>' + esc(a.SubscriptionName) + '</td>'
    + '<td>' + esc(a.ResourceGroup) + '</td>'
    + '<td>' + esc(a.Location) + '</td>'
    + '<td>' + esc(a.Kind) + '</td>'
    + '<td>' + esc(a.Sku) + '</td>'
    + '<td>' + skuRecoBadge(a) + '</td>'
    + '<td>' + esc(a.AccessTier||'n/a') + '</td>'
    + '<td>' + tierRecoBadge(a) + '</td>'
    + '<td class="right">' + (a.UsedCapacityGB||0).toFixed(2) + '</td>'
    + '<td class="right">' + (a.TransactionsMonthly||0).toLocaleString() + '</td>'
    + '<td class="right">' + (a.EgressGBMonthly||0).toFixed(2) + '</td>'
    + '<td class="right">' + (findByAcc[a.ResourceId]||0) + '</td>'
    + '</tr>'
  ).join('') || '<tr><td colspan="13" class="empty">No accounts match the current filters.</td></tr>';
  document.getElementById('aCount').textContent = rows.length + ' account(s)';
}
['aSearch','aSub','aTier'].forEach(id => document.getElementById(id).addEventListener('input', renderAccounts));
renderAccounts();

// ------------- Overview table -------------
function renderOverviewTable() {
  const findByAcc = {};
  scopedFindings().forEach(f => { findByAcc[f.ResourceId] = (findByAcc[f.ResourceId]||0) + 1; });
  const tbody = document.querySelector('#tblOverview tbody');
  tbody.innerHTML = scopedAccounts().map(a =>
    '<tr onclick="showAccount(\'' + a.ResourceId + '\')">'
    + '<td><b>' + esc(a.Name) + '</b></td>'
    + '<td>' + esc(a.SubscriptionName) + '</td>'
    + '<td>' + esc(a.Location) + '</td>'
    + '<td>' + esc(a.Kind) + '</td>'
    + '<td>' + esc(a.Sku) + '</td>'
    + '<td>' + skuRecoBadge(a) + '</td>'
    + '<td>' + esc(a.AccessTier||'n/a') + '</td>'
    + '<td>' + tierRecoBadge(a) + '</td>'
    + '<td class="right">' + (a.UsedCapacityGB||0).toFixed(2) + '</td>'
    + '<td class="right">' + (a.TransactionsMonthly||0).toLocaleString() + '</td>'
    + '<td class="right">' + (a.EgressGBMonthly||0).toFixed(2) + '</td>'
    + '<td class="right">' + (a.LifecycleRules||0) + '</td>'
    + '<td>' + boolBadge(a.Versioning) + '</td>'
    + '<td class="right">' + (findByAcc[a.ResourceId]||0) + '</td>'
    + '</tr>'
  ).join('') || '<tr><td colspan="14" class="empty">No storage accounts found.</td></tr>';
}
try { renderOverviewTable(); } catch(e){ console.error('renderOverviewTable', e); }

function showAccount(id) {
  const a = ACCOUNTS.find(x => x.ResourceId === id); if (!a) return;
  const fs = FINDINGS.filter(f => f.ResourceId === id);
  document.getElementById('drillTitle').textContent = a.Name + '  -  configuration & findings';
  const cfg = [
    ['Subscription', a.SubscriptionName],
    ['Resource group', a.ResourceGroup],
    ['Location', a.Location],
    ['Kind', a.Kind],
    ['SKU (redundancy)', a.Sku],
    ['Access tier', a.AccessTier||'n/a'],
    ['Lifecycle rules', a.LifecycleRules||0],
    ['Soft-delete days', a.SoftDeleteDays||0],
    ['Blob versioning', a.Versioning ? 'Enabled' : 'Disabled'],
    ['Used capacity (GB)', (a.UsedCapacityGB||0).toFixed(2)],
    ['Transactions / month', (a.TransactionsMonthly||0).toLocaleString()],
    ['Reads / month', (a.ReadMonthly||0).toLocaleString()],
    ['Writes / month', (a.WriteMonthly||0).toLocaleString()],
    ['Ingress GB / month', (a.IngressGBMonthly||0).toFixed(2)],
    ['Egress GB / month', (a.EgressGBMonthly||0).toFixed(2)],
    ['Availability %', a.Availability!=null?a.Availability:'-']
  ];
  let cfgHtml = '<h4 style="margin:0 0 10px;color:#323130;">Configuration</h4><div class="cfg-grid">';
  cfg.forEach(kv => { cfgHtml += '<div class="k">' + esc(kv[0]) + '</div><div class="v">' + esc(kv[1]) + '</div>'; });
  cfgHtml += '</div>';

  // ---- Tier cost projection ----
  let projHtml = '';
  if (a.TierProjections && a.TierProjections.length) {
    const cheapest = a.RecommendedTier;
    const changes  = cheapest && a.AccessTier !== cheapest;

    // Structured recommendation callout — clearly separated sections so users see
    // (1) the headline recommendation, (2) where the numbers come from, (3) the
    // observed pattern in plain language, (4) why that pattern favors this tier,
    // and (5) the concrete action to take.
    if (a.TierRecommendationDetails || a.TierRecommendationReason) {
      const bg    = changes ? '#DEECF9' : '#DFF6DD';
      const brd   = changes ? '#0078D4' : '#107C10';
      const head  = changes
        ? ('Recommendation: change access tier from <b>' + esc(a.AccessTier||'n/a') + '</b> to <b>' + esc(cheapest) + '</b>')
        : ('Current tier <b>' + esc(a.AccessTier||'n/a') + '</b> is already the cheapest for this workload.');
      const d = a.TierRecommendationDetails;
      let body = '';
      if (d) {
        if (d.Observations && d.Observations.length) {
          body += '<div style="margin-top:10px;"><span style="color:#605E5C;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;">What we observed</span>'
                + '<ul style="margin:4px 0 0 0;padding-left:20px;">'
                + d.Observations.map(o => '<li style="margin:2px 0;">' + esc(o) + '</li>').join('')
                + '</ul></div>';
        }
        if (d.Interpretation) {
          body += '<div style="margin-top:10px;"><span style="color:#605E5C;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;">Why this tier is cheapest</span>'
                + '<div style="margin-top:2px;">' + esc(d.Interpretation) + '</div></div>';
        }
        if (d.Action) {
          body += '<div style="margin-top:10px;"><span style="color:#605E5C;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;">Action</span>'
                + '<div style="margin-top:2px;font-weight:500;color:#323130;">' + esc(d.Action) + '</div></div>';
        }
        if (d.MetricsUsed && d.MetricsUsed.length) {
          body += '<details class="reveal-metrics" style="margin-top:14px;">'
                + '<summary style="cursor:pointer;color:#0078D4;font-weight:600;font-size:12.5px;list-style:none;">View metrics used <span style="opacity:.6;font-weight:500;">(Azure Monitor definitions used to compute this recommendation)</span></summary>'
                + '<div style="margin-top:8px;padding:10px 12px;background:rgba(255,255,255,0.7);border:1px solid #EDEBE9;border-radius:4px;font-size:12px;line-height:1.6;color:#484644;">'
                + (d.DataSource ? '<div style="margin-bottom:6px;">' + esc(d.DataSource) + '</div>' : '')
                + d.MetricsUsed.map(m => '<div style="margin:2px 0;font-family:\'Cascadia Code\',Consolas,monospace;font-size:11.5px;">' + esc(m) + '</div>').join('')
                + '</div></details>';
        }
      } else {
        body = '<div style="margin-top:8px;">Why: ' + esc(a.TierRecommendationReason) + '</div>';
      }
      projHtml += '<div style="background:' + bg + ';border-left:4px solid ' + brd + ';padding:16px 18px;border-radius:6px;margin:12px 0 14px;font-size:13px;color:#484644;line-height:1.55;">'
        + '<div style="font-weight:600;color:#323130;font-size:14px;">' + head + '</div>'
        + body
        + '</div>';
    }

    projHtml += '<h4 style="margin:12px 0 8px;color:#323130;">Tier cost projection at observed usage <span class="tiny muted">(capacity + read ops + write ops + Cool/Cold small-blob penalty)</span></h4>';
    projHtml += '<table class="data" style="margin-bottom:16px;"><thead><tr>'
      + '<th>Tier</th><th class="right">Capacity</th><th class="right">Read ops</th><th class="right">Write ops</th><th class="right">Small-blob penalty</th><th class="right">Total / month</th><th></th>'
      + '</tr></thead><tbody>';
    a.TierProjections.forEach(p => {
      const isCurrent = p.Tier === a.AccessTier;
      const isReco    = p.Tier === cheapest;
      let flag = '';
      if (isCurrent && isReco) flag = '<span class="badge b-yes">current & recommended</span>';
      else if (isCurrent)      flag = '<span class="badge b-warn">current</span>';
      else if (isReco)         flag = '<span class="badge b-cost">recommended</span>';
      projHtml += '<tr' + (isReco ? ' style="background:#DFF6DD;"' : '') + '>'
        + '<td><b>' + p.Tier + '</b></td>'
        + '<td class="right">$' + p.CapacityCost.toFixed(2) + '</td>'
        + '<td class="right">$' + p.ReadOpsCost.toFixed(2) + '</td>'
        + '<td class="right">$' + p.WriteOpsCost.toFixed(2) + '</td>'
        + '<td class="right">' + (p.SmallWritePenalty > 0 ? '$'+p.SmallWritePenalty.toFixed(2) : '-') + '</td>'
        + '<td class="right"><b>$' + p.TotalCost.toFixed(2) + '</b></td>'
        + '<td>' + flag + '</td>'
        + '</tr>';
    });
    projHtml += '</tbody></table>';
    if (a.TierProjections[0].AvgBlobSizeKB) {
      projHtml += '<p class="tiny muted">Average written blob size estimated from ingress / write ops: <b>' + a.TierProjections[0].AvgBlobSizeKB.toFixed(1) + ' KB</b>. If &lt; 128 KB, Cool/Cold tiers apply a minimum-billable-blob penalty for each PUT.</p>';
    }
  }

  // ---- Replication (SKU) cost projection ----
  if (a.SkuProjections && a.SkuProjections.length && a.SkuRecommendationDetails) {
    const d = a.SkuRecommendationDetails;
    const changes = a.RecommendedSku && a.Sku !== a.RecommendedSku;
    const conf = d.Confidence || 'informational';
    const bg  = conf === 'safe'    ? '#DEECF9'
              : conf === 'upgrade' ? '#FFF4CE'
              : '#F3F2F1';
    const brd = conf === 'safe'    ? '#0078D4'
              : conf === 'upgrade' ? '#FFB900'
              : '#C8C6C4';
    const head = changes
      ? ('Replication recommendation: ' + esc(a.Sku.replace('Standard_','')) + ' &#8594; ' + esc(a.RecommendedSku.replace('Standard_','')))
      : ('Current replication <b>' + esc(a.Sku.replace('Standard_','')) + '</b> is aligned with the observed usage.');
    let body = '';
    if (d.Observations && d.Observations.length) {
      body += '<div style="margin-top:10px;"><span style="color:#605E5C;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;">What we observed</span>'
            + '<ul style="margin:4px 0 0 0;padding-left:20px;">'
            + d.Observations.map(o => '<li style="margin:2px 0;">' + esc(o) + '</li>').join('')
            + '</ul></div>';
    }
    if (d.Interpretation) {
      body += '<div style="margin-top:10px;"><span style="color:#605E5C;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;">Why</span>'
            + '<div style="margin-top:2px;">' + esc(d.Interpretation) + '</div></div>';
    }
    if (d.Action) {
      body += '<div style="margin-top:10px;"><span style="color:#605E5C;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;">Action</span>'
            + '<div style="margin-top:2px;font-weight:500;color:#323130;">' + esc(d.Action) + '</div></div>';
    }
    if (d.MetricsUsed && d.MetricsUsed.length) {
      body += '<details class="reveal-metrics" style="margin-top:14px;">'
            + '<summary style="cursor:pointer;color:#0078D4;font-weight:600;font-size:12.5px;list-style:none;">View metrics used <span style="opacity:.6;font-weight:500;">(Azure Monitor definitions used to compute this recommendation)</span></summary>'
            + '<div style="margin-top:8px;padding:10px 12px;background:rgba(255,255,255,0.7);border:1px solid #EDEBE9;border-radius:4px;font-size:12px;line-height:1.6;color:#484644;">'
            + (d.DataSource ? '<div style="margin-bottom:6px;">' + esc(d.DataSource) + '</div>' : '')
            + d.MetricsUsed.map(m => '<div style="margin:2px 0;font-family:\'Cascadia Code\',Consolas,monospace;font-size:11.5px;">' + esc(m) + '</div>').join('')
            + '</div></details>';
    }
    projHtml += '<div style="background:' + bg + ';border-left:4px solid ' + brd + ';padding:16px 18px;border-radius:6px;margin:16px 0 14px;font-size:13px;color:#484644;line-height:1.55;">'
              + '<div style="font-weight:600;color:#323130;font-size:14px;">' + head + '</div>' + body + '</div>';

    projHtml += '<h4 style="margin:12px 0 8px;color:#323130;">Replication cost projection at your current tier <span class="tiny muted">(same capacity + ops, different SKU multiplier + geo-write cost)</span></h4>';
    projHtml += '<table class="data" style="margin-bottom:16px;"><thead><tr><th>Replication</th><th class="right">Total / month</th><th></th></tr></thead><tbody>';
    a.SkuProjections.forEach(p => {
      const isCurrent = p.Sku === a.Sku;
      const isReco    = p.Sku === a.RecommendedSku;
      let flag = '';
      if (isCurrent && isReco) flag = '<span class="badge b-yes">current & recommended</span>';
      else if (isCurrent)      flag = '<span class="badge b-warn">current</span>';
      else if (isReco)         flag = '<span class="badge b-cost">recommended</span>';
      projHtml += '<tr' + (isReco ? ' style="background:#DFF6DD;"' : '') + '>'
        + '<td><b>' + esc(p.Sku.replace('Standard_','')) + '</b></td>'
        + '<td class="right"><b>$' + p.TotalCost.toFixed(2) + '</b></td>'
        + '<td>' + flag + '</td></tr>';
    });
    projHtml += '</tbody></table>';
  }

  let fHtml = '<h4 style="margin:8px 0 10px;color:#323130;">Findings (' + fs.length + ')</h4>';
  if (fs.length) {
    fs.forEach(f => {
      const cls = ({Critical:'crit',High:'high',Medium:'med',Low:'low'})[f.Severity]||'low';
      fHtml += '<details class="finding ' + cls + '">';
      fHtml += '<summary>' + sevBadge(f.Severity) + ' ' + pillarBadge(f.Pillar) + ' ' + esc(f.Title) + ' <span class="tiny muted">- ' + esc(f.Category) + '</span></summary>';
      fHtml += '<div style="white-space:pre-wrap;margin:8px 0;">' + esc(f.Description) + '</div>';
      fHtml += '<p><b>Recommendation.</b> ' + esc(f.Recommendation) + '</p>';
      if (f.Impact)   fHtml += '<p><b>Impact.</b> '   + esc(f.Impact)   + '</p>';
      if (f.Evidence) fHtml += '<p><b>Evidence.</b> <code>' + esc(f.Evidence) + '</code></p>';
      if (f.EstimatedMonthlySavingsUsd) fHtml += '<p><b>Est. savings.</b> <span class="badge b-cost">$' + f.EstimatedMonthlySavingsUsd.toFixed(2) + '/mo</span></p>';
      if (f.VerifyCommand) fHtml += '<p><b>Verify:</b> <code>' + esc(f.VerifyCommand) + '</code></p>';
      fHtml += '</details>';
    });
  } else {
    fHtml += '<p class="muted">No optimization findings for this account. Configuration is aligned with best practices for the observed usage pattern.</p>';
  }

  // Growth forecast + real cost widget (only rendered when data is present).
  let widgetsHtml = '';
  if (a.CapacityForecast || a.RealCost) {
    widgetsHtml += '<h4 style="margin:16px 0 6px;color:#323130;">Trend &amp; billing signal</h4><div class="kv-panel">';
    if (a.CapacityForecast) {
      const fc = a.CapacityForecast;
      const dirBadge = fc.Direction === 'growing' ? '<span class="badge b-warn">growing</span>' : (fc.Direction === 'shrinking' ? '<span class="badge b-yes">shrinking</span>' : '<span class="badge b-info">stable</span>');
      widgetsHtml += '<div><div class="kv-label">Trend</div><div class="kv-value">' + dirBadge + '</div><div class="kv-hint">R&sup2; ' + (fc.RSquared||0).toFixed(2) + ' &middot; ' + fc.DataPoints + ' data points</div></div>';
      widgetsHtml += '<div><div class="kv-label">Monthly growth</div><div class="kv-value">' + (fc.MonthlyGrowthGB>=0?'+':'') + (fc.MonthlyGrowthGB||0).toFixed(2) + ' GB</div><div class="kv-hint">' + (fc.DailyGrowthGB||0).toFixed(3) + ' GB/day slope</div></div>';
      widgetsHtml += '<div><div class="kv-label">Forecast +6 mo</div><div class="kv-value">' + (fc.Forecast6MoGB||0).toFixed(1) + ' GB</div><div class="kv-hint">from ' + (fc.CurrentGB||0).toFixed(1) + ' GB today</div></div>';
      widgetsHtml += '<div><div class="kv-label">Forecast +12 mo</div><div class="kv-value">' + (fc.Forecast12MoGB||0).toFixed(1) + ' GB</div><div class="kv-hint">linear projection (best-effort)</div></div>';
    }
    if (a.RealCost) {
      widgetsHtml += '<div><div class="kv-label">Real cost (last 30d)</div><div class="kv-value">$' + (a.RealCost.Last30DaysUsd||0).toFixed(2) + '</div><div class="kv-hint">' + esc(a.RealCost.Source||'') + '</div></div>';
    }
    widgetsHtml += '</div>';
  }

  document.getElementById('drillBody').innerHTML = cfgHtml + widgetsHtml + projHtml + fHtml;
  document.getElementById('drill').classList.add('open');
}

function closeDrill() { document.getElementById('drill').classList.remove('open'); }
document.getElementById('drill').addEventListener('click', e => { if (e.target.id === 'drill') closeDrill(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrill(); });

// ------------- Excel export -------------
function exportExcel(kind) {
  const wb = XLSX.utils.book_new();
  if (kind === 'findings') {
    const rows = FINDINGS.map(f => ({
      Severity: f.Severity, Pillar: f.Pillar, Category: f.Category, Account: f.Account, ResourceGroup: f.ResourceGroup,
      Subscription: f.SubscriptionName, Location: f.Location, Title: f.Title,
      Description: f.Description, Recommendation: f.Recommendation, Impact: f.Impact,
      Evidence: f.Evidence, 'Est. Monthly Savings USD': f.EstimatedMonthlySavingsUsd,
      'Verify Command': f.VerifyCommand, ResourceId: f.ResourceId
    }));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), 'Findings');
  } else if (kind === 'accounts') {
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(ACCOUNTS), 'Accounts');
    const rows = FINDINGS.map(f => ({
      Severity: f.Severity, Pillar: f.Pillar, Category: f.Category, Account: f.Account, Title: f.Title,
      Recommendation: f.Recommendation, 'Est. USD/mo': f.EstimatedMonthlySavingsUsd
    }));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), 'Findings');
  }
  XLSX.writeFile(wb, 'StorageOptimizer_' + kind + '___RUNID__.xlsx');
}
</script>
</body>
</html>
'@

# Safety: neutralize sequences that could break out of the <script> tag or open HTML comments.
function Protect-JsonForHtml { param([string] $Json) $Json.Replace('</','<\/').Replace('<!--','<\!--') }
$accountsJsonSafe = Protect-JsonForHtml $accountsJson
$findingsJsonSafe = Protect-JsonForHtml $findingsJson
$aggJsonSafe      = Protect-JsonForHtml $aggJson
$subsJsonSafe     = Protect-JsonForHtml $subsJson

# Prior-run summary for comparison. Keep it small — only title+account is needed
# to identify a finding as "resolved" or "still open" on the next run.
$compareJson = if ($compareData) {
    $priorFindings = @($compareData.Findings | ForEach-Object {
        [pscustomobject]@{ Account=$_.Account; Title=$_.Title; Category=$_.Category; EstimatedMonthlySavingsUsd=$_.EstimatedMonthlySavingsUsd }
    })
    [ordered]@{
        RunId       = $compareData.RunId
        GeneratedAt = $compareData.GeneratedAt
        Findings    = $priorFindings
    } | ConvertTo-Json -Depth 4 -Compress
} else { 'null' }
$compareJsonSafe = Protect-JsonForHtml $compareJson

# Substitute placeholders (data is injected here so JS/HTML stays 100% literal above)
$html = $htmlTemplate.
    Replace('__RUNID__',          $runId).
    Replace('__REPORT_DATE__',    $reportDate).
    Replace('__TENANT_ID__',      $ctx.Tenant.Id.ToString()).
    Replace('__ACCOUNT_ID__',     $ctx.Account.Id.ToString()).
    Replace('__METRICS_DAYS__',   "$MetricsDays").
    Replace('__SCRIPT_VERSION__', $script:ScriptVersion).
    Replace('__TOTAL_ACCOUNTS__', "$totalAccounts").
    Replace('__SEV_CRITICAL__',   "$($sevCounts.Critical)").
    Replace('__SEV_HIGH__',       "$($sevCounts.High)").
    Replace('__SEV_MEDIUM__',     "$($sevCounts.Medium)").
    Replace('__PILLAR_COST__',    "$($pillarCounts.Cost)").
    Replace('__PILLAR_PERF__',    "$($pillarCounts.Performance)").
    Replace('__TOTAL_SAVINGS__',  ("{0:N2}" -f $totalSavings)).
    Replace('__ACCOUNTS_JSON__',  $accountsJsonSafe).
    Replace('__FINDINGS_JSON__',  $findingsJsonSafe).
    Replace('__AGG_JSON__',       $aggJsonSafe).
    Replace('__SUBS_JSON__',      $subsJsonSafe).
    Replace('__COMPARE_JSON__',   $compareJsonSafe)

# Save
Set-Content -Path $reportFile -Value $html -Encoding UTF8
Write-Log "HTML report written: $reportFile" OK

# ----- Integrity hash (SHA-256) for tamper-evidence when handing the file to a
#       customer. The hash is computed AFTER the report is complete and written to
#       a sidecar .sha256 file (canonical). We do NOT embed the hash inside the HTML
#       because that would change the hash (chicken-and-egg). The HTML footer shows
#       only the sidecar filename and the verify command.
try {
    $bannerNote = "<div style='padding:12px 24px;color:#605E5C;font-family:Segoe UI,sans-serif;font-size:11px;border-top:1px solid #EDEBE9;background:#F3F2F1;'>Integrity: verify with <code style='font-family:Cascadia Code,Consolas,monospace;font-size:11px;'>Get-FileHash -Algorithm SHA256 '$([IO.Path]::GetFileName($reportFile))'</code> and compare to the hash in the companion file <code>$([IO.Path]::GetFileName($reportFile)).sha256</code>.</div>"
    $stamped = (Get-Content -Raw -LiteralPath $reportFile) -replace '</body>', ($bannerNote + '</body>')
    Set-Content -Path $reportFile -Value $stamped -Encoding UTF8

    $sha = (Get-FileHash -LiteralPath $reportFile -Algorithm SHA256).Hash
    $sidecar = "$reportFile.sha256"
    "$sha  $(Split-Path $reportFile -Leaf)" | Set-Content -LiteralPath $sidecar -Encoding UTF8
    Write-Log "Report integrity SHA-256: $sha" OK
    Write-Log "Sidecar hash file: $sidecar" INFO
    Write-Log "Verify with: Get-FileHash -Algorithm SHA256 '$([IO.Path]::GetFileName($reportFile))'" INFO
} catch {
    Write-Log ("Failed to write integrity hash: {0}" -f $_.Exception.Message) WARN
}

# ----- JSON snapshot (used by -CompareWith on future runs) -----
$snapshotFile = Join-Path $OutputPath ("StorageOptimizer_snapshot_{0}.json" -f $runId)
try {
    $snapshot = [ordered]@{
        RunId          = $runId
        GeneratedAt    = $reportDate
        MetricsDays    = $MetricsDays
        TotalAccounts  = $totalAccounts
        TotalSavings   = $totalSavings
        Accounts       = $results
        Findings       = $flatFindings
    }
    $snapshot | ConvertTo-Json -Depth 10 -Compress | Set-Content -LiteralPath $snapshotFile -Encoding UTF8
    Write-Log "Snapshot saved: $snapshotFile (use -CompareWith on the next run to see resolved/new findings)" OK
} catch {
    Write-Log ("Snapshot save failed: {0}" -f $_.Exception.Message) WARN
}

#endregion HTML report

#region ------------------------------------------------------------- Upload to Cloud Shell storage

# In Cloud Shell, ~/clouddrive IS the mounted Azure Files share of the Cloud
# Shell storage account. Writing the file there IS the upload. We surface the
# storage account details so the user can locate the file in the portal.
try {
    $cfg = Get-ChildItem "$HOME/clouddrive" -Force -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cfg) {
        Write-Log "Report is persisted on the Cloud Shell file share (clouddrive)." OK
        Write-Log "Portal path: Storage account backing Cloud Shell -> File shares -> your Cloud Shell share -> StorageAccount_Optimizer/" INFO
    } else {
        Write-Log "clouddrive not detected; report kept locally at $reportFile" WARN
    }
} catch { }

$elapsed = (Get-Date) - $script:StartTime
Write-Log ("Done in {0:N1} minutes." -f $elapsed.TotalMinutes) OK
Write-Host ""
Write-Host ("Report:   {0}" -f $reportFile)     -ForegroundColor Cyan
Write-Host ("Accounts: {0}" -f $totalAccounts)   -ForegroundColor Cyan
Write-Host ("Findings: {0}" -f $flatFindings.Count) -ForegroundColor Cyan
Write-Host ("Est. monthly savings (USD): `$$totalSavings") -ForegroundColor Green

#endregion Upload


