#requires -Version 5.1
<#
TELAI S02 P0402 - G07 group job safe list validation relaunch (CP220 scope).
New scope and new content after: P0398 PASS (CP219 published),
P0399 PRELAUNCH_FAIL (parse), P0400 parse/state diagnostic (published),
P0401 watcher/broker identity probe (published).
This patch:
  - reconciles the ACTUAL current machine state (CP219 anchors, predecessor
    results P0400/P0401, newest local patches, newest checkpoints)
  - re-implements the failed P0399 scope as fresh parse-verified code:
    a fail-closed G07 group job safe list validator with a 9-fixture proof suite
  - performs NO project source mutations (readonly evidence + inline fixtures);
    adoption into project source is the next patch after this gate passes
  - duplicate-prevention: if a newer local patch (P0403+) or a CP220+ checkpoint
    already exists, it records that and does not claim the scope
Autonomous: no Read-Host, no Pause, no GUI. ASCII only.
Run:
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "<PATCH>.ps1"
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = 'C:\Users\a2\Desktop\TL_Bot',
    [string]$LogRoot = 'C:\Users\a2\Desktop\log'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$patchId = 'TELAI_S02_P0402_G07_SAFE_LIST_VALIDATION_RELAUNCH_CP220_20261112_D643319D'
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '_' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$runDir = Join-Path $LogRoot ('TELAI_P0402_' + $runId)
$resultFile = Join-Path $runDir 'P0402_RESULT.json'
$traceFile = Join-Path $runDir 'P0402_TRACE.log'

# Anchors inherited from P0400/P0401 (published CP219 state).
$checkpointName = 'TELAI_V004_S02_P0398_CP219_20261104T035538Z_165869a7.zip'
$expectedCheckpointSha = '9cdb9c75e5b3cb139b51b3b3ce6d0cd4f07621c3f7ba7a3740f63a8f8b860144'
$expectedSourceSha = '224d2c7e9674f3402e7298eda2587b6a1c5e44ea4579f0bdd8cc13a901cd722a'

# Platform-independent path assembly (Windows separators in defaults are fine,
# but relative paths are built with IO.Path.Combine so the script is testable).
$srcPath = [IO.Path]::Combine($ProjectRoot, 'src', 'ui', 'src', 'main.tsx')
$cpDir = [IO.Path]::Combine($ProjectRoot, '_state', 'checkpoints')
$cpPath = [IO.Path]::Combine($cpDir, $checkpointName)
$patchesDir = [IO.Path]::Combine($ProjectRoot, '_state', 'patches')

$result = [ordered]@{
    patch_id = $patchId
    run_id = $runId
    status = 'STARTING'
    scope = 'G07_GROUP_JOB_SAFE_LIST_VALIDATION_RELAUNCH_CP220'
    predecessor = 'P0398_PASS_CP219; P0399_PRELAUNCH_FAIL; P0400_DIAGNOSTIC; P0401_IDENTITY_PROBE'
    self_parse_errors = @()
    prechecks = @()
    state_reconcile = [ordered]@{}
    project_rollback = 'NO_PROJECT_MUTATIONS_PERFORMED'
    changed_project_files = 0
    validator_suite = @()
    validator_suite_passed = 0
    validator_suite_total = 0
    decision = ''
    next_action = ''
    error = ''
}

function Sha256([string]$path) {
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Sha256Text([string]$text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
        (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}
function Trace([string]$message) {
    $dir = [IO.Path]::GetDirectoryName($traceFile)
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { [IO.Directory]::CreateDirectory($dir) | Out-Null }
    $line = [DateTime]::UtcNow.ToString('o') + ' ' + $message
    [IO.File]::AppendAllText($traceFile, $line + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Write-Output $message
}
function Assert-True([bool]$condition, [string]$code) {
    if (-not $condition) { throw $code }
}
function ConvertFrom-JsonSafe([string]$jsonText) {
    if ([string]::IsNullOrWhiteSpace($jsonText)) { return $null }
    try { return ($jsonText | ConvertFrom-Json) } catch { return $null }
}

function Test-GroupJobSafeList([string]$jobJson, [string]$safeListJson) {
    # G07 fail-closed validator: any doubt -> DENY. Never throws on bad input.
    $reasons = @()
    $job = ConvertFrom-JsonSafe $jobJson
    $safe = ConvertFrom-JsonSafe $safeListJson
    if ($null -eq $job) { $reasons += 'DENY_MALFORMED_JOB_JSON' }
    if ($null -eq $safe) { $reasons += 'DENY_MALFORMED_SAFELIST_JSON' }
    if ($null -ne $job -and $null -ne $safe) {
        if ([string]::IsNullOrWhiteSpace([string]$job.job_id)) { $reasons += 'DENY_EMPTY_JOB_ID' }
        if ([string]::IsNullOrWhiteSpace([string]$job.group_id)) { $reasons += 'DENY_EMPTY_GROUP_ID' }
        if ($null -eq $job.account_ids) { $reasons += 'DENY_MISSING_ACCOUNT_IDS' }
        if ($null -eq $safe.group_id) { $reasons += 'DENY_MISSING_SAFELIST_GROUP' }
        $allowed = @()
        if ($null -ne $safe.allowed_account_ids) { $allowed = @($safe.allowed_account_ids) }
        if ($allowed.Count -eq 0) { $reasons += 'DENY_EMPTY_SAFE_LIST' }
        if (($null -ne $job.group_id) -and ($null -ne $safe.group_id) -and ([string]$job.group_id -ne [string]$safe.group_id)) {
            $reasons += 'DENY_GROUP_NOT_IN_SAFE_LIST'
        }
        if (($null -ne $job.account_ids) -and ($allowed.Count -gt 0)) {
            $accounts = @($job.account_ids)
            foreach ($acc in $accounts) {
                $s = [string]$acc
                $match = $false
                foreach ($a in $allowed) { if ([string]$a -ceq $s) { $match = $true; break } }
                if (-not $match) { $reasons += ('DENY_ACCOUNT_NOT_IN_SAFE_LIST:' + $s); break }
            }
            $seen = @{}
            $dup = $false
            foreach ($acc in $accounts) {
                $s = [string]$acc
                if ($seen.ContainsKey($s)) { $dup = $true; break }
                $seen[$s] = $true
            }
            if ($dup) { $reasons += 'DENY_DUPLICATE_ACCOUNT_IDS' }
            $max = 0
            if ($null -ne $safe.max_accounts_per_job) { $max = [int]$safe.max_accounts_per_job }
            if (($max -gt 0) -and ($accounts.Count -gt $max)) { $reasons += 'DENY_ACCOUNT_COUNT_OVER_MAX' }
            $actions = @()
            if ($null -ne $safe.allowed_actions) { $actions = @($safe.allowed_actions) }
            $actOk = $false
            foreach ($a in $actions) { if ([string]$a -ceq [string]$job.action) { $actOk = $true; break } }
            if (-not $actOk) { $reasons += 'DENY_ACTION_NOT_ALLOWED' }
        }
    }
    $decision = 'ALLOW'
    if ($reasons.Count -gt 0) { $decision = 'DENY' }
    $evidence = Sha256Text ($jobJson + '||' + $safeListJson + '||' + ($reasons -join ';') + '||' + $decision)
    return [ordered]@{ decision = $decision; reasons = $reasons; evidence_sha256 = $evidence }
}

function Get-LatestPatchResult([string]$dirPrefix, [string]$resultName) {
    # Reads the newest <LogRoot>\<dirPrefix>_*\<resultName> and returns dir+status.
    if (-not (Test-Path -LiteralPath $LogRoot -PathType Container)) { return $null }
    $dirs = @(Get-ChildItem -LiteralPath $LogRoot -Directory -Filter ($dirPrefix + '_*') | Sort-Object LastWriteTime -Descending)
    foreach ($d in $dirs) {
        $rf = [IO.Path]::Combine($d.FullName, $resultName)
        if (Test-Path -LiteralPath $rf -PathType Leaf) {
            $obj = ConvertFrom-JsonSafe ([IO.File]::ReadAllText($rf))
            if ($null -ne $obj) { return [ordered]@{ dir = $d.Name; status = [string]$obj.status } }
        }
    }
    return $null
}

$exitCode = 0
try {
    # ---------- Phase A: prechecks ----------
    if (-not (Test-Path -LiteralPath $runDir -PathType Container)) { [IO.Directory]::CreateDirectory($runDir) | Out-Null }
    Trace ('RUN_DIR=' + $runDir)
    Assert-True (Test-Path -LiteralPath $ProjectRoot -PathType Container) 'PRECHECK_PROJECT_ROOT_MISSING'
    $result.prechecks += 'PROJECT_ROOT_PRESENT'
    Trace ('PROJECT_ROOT_OK=' + $ProjectRoot)

    $tokens = $null; $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$tokens, [ref]$parseErrors)
    foreach ($e in $parseErrors) { $result.self_parse_errors += ('L' + $e.Extent.StartLineNumber + ':' + $e.Message) }
    Assert-True ($parseErrors.Count -eq 0) 'PRECHECK_SELF_PARSE_FAILED'
    $result.prechecks += 'SELF_PARSE_CLEAN'
    Trace 'SELF_PARSE_CLEAN'

    # ---------- Phase B: state reconcile (readonly evidence) ----------
    if (Test-Path -LiteralPath $cpPath -PathType Leaf) {
        $sha = Sha256 $cpPath
        $result.state_reconcile.cp219_checkpoint_sha = $sha
        $result.state_reconcile.cp219_checkpoint_state = $(if ($sha -eq $expectedCheckpointSha) { 'MATCH' } else { 'MISMATCH' })
    } else { $result.state_reconcile.cp219_checkpoint_state = 'MISSING' }
    Trace ('CP219_CHECKPOINT=' + $result.state_reconcile.cp219_checkpoint_state)

    if (Test-Path -LiteralPath $srcPath -PathType Leaf) {
        $sha = Sha256 $srcPath
        $result.state_reconcile.cp219_source_sha = $sha
        $result.state_reconcile.cp219_source_state = $(if ($sha -eq $expectedSourceSha) { 'MATCH' } else { 'MISMATCH_OR_ADVANCED' })
    } else { $result.state_reconcile.cp219_source_state = 'MISSING' }
    Trace ('CP219_SOURCE=' + $result.state_reconcile.cp219_source_state)

    $recentPatches = @()
    $newerPatchPresent = $false
    if (Test-Path -LiteralPath $patchesDir -PathType Container) {
        $recentPatches = @(Get-ChildItem -LiteralPath $patchesDir -Filter '*.ps1' -File | Sort-Object Name | Select-Object -Last 8 | ForEach-Object { $_.Name })
        foreach ($n in $recentPatches) {
            if ($n -match 'TELAI_S02_P0(\d{3})') {
                if ([int]$Matches[1] -gt 402) { $newerPatchPresent = $true }
            }
        }
    }
    $result.state_reconcile.recent_local_patches = $recentPatches
    $result.state_reconcile.newer_local_patch_present = $newerPatchPresent
    Trace ('NEWER_LOCAL_PATCH_PRESENT=' + $newerPatchPresent)

    $cpMax = 0
    $latestCp = ''
    if (Test-Path -LiteralPath $cpDir -PathType Container) {
        $cps = @(Get-ChildItem -LiteralPath $cpDir -Filter '*.zip' -File | Sort-Object Name)
        if ($cps.Count -gt 0) { $latestCp = $cps[-1].Name }
        foreach ($c in $cps) {
            if ($c.Name -match '_CP(\d{3})_') { $n = [int]$Matches[1]; if ($n -gt $cpMax) { $cpMax = $n } }
        }
    }
    $result.state_reconcile.latest_checkpoint = $latestCp
    $result.state_reconcile.max_checkpoint_number = $cpMax
    Trace ('MAX_CHECKPOINT=CP' + $cpMax)

    $p0400 = Get-LatestPatchResult 'TELAI_P0400' 'P0400_RESULT.json'
    $p0401 = Get-LatestPatchResult 'TELAI_P0401' 'P0401_RESULT.json'
    $result.state_reconcile.p0400 = $(if ($null -ne $p0400) { $p0400 } else { 'RESULT_NOT_FOUND' })
    $result.state_reconcile.p0401 = $(if ($null -ne $p0401) { $p0401 } else { 'RESULT_NOT_FOUND' })
    Trace ('P0400_STATUS=' + $(if ($null -ne $p0400) { $p0400.status } else { 'RESULT_NOT_FOUND' }))
    Trace ('P0401_STATUS=' + $(if ($null -ne $p0401) { $p0401.status } else { 'RESULT_NOT_FOUND' }))

    # P0399 parse evidence (fresh, machine-local)
    $p399Parse = 'NOT_FOUND'
    if (Test-Path -LiteralPath $patchesDir -PathType Container) {
        $p399 = @(Get-ChildItem -LiteralPath $patchesDir -Filter 'TELAI_S02_P0399_*.ps1' -File | Sort-Object Name)
        if ($p399.Count -gt 0) {
            $t2 = $null; $pe2 = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($p399[-1].FullName, [ref]$t2, [ref]$pe2)
            $p399Parse = $(if ($pe2.Count -eq 0) { 'PARSE_CLEAN' } else { 'PARSE_FAIL_' + $pe2.Count + '_ERRORS' })
        }
    }
    $result.state_reconcile.p0399_parse = $p399Parse
    Trace ('P0399_PARSE=' + $p399Parse)

    # ---------- Phase C: duplicate-prevention scope guard ----------
    $scopeClaimed = $false
    if ($newerPatchPresent) {
        $scopeClaimed = $true
        $result.decision = 'NEWER_LOCAL_PATCH_DETECTED_NO_SCOPE_CLAIM'
        $result.next_action = 'RECONCILE_FROM_NEWEST_LOCAL_PATCH_BEFORE_ANY_NEW_WORK'
        Trace 'SCOPE_GUARD=NEWER_PATCH'
    } elseif ($cpMax -ge 220) {
        $scopeClaimed = $true
        $result.decision = 'CP220_ALREADY_PUBLISHED_VALIDATOR_AS_REGRESSION_ONLY'
        $result.next_action = 'G07_SCOPE_ALREADY_CHECKPOINTED_USE_VALIDATOR_AS_REGRESSION'
        Trace 'SCOPE_GUARD=CP220_ALREADY_PUBLISHED'
    }

    # ---------- Phase D: G07 validator fixture suite (inline, no project mutation) ----------
    $safeListOk = '{"group_id":"g1","allowed_account_ids":["a1","a2","a3"],"max_accounts_per_job":3,"allowed_actions":["join","leave"]}'
    $safeListMax2 = '{"group_id":"g1","allowed_account_ids":["a1","a2","a3"],"max_accounts_per_job":2,"allowed_actions":["join","leave"]}'
    $safeListEmpty = '{"group_id":"g1","allowed_account_ids":[],"max_accounts_per_job":3,"allowed_actions":["join","leave"]}'
    $fixtures = @(
        @{ id = 'F1_VALID_ALLOW';            want = 'ALLOW'; wantReason = '';                job = '{"job_id":"j1","group_id":"g1","account_ids":["a1","a2"],"action":"join"}'; safe = $safeListOk },
        @{ id = 'F2_UNKNOWN_ACCOUNT_DENY';   want = 'DENY';  wantReason = 'DENY_ACCOUNT_NOT_IN_SAFE_LIST'; job = '{"job_id":"j2","group_id":"g1","account_ids":["a1","a9"],"action":"join"}'; safe = $safeListOk },
        @{ id = 'F3_OVER_MAX_DENY';          want = 'DENY';  wantReason = 'DENY_ACCOUNT_COUNT_OVER_MAX';  job = '{"job_id":"j3","group_id":"g1","account_ids":["a1","a2","a3"],"action":"join"}'; safe = $safeListMax2 },
        @{ id = 'F4_ACTION_NOT_ALLOWED';     want = 'DENY';  wantReason = 'DENY_ACTION_NOT_ALLOWED';      job = '{"job_id":"j4","group_id":"g1","account_ids":["a1"],"action":"post"}'; safe = $safeListOk },
        @{ id = 'F5_MALFORMED_JOB_JSON';     want = 'DENY';  wantReason = 'DENY_MALFORMED_JOB_JSON';      job = 'this-is-not-json'; safe = $safeListOk },
        @{ id = 'F6_EMPTY_SAFE_LIST';        want = 'DENY';  wantReason = 'DENY_EMPTY_SAFE_LIST';         job = '{"job_id":"j6","group_id":"g1","account_ids":["a1"],"action":"join"}'; safe = $safeListEmpty },
        @{ id = 'F7_DUPLICATE_ACCOUNTS';     want = 'DENY';  wantReason = 'DENY_DUPLICATE_ACCOUNT_IDS';   job = '{"job_id":"j7","group_id":"g1","account_ids":["a1","a1"],"action":"join"}'; safe = $safeListOk },
        @{ id = 'F8_GROUP_NOT_IN_SAFE_LIST'; want = 'DENY';  wantReason = 'DENY_GROUP_NOT_IN_SAFE_LIST';  job = '{"job_id":"j8","group_id":"g2","account_ids":["a1"],"action":"join"}'; safe = $safeListOk },
        @{ id = 'F9_DETERMINISM_SAME_INPUT_SAME_EVIDENCE'; want = 'ALLOW'; wantReason = ''; job = '{"job_id":"j1","group_id":"g1","account_ids":["a1","a2"],"action":"join"}'; safe = $safeListOk }
    )
    $passed = 0
    foreach ($f in $fixtures) {
        $v = Test-GroupJobSafeList $f.job $f.safe
        $ok = ($v.decision -eq $f.want)
        if ($f.wantReason -ne '') {
            # reasons may carry an evidence suffix (e.g. 'DENY_ACCOUNT_NOT_IN_SAFE_LIST:a9'),
            # so wantReason is matched as a prefix, not as an exact string.
            $reasonHit = @(@($v.reasons) | Where-Object { $_ -like ($f.wantReason + '*') })
            $ok = $ok -and ($reasonHit.Count -gt 0)
        }
        if ($f.id -like 'F9_*') {
            $v2 = Test-GroupJobSafeList $f.job $f.safe
            $ok = $ok -and ($v.evidence_sha256 -eq $v2.evidence_sha256)
        }
        if ($ok) { $passed++ }
        $result.validator_suite += [ordered]@{
            id = $f.id; got = $v.decision; want = $f.want; pass = $ok
            reasons = @($v.reasons); evidence_sha256 = $v.evidence_sha256
        }
        Trace ('FIXTURE_' + $f.id + '=' + $(if ($ok) { 'PASS' } else { 'FAIL' }))
    }
    $result.validator_suite_passed = $passed
    $result.validator_suite_total = $fixtures.Count
    Assert-True ($passed -eq $fixtures.Count) ('VALIDATOR_SUITE_FAILED_' + $passed + '_OF_' + $fixtures.Count)
    Trace ('VALIDATOR_SUITE=' + $passed + '/' + $fixtures.Count)

    # ---------- Phase E: decision ----------
    if (-not $scopeClaimed) {
        $result.decision = 'G07_VALIDATOR_GATE_PASS_READY_FOR_ADOPTION'
        $result.next_action = 'NEXT_PATCH_ADOPTS_VALIDATOR_INTO_PROJECT_SOURCE_WITH_BACKUP_ROLLBACK'
    }
    $result.status = 'PASS'
} catch {
    $result.status = 'FAIL'
    $result.error = $_.Exception.Message
    $exitCode = 1
    Trace ('ERROR=' + $result.error)
} finally {
    if (-not (Test-Path -LiteralPath $runDir -PathType Container)) { [IO.Directory]::CreateDirectory($runDir) | Out-Null }
    [IO.File]::WriteAllText($resultFile, ($result | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    Write-Output ('PATCH_RESULT=' + $result.status)
    Write-Output ('DECISION=' + $result.decision)
    Write-Output ('VALIDATOR_SUITE=' + $result.validator_suite_passed + '/' + $result.validator_suite_total)
    Write-Output ('CP219_CHECKPOINT=' + $result.state_reconcile.cp219_checkpoint_state)
    Write-Output ('CP219_SOURCE=' + $result.state_reconcile.cp219_source_state)
    Write-Output ('P0399_PARSE=' + $result.state_reconcile.p0399_parse)
    Write-Output ('PROJECT_ROLLBACK=' + $result.project_rollback)
    Write-Output ('LOGS=' + $resultFile)
}
exit $exitCode
