# Windows equivalent of perf/run-extension-compare.sh (before = CDE -B, simple = -S with the
# published library). Launches AzureAttestSKR.exe the way the CDE extension does: one process
# per batch, batch JSON on stdin, IMDS_MSI_RES_ID, CWD = binary dir. Verifies every key.
param(
    [string]$Root = 'C:\skrperf',
    [int[]]$Disks = @(1, 4, 8, 16, 32),
    [int]$Iterations = 30,
    [int]$Warmup = 3,
    [string]$Out = 'C:\skrperf\results\windows-compare.csv'
)
$ErrorActionPreference = 'Stop'
$Maa = 'https://sharedeus2e.eus2e.attest.azure.net'
$MiResId = '/subscriptions/759532d8-9991-4d04-878f-49f0f4804906/resourceGroups/cde-dnd-shared/providers/Microsoft.ManagedIdentity/userAssignedIdentities/cdde-mhsm-test-mi'
$skr = Get-Content "$Root\baseline-mhsm-batch.json" -Raw | ConvertFrom-Json
$sec = Get-Content "$Root\mhsm-rsa-batch.json" -Raw | ConvertFrom-Json

function Sha256B64Url([string]$v) {
    $s = $v.Replace('-', '+').Replace('_', '/'); while ($s.Length % 4) { $s += '=' }
    $b = [Convert]::FromBase64String($s)
    ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)) -replace '-', '').ToLower()
}

function Invoke-Skr([string]$exe, [string[]]$argv, [string]$stdin) {
    $psi = New-Object Diagnostics.ProcessStartInfo $exe
    $psi.Arguments = ($argv | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $psi.WorkingDirectory = Split-Path $exe
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables['IMDS_MSI_RES_ID'] = $MiResId
    $psi.EnvironmentVariables.Remove('IMDS_CLIENT_ID')
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = [Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
    $p.StandardInput.Write($stdin); $p.StandardInput.Close()
    $p.WaitForExit(); $sw.Stop()
    [pscustomobject]@{ Ms = $sw.Elapsed.TotalMilliseconds; Code = $p.ExitCode; Out = $o.Result; Err = $e.Result }
}

New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
if (-not (Test-Path $Out)) { 'label,mode,disks,concurrency,iterations,failures,p50,p95,p99,max,mean' | Set-Content $Out }
foreach ($n in $Disks) {
    $skrIn = @{ keys = @($skr.keys | Select-Object -First $n | ForEach-Object { @{ id = $_.id; wrapped = $_.wrapped } }) } | ConvertTo-Json -Depth 5 -Compress
    $secKeys = for ($i = 0; $i -lt $n; $i++) { $k = $sec.keys[$i % $sec.keys.Count]; [pscustomobject]@{ id = "$($k.id)#$i"; wrapped = $k.wrapped; sha256 = $k.sha256 } }
    $secIn = @{ keys = @($secKeys | ForEach-Object { @{ id = $_.id; wrapped = $_.wrapped } }) } | ConvertTo-Json -Depth 5 -Compress
    $expected = @{}; foreach ($k in $secKeys) { $expected[$k.id] = $k.sha256 }

    $modes = @(
        @{ Name = 'cde-skr'; Exe = "$Root\before\AzureAttestSKR.exe"; Args = @('-B', '-', '-a', $Maa, '-k', $skr.kid, '-H', 'sha256'); In = $skrIn; Conc = 1 },
        @{ Name = 'simple'; Exe = "$Root\after\AzureAttestSKR.exe"; Args = @('-S', '-', '-a', $Maa, '-k', $sec.kid, '-A', 'RSA-OAEP-256'); In = $secIn; Conc = 2 }
    )
    foreach ($m in $modes) {
        Write-Host "=== $($m.Name) n=$n"
        $samples = @(); $fails = 0
        for ($i = 0; $i -lt $Warmup + $Iterations; $i++) {
            $r = Invoke-Skr $m.Exe $m.Args $m.In
            $ok = $false
            if ($r.Code -eq 0) {
                try {
                    $res = ($r.Out | ConvertFrom-Json).results
                    if ($m.Name -eq 'cde-skr') {
                        $ok = (@($res | Where-Object { $_.unwrapped }).Count -eq $n)
                    } else {
                        $good = @($res | Where-Object { $_.unwrapped -and $expected[$_.id] -eq (Sha256B64Url $_.unwrapped) }).Count
                        $ok = ($good -eq $n)
                    }
                } catch { $ok = $false }
            }
            if ($i -lt $Warmup) { continue }
            if ($ok) { $samples += $r.Ms } else { $fails++; Write-Host "  iteration $i failed (exit $($r.Code)): $($r.Err.Substring(0, [Math]::Min(300, $r.Err.Length)))" }
        }
        $s = @($samples | Sort-Object)
        $pct = { param($p) if ($s.Count) { [int]$s[[Math]::Max(0, [Math]::Ceiling($p * $s.Count) - 1)] } else { '' } }
        $mean = if ($s.Count) { '{0:F1}' -f (($s | Measure-Object -Average).Average) } else { '' }
        $max = if ($s.Count) { [int]$s[-1] } else { '' }
        "windows,$($m.Name),$n,$($m.Conc),$Iterations,$fails,$(& $pct 0.50),$(& $pct 0.95),$(& $pct 0.99),$max,$mean" | Add-Content $Out
    }
}
Get-Content $Out
