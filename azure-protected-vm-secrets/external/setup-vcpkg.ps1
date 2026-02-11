<#
.SYNOPSIS
    Setup vcpkg dependencies for tpm2-tss and OpenSSL
.EXAMPLE
    .\setup-vcpkg.ps1           # Build both static and dynamic
    .\setup-vcpkg.ps1 -Clean    # Clean rebuild
    .\setup-vcpkg.ps1 -StaticOnly
    .\setup-vcpkg.ps1 -DynamicOnly
#>
param(
    [switch]$Clean,
    [switch]$StaticOnly,
    [switch]$DynamicOnly,
    [switch]$KeepBuildArtifacts
)

$ErrorActionPreference = "Stop"
$VcpkgVersion = "2024.12.16"

Push-Location $PSScriptRoot
try {
    # Clone vcpkg if missing
    if (-not (Test-Path "vcpkg\bootstrap-vcpkg.bat")) {
        Write-Host "Cloning vcpkg ($VcpkgVersion)..." -ForegroundColor Cyan
        Remove-Item -Recurse -Force vcpkg -ErrorAction SilentlyContinue
        git clone --depth 1 --branch $VcpkgVersion https://github.com/microsoft/vcpkg.git vcpkg
        if ($LASTEXITCODE -ne 0) { throw "Failed to clone vcpkg" }
    }

    # Bootstrap vcpkg if needed
    if (-not (Test-Path "vcpkg\vcpkg.exe")) {
        Write-Host "Bootstrapping vcpkg..." -ForegroundColor Cyan
        & vcpkg\bootstrap-vcpkg.bat
    }

    # Clean if requested
    if ($Clean) {
        Write-Host "Cleaning..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force vcpkg\buildtrees, vcpkg_installed, vcpkg\packages -ErrorAction SilentlyContinue
        $cacheDir = if ($env:VCPKG_DEFAULT_BINARY_CACHE) { $env:VCPKG_DEFAULT_BINARY_CACHE } else { "$env:LOCALAPPDATA\vcpkg\archives" }
        Get-ChildItem $cacheDir -Recurse -Filter "*tpm2-tss*" -ErrorAction SilentlyContinue | Remove-Item -Force
    }

    # Disable manifest mode temporarily
    $manifest = "vcpkg.json"
    if (Test-Path $manifest) { Rename-Item $manifest "$manifest.disabled" }

    try {
        # Build triplets
        $triplets = @()
        if (-not $DynamicOnly) { $triplets += "x64-windows-static" }
        if (-not $StaticOnly) { $triplets += "x64-windows" }

        foreach ($triplet in $triplets) {
            Write-Host "`n=== Building $triplet ===" -ForegroundColor Green

            # Clean buildtrees between triplets
            if ($triplet -ne $triplets[0]) {
                Remove-Item -Recurse -Force vcpkg\buildtrees\tpm2-tss -ErrorAction SilentlyContinue
            }

            & vcpkg\vcpkg.exe install "tpm2-tss:$triplet" --overlay-ports=vcpkg-overlay --x-install-root=vcpkg_installed
            if ($LASTEXITCODE -ne 0) {
                # Output build logs on failure
                Write-Host "`n=== Build Failed - Showing Logs ===" -ForegroundColor Red
                Get-ChildItem "vcpkg\buildtrees\tpm2-tss\*.log" -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Host "`n--- $($_.Name) ---" -ForegroundColor Yellow
                    Get-Content $_.FullName -Tail 100
                }
                throw "$triplet build failed"
            }
        }
    } finally {
        if (Test-Path "$manifest.disabled") { Rename-Item "$manifest.disabled" $manifest }
    }

    # Verify
    Write-Host "`n=== Installed Libraries ===" -ForegroundColor Green
    Get-ChildItem vcpkg_installed\*\lib\tss2*.lib -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.FullName.Replace($PWD.Path + '\', ''))" }
    Get-ChildItem vcpkg_installed\*\debug\lib\tss2*.lib -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.FullName.Replace($PWD.Path + '\', ''))" }

    # Cleanup build artifacts to prevent file locking issues in CI
    if (-not $KeepBuildArtifacts) {
        Write-Host "`n=== Cleaning up build artifacts ===" -ForegroundColor Cyan
        @("vcpkg\buildtrees", "vcpkg\downloads", "vcpkg\packages") | ForEach-Object {
            if (Test-Path $_) {
                Write-Host "Removing $_..."
                Remove-Item -Recurse -Force $_ -ErrorAction SilentlyContinue
            }
        }
    }

} finally {
    Pop-Location
}