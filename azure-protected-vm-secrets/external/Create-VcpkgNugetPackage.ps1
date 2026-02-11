<#
.SYNOPSIS
    Creates a NuGet package from vcpkg installed dependencies (TPM2-TSS libraries)
.DESCRIPTION
    Packages the vcpkg-built TPM2-TSS libraries into a NuGet package for consumption
    by SecretsProvisioningLibrary projects. Version is derived from vcpkg baseline.
.PARAMETER VcpkgInstalledPath
    Path to vcpkg_installed directory containing built libraries
.PARAMETER OutputPath
    Directory to output the .nupkg file
.PARAMETER Version
    Package version (optional - auto-generates from vcpkg baseline if not specified)
.PARAMETER PackageId
    Package ID (optional - uses ID from nuspec if not specified)
.EXAMPLE
    .\Create-VcpkgNugetPackage.ps1 -VcpkgInstalledPath ".\vcpkg_installed" -OutputPath ".\nuget"
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$VcpkgInstalledPath,
    
    [Parameter(Mandatory=$true)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [string]$PackageId
)

$ErrorActionPreference = "Stop"

# Auto-generate version from vcpkg baseline + build date if not provided
if (-not $Version) {
    # Read baseline from setup-vcpkg.ps1
    $vcpkgBaseline = $null
    $setupScript = Join-Path $PSScriptRoot "setup-vcpkg.ps1"
    if (Test-Path $setupScript) {
        $content = Get-Content $setupScript -Raw
        if ($content -match '\$VcpkgVersion\s*=\s*[''"]([^''"]+)[''"]') {
            $vcpkgBaseline = $Matches[1]  # e.g., "2024.12.16"
        }
    }
    
    if (-not $vcpkgBaseline) {
        throw "Could not determine vcpkg baseline from setup-vcpkg.ps1. Please specify -Version parameter."
    }
    
    # Format: {vcpkg-baseline}.{YYYYMMDD} e.g., 2024.12.16.20250120
    $buildDate = (Get-Date).ToString("yyyyMMdd")
    $Version = "$vcpkgBaseline.$buildDate"
    
    Write-Host "Auto-generated version: $Version" -ForegroundColor Cyan
    Write-Host "  vcpkg baseline: $vcpkgBaseline" -ForegroundColor Cyan
    Write-Host "  build date: $buildDate" -ForegroundColor Cyan
}

Write-Host "Creating NuGet package..." -ForegroundColor Green
Write-Host "  Version: $Version" -ForegroundColor Cyan
Write-Host "  Source: $VcpkgInstalledPath" -ForegroundColor Cyan
Write-Host "  Output: $OutputPath" -ForegroundColor Cyan

# Validate input
if (-not (Test-Path $VcpkgInstalledPath)) {
    throw "VcpkgInstalledPath not found: $VcpkgInstalledPath"
}

# Create output directory
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

# Locate nuspec file
$nugetDir = Join-Path $PSScriptRoot "..\nuget"
$nuspecFile = Join-Path $nugetDir "SecretsProvisioningLibDeps-vcpkg.All.x64.nuspec"
if (-not (Test-Path $nuspecFile)) {
    throw "nuspec file not found: $nuspecFile"
}

# Create staging directory
$stagingDir = Join-Path $nugetDir "staging"
Write-Host "Creating staging directory..." -ForegroundColor Yellow
if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force }

@(
    "$stagingDir\include\tss2",
    "$stagingDir\include\openssl",
    "$stagingDir\lib\x64\static",
    "$stagingDir\lib\x64\static\debug",
    "$stagingDir\lib\x64\dynamic",
    "$stagingDir\lib\x64\dynamic\debug",
    "$stagingDir\runtimes\win-x64\native",
    "$stagingDir\runtimes\win-x64\native\debug"
) | ForEach-Object { New-Item -Path $_ -ItemType Directory -Force | Out-Null }

# Find available triplets
$staticTriplet = "x64-windows-static"
$dynamicTriplet = "x64-windows"
$availableTriplets = @()

if (Test-Path (Join-Path $VcpkgInstalledPath $staticTriplet)) {
    $availableTriplets += @{ Name = $staticTriplet; LibType = "static" }
}
if (Test-Path (Join-Path $VcpkgInstalledPath $dynamicTriplet)) {
    $availableTriplets += @{ Name = $dynamicTriplet; LibType = "dynamic" }
}

if ($availableTriplets.Count -eq 0) {
    throw "No vcpkg triplets found in $VcpkgInstalledPath"
}

Write-Host "Found triplets: $($availableTriplets.Name -join ', ')" -ForegroundColor Cyan

# Copy files from each triplet
$headersCopied = $false
foreach ($triplet in $availableTriplets) {
    $tripletDir = Join-Path $VcpkgInstalledPath $triplet.Name
    $libType = $triplet.LibType
    
    Write-Host "`nProcessing $($triplet.Name)..." -ForegroundColor Yellow

    # Copy includes (once, from first available triplet)
    if (-not $headersCopied) {
        $srcTss2 = Join-Path $tripletDir "include\tss2"
        if (Test-Path $srcTss2) {
            Copy-Item -Path "$srcTss2\*" -Destination "$stagingDir\include\tss2" -Recurse -Force
            $count = (Get-ChildItem "$stagingDir\include\tss2" -Filter "*.h" -Recurse).Count
            Write-Host "  Copied $count tss2 headers" -ForegroundColor Green
        }
        
        # Copy OpenSSL headers if present
        $srcOpenssl = Join-Path $tripletDir "include\openssl"
        if (Test-Path $srcOpenssl) {
            Copy-Item -Path "$srcOpenssl\*" -Destination "$stagingDir\include\openssl" -Recurse -Force
            $count = (Get-ChildItem "$stagingDir\include\openssl" -Filter "*.h" -Recurse).Count
            Write-Host "  Copied $count openssl headers" -ForegroundColor Green
        }
        $headersCopied = $true
    }

    # Copy Release libraries
    $srcLib = Join-Path $tripletDir "lib"
    $destLib = "$stagingDir\lib\x64\$libType"
    if (Test-Path $srcLib) {
        Get-ChildItem $srcLib -Filter "tss2*.lib" | ForEach-Object {
            Copy-Item $_.FullName -Destination $destLib -Force
            Write-Host "  Copied $($_.Name) to $libType (Release)" -ForegroundColor Green
        }
    }

    # Copy Debug libraries
    $srcDebugLib = Join-Path $tripletDir "debug\lib"
    $destDebugLib = "$stagingDir\lib\x64\$libType\debug"
    if (Test-Path $srcDebugLib) {
        Get-ChildItem $srcDebugLib -Filter "tss2*.lib" | ForEach-Object {
            Copy-Item $_.FullName -Destination $destDebugLib -Force
            Write-Host "  Copied $($_.Name) to $libType (Debug)" -ForegroundColor Green
        }
    }

    # Copy DLLs for dynamic triplet
    if ($libType -eq "dynamic") {
        $srcBin = Join-Path $tripletDir "bin"
        if (Test-Path $srcBin) {
            Get-ChildItem $srcBin -Filter "tss2*.dll" | ForEach-Object {
                Copy-Item $_.FullName -Destination "$stagingDir\runtimes\win-x64\native" -Force
                Write-Host "  Copied $($_.Name) to runtimes (Release)" -ForegroundColor Green
            }
        }
        
        $srcDebugBin = Join-Path $tripletDir "debug\bin"
        if (Test-Path $srcDebugBin) {
            Get-ChildItem $srcDebugBin -Filter "tss2*.dll" | ForEach-Object {
                Copy-Item $_.FullName -Destination "$stagingDir\runtimes\win-x64\native\debug" -Force
                Write-Host "  Copied $($_.Name) to runtimes (Debug)" -ForegroundColor Green
            }
        }
    }
}

# Verify staging
Write-Host "`nVerifying staging..." -ForegroundColor Yellow
$tss2Esys = "$stagingDir\include\tss2\tss2_esys.h"
if (Test-Path $tss2Esys) {
    Write-Host "  tss2_esys.h: OK" -ForegroundColor Green
} else {
    throw "tss2_esys.h not found at $tss2Esys"
}

# Find NuGet executable
$repoRoot = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$nugetExe = Join-Path $repoRoot "build\nuget\nuget.exe"

if (-not (Test-Path $nugetExe)) {
    # Try to find nuget in PATH
    $nugetInPath = Get-Command nuget -ErrorAction SilentlyContinue
    if ($nugetInPath) {
        $nugetExe = $nugetInPath.Source
    } else {
        # Download nuget.exe
        $nugetDir = Join-Path $repoRoot "build\nuget"
        New-Item -Path $nugetDir -ItemType Directory -Force | Out-Null
        $nugetExe = Join-Path $nugetDir "nuget.exe"
        Write-Host "Downloading nuget.exe..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile $nugetExe
    }
}

Write-Host "Using NuGet: $nugetExe" -ForegroundColor Cyan

# Create package using existing nuspec
Write-Host "`nCreating NuGet package..." -ForegroundColor Yellow

# Pack with version substitution
& $nugetExe pack $nuspecFile -OutputDirectory $OutputPath -BasePath $nugetDir -Version $Version -NoPackageAnalysis

if ($LASTEXITCODE -ne 0) {
    throw "NuGet pack failed with exit code $LASTEXITCODE"
}

# List output - updated package name pattern
$nupkg = Get-ChildItem $OutputPath -Filter "SecretsProvisioningLibDeps-vcpkg.All.x64.*.nupkg" | Select-Object -First 1
if ($nupkg) {
    Write-Host "`nCreated: $($nupkg.Name) ($([math]::Round($nupkg.Length / 1MB, 2)) MB)" -ForegroundColor Green
} else {
    throw "No .nupkg file found in $OutputPath"
}

Write-Host "`nDone!" -ForegroundColor Green
