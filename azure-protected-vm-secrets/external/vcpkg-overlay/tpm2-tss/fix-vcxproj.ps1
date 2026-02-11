param(
    [Parameter(Mandatory=$true)]
    [string]$SourcePath,
    
    [Parameter(Mandatory=$false)]
    [string]$OpenSslInclude = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OpenSslLib = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OpenSslDebugLib = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$Static = $false
)

Write-Host "Fixing vcxproj files in: $SourcePath"
Write-Host "Build type: $(if ($Static) { 'Static' } else { 'Dynamic' })"

# Convert forward slashes to backslashes
$OpenSslInclude = $OpenSslInclude -replace '/', '\'
$OpenSslLib = $OpenSslLib -replace '/', '\'
$OpenSslDebugLib = $OpenSslDebugLib -replace '/', '\'

foreach ($file in (Get-ChildItem -Path $SourcePath -Recurse -Filter "*.vcxproj")) {
    Write-Host "Processing: $($file.Name)"
    
    $lines = Get-Content $file.FullName
    $modified = $false
    
    # Track if we're in an x64 Release or Debug ItemDefinitionGroup with ClCompile
    $inX64ReleaseClCompile = $false
    $inX64DebugClCompile = $false
    $needsRuntimeLibrary = $false
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        
        # Update PlatformToolset
        if ($line -match 'v141_clang_c2') {
            $lines[$i] = $line -replace 'v141_clang_c2', 'ClangCL'
            $modified = $true
        }
        
        # Fix Windows SDK version
        if ($line -match '<WindowsTargetPlatformVersion>10\.0\.17134\.0</WindowsTargetPlatformVersion>') {
            $lines[$i] = $line -replace '10\.0\.17134\.0', '10.0'
            $modified = $true
        }
        if ($line -match '<WindowsTargetPlatformVersion>10</WindowsTargetPlatformVersion>') {
            $lines[$i] = $line -replace '>10<', '>10.0<'
            $modified = $true
        }
        
        # Static build modifications
        if ($Static) {
            # Change DynamicLibrary to StaticLibrary for x64
            if ($line -match "Condition=.*'Release\|x64'.*Configuration") {
                for ($j = $i; $j -lt [Math]::Min($i + 10, $lines.Count); $j++) {
                    if ($lines[$j] -match '<ConfigurationType>DynamicLibrary</ConfigurationType>') {
                        $lines[$j] = $lines[$j] -replace 'DynamicLibrary', 'StaticLibrary'
                        $modified = $true
                        break
                    }
                }
            }
            if ($line -match "Condition=.*'Debug\|x64'.*Configuration") {
                for ($j = $i; $j -lt [Math]::Min($i + 10, $lines.Count); $j++) {
                    if ($lines[$j] -match '<ConfigurationType>DynamicLibrary</ConfigurationType>') {
                        $lines[$j] = $lines[$j] -replace 'DynamicLibrary', 'StaticLibrary'
                        $modified = $true
                        break
                    }
                }
            }
            
            # Change existing RuntimeLibrary from /MD to /MT
            if ($line -match '<RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary>') {
                $lines[$i] = $line -replace 'MultiThreadedDLL', 'MultiThreaded'
                $modified = $true
            }
            if ($line -match '<RuntimeLibrary>MultiThreadedDebugDLL</RuntimeLibrary>') {
                $lines[$i] = $line -replace 'MultiThreadedDebugDLL', 'MultiThreadedDebug'
                $modified = $true
            }
            
            # Track x64 ItemDefinitionGroups to add missing RuntimeLibrary
            if ($line -match "ItemDefinitionGroup.*Condition=.*'Release\|x64'") {
                $inX64ReleaseClCompile = $false
                $needsRuntimeLibrary = $false
            }
            elseif ($line -match "ItemDefinitionGroup.*Condition=.*'Debug\|x64'") {
                $inX64DebugClCompile = $false
                $needsRuntimeLibrary = $false
            }
            elseif ($inX64ReleaseClCompile -eq $false -and $line -match '<ClCompile>') {
                # Check if this ClCompile is within a Release|x64 ItemDefinitionGroup
                $startIndex = [Math]::Max(0, $i - 5)
                $contextLines = $lines[$startIndex..$i] -join ''
                if ($contextLines -match "Release\|x64") {
                    $inX64ReleaseClCompile = $true
                    $needsRuntimeLibrary = $true
                }
            }
            elseif ($inX64DebugClCompile -eq $false -and $line -match '<ClCompile>') {
                # Check if this ClCompile is within a Debug|x64 ItemDefinitionGroup
                $startIndex = [Math]::Max(0, $i - 5)
                $contextLines = $lines[$startIndex..$i] -join ''
                if ($contextLines -match "Debug\|x64") {
                    $inX64DebugClCompile = $true
                    $needsRuntimeLibrary = $true
                }
            }
            
            # Check if RuntimeLibrary already exists in this ClCompile section
            if (($inX64ReleaseClCompile -or $inX64DebugClCompile) -and $line -match '<RuntimeLibrary>') {
                $needsRuntimeLibrary = $false
            }
            
            # When we hit </ClCompile>, insert RuntimeLibrary if needed
            if (($inX64ReleaseClCompile -or $inX64DebugClCompile) -and $line -match '</ClCompile>') {
                if ($needsRuntimeLibrary) {
                    $indent = $line -replace '</ClCompile>.*', ''
                    $runtimeLib = if ($inX64ReleaseClCompile) { 'MultiThreaded' } else { 'MultiThreadedDebug' }
                    
                    # Insert before </ClCompile>
                    $newLine = "$indent  <RuntimeLibrary>$runtimeLib</RuntimeLibrary>"
                    $lines = $lines[0..($i-1)] + $newLine + $lines[$i..($lines.Count-1)]
                    $i++ # Skip the line we just inserted
                    $modified = $true
                }
                $inX64ReleaseClCompile = $false
                $inX64DebugClCompile = $false
                $needsRuntimeLibrary = $false
            }
            
            # For projects with project-level <ClCompile> with Condition attributes (tss2-mu, tss2-rc, tss2-sys)
            # Add RuntimeLibrary property with x64 Release condition
            if ($line -match '^\s*<ClCompile>\s*$' -and $i -lt $lines.Count - 1 -and $lines[$i+1] -match 'Condition') {
                # Find if there's already a RuntimeLibrary in this section
                $hasRuntimeLib = $false
                for ($j = $i; $j -lt [Math]::Min($i + 50, $lines.Count); $j++) {
                    if ($lines[$j] -match '</ClCompile>') { break }
                    if ($lines[$j] -match '<RuntimeLibrary') {
                        $hasRuntimeLib = $true
                        break
                    }
                }
                
                if (-not $hasRuntimeLib) {
                    # Find the closing </ClCompile> and insert before it
                    for ($j = $i; $j -lt [Math]::Min($i + 50, $lines.Count); $j++) {
                        if ($lines[$j] -match '^\s*</ClCompile>\s*$') {
                            $indent = $lines[$j] -replace '</ClCompile>.*', ''
                            $newLines = @(
                                "$indent  <RuntimeLibrary Condition=""'`$(Configuration)|`$(Platform)'=='Release|x64'"">MultiThreaded</RuntimeLibrary>",
                                "$indent  <RuntimeLibrary Condition=""'`$(Configuration)|`$(Platform)'=='Debug|x64'"">MultiThreadedDebug</RuntimeLibrary>"
                            )
                            $lines = $lines[0..($j-1)] + $newLines + $lines[$j..($lines.Count-1)]
                            $i = $j + 2  # Skip past inserted lines
                            $modified = $true
                            break
                        }
                    }
                }
            }
        }
        else {
            # For projects with ClCompile in ItemDefinitionGroup (tss2-esys, tss2-tcti-*)
            # Track x64 ItemDefinitionGroups to add missing RuntimeLibrary
            if ($line -match "ItemDefinitionGroup.*Condition=.*'Release\|x64'") {
                $inX64ReleaseClCompile = $false
                $needsRuntimeLibrary = $false
            }
            elseif ($line -match "ItemDefinitionGroup.*Condition=.*'Debug\|x64'") {
                $inX64DebugClCompile = $false
                $needsRuntimeLibrary = $false
            }
            elseif ($inX64ReleaseClCompile -eq $false -and $line -match '<ClCompile>') {
                $startIndex = [Math]::Max(0, $i - 5)
                $contextLines = $lines[$startIndex..$i] -join ''
                if ($contextLines -match "Release\|x64") {
                    $inX64ReleaseClCompile = $true
                    $needsRuntimeLibrary = $true
                }
            }
            elseif ($inX64DebugClCompile -eq $false -and $line -match '<ClCompile>') {
                $startIndex = [Math]::Max(0, $i - 5)
                $contextLines = $lines[$startIndex..$i] -join ''
                if ($contextLines -match "Debug\|x64") {
                    $inX64DebugClCompile = $true
                    $needsRuntimeLibrary = $true
                }
            }
            
            if (($inX64ReleaseClCompile -or $inX64DebugClCompile) -and $line -match '<RuntimeLibrary>') {
                $needsRuntimeLibrary = $false
            }
            
            if (($inX64ReleaseClCompile -or $inX64DebugClCompile) -and $line -match '</ClCompile>') {
                if ($needsRuntimeLibrary) {
                    $indent = $line -replace '</ClCompile>.*', ''
                    $runtimeLib = if ($inX64ReleaseClCompile) { 'MultiThreaded' } else { 'MultiThreadedDebug' }
                    $newLine = "$indent  <RuntimeLibrary>$runtimeLib</RuntimeLibrary>"
                    $lines = $lines[0..($i-1)] + $newLine + $lines[$i..($lines.Count-1)]
                    $i++
                    $modified = $true
                }
                $inX64ReleaseClCompile = $false
                $inX64DebugClCompile = $false
                $needsRuntimeLibrary = $false
            }
            
            # For projects with project-level <ClCompile> with Condition attributes (tss2-mu, tss2-rc, tss2-sys)
            # Add RuntimeLibrary property with x64 Release condition
            if ($line -match '^\s*<ClCompile>\s*$' -and $i -lt $lines.Count - 1 -and $lines[$i+1] -match 'Condition') {
                # Find if there's already a RuntimeLibrary in this section
                $hasRuntimeLib = $false
                for ($j = $i; $j -lt [Math]::Min($i + 50, $lines.Count); $j++) {
                    if ($lines[$j] -match '</ClCompile>') { break }
                    if ($lines[$j] -match '<RuntimeLibrary') {
                        $hasRuntimeLib = $true
                        break
                    }
                }
                
                if (-not $hasRuntimeLib) {
                    # Find the closing </ClCompile> and insert before it
                    for ($j = $i; $j -lt [Math]::Min($i + 50, $lines.Count); $j++) {
                        if ($lines[$j] -match '^\s*</ClCompile>\s*$') {
                            $indent = $lines[$j] -replace '</ClCompile>.*', ''
                            $newLines = @(
                                "$indent  <RuntimeLibrary Condition=""'`$(Configuration)|`$(Platform)'=='Release|x64'"">MultiThreaded</RuntimeLibrary>",
                                "$indent  <RuntimeLibrary Condition=""'`$(Configuration)|`$(Platform)'=='Debug|x64'"">MultiThreadedDebug</RuntimeLibrary>"
                            )
                            $lines = $lines[0..($j-1)] + $newLines + $lines[$j..($lines.Count-1)]
                            $i = $j + 2  # Skip past inserted lines
                            $modified = $true
                            break
                        }
                    }
                }
            }
        }
        
        # Replace OpenSSL paths
        if ($line -match 'C:\\OpenSSL' -or $line -match '\$\(OpenSslDir') {
            $originalLine = $line
            $line = $line -replace 'C:\\OpenSSL-v11-Win64\\include', $OpenSslInclude
            $line = $line -replace 'C:\\OpenSSL-v11-Win32\\include', $OpenSslInclude
            $line = $line -replace '\$\(OpenSslDir\)\\include', $OpenSslInclude
            $line = $line -replace '\$\(OpenSslDir32Bit\)\\include', $OpenSslInclude
            $line = $line -replace 'C:\\OpenSSL-v11-Win64\\lib', $OpenSslLib
            $line = $line -replace 'C:\\OpenSSL-v11-Win32\\lib', $OpenSslLib
            $line = $line -replace '\$\(OpenSslDir\)\\lib', $OpenSslLib
            $line = $line -replace '\$\(OpenSslDir32Bit\)\\lib', $OpenSslLib
            if ($line -ne $originalLine) {
                $lines[$i] = $line
                $modified = $true
            }
        }
        
        # Reduce log level
        if ($line -match 'MAXLOGLEVEL=6') {
            $lines[$i] = $line -replace 'MAXLOGLEVEL=6', 'MAXLOGLEVEL=0'
            $modified = $true
        }
        
        # Add -Wno-error=int-conversion to suppress int-to-pointer conversion errors
        if ($line -match '<AdditionalOptions>' -and $line -notmatch '-Wno-int-conversion') {
            $lines[$i] = $line -replace '(<AdditionalOptions>)', '$1-Wno-error=int-conversion -Wno-int-conversion '
            $modified = $true
        }
        # For ItemDefinitionGroup-based ClCompile sections that don't have AdditionalOptions
        elseif ($line -match '^\s*<ClCompile>\s*$') {
            # Check if this is within an ItemDefinitionGroup (not project-level with Condition attributes)
            $startIndex = [Math]::Max(0, $i - 5)
            $contextLines = if ($startIndex -lt $i) { $lines[$startIndex..($i-1)] -join '' } else { '' }
            $isItemDefinitionGroup = $contextLines -match 'ItemDefinitionGroup'
            
            if ($isItemDefinitionGroup) {
                # Check if the next few lines have AdditionalOptions
                $hasAdditionalOptions = $false
                for ($j = $i + 1; $j -lt [Math]::Min($i + 10, $lines.Count); $j++) {
                    if ($lines[$j] -match '</ClCompile>') { break }
                    if ($lines[$j] -match '<AdditionalOptions>') {
                        $hasAdditionalOptions = $true
                        break
                    }
                }
                
                if (-not $hasAdditionalOptions) {
                    # Insert AdditionalOptions right after <ClCompile>
                    $indent = $line -replace '<ClCompile>.*', ''
                    $newLine = "$indent  <AdditionalOptions>-Wno-error=int-conversion -Wno-int-conversion %(AdditionalOptions)</AdditionalOptions>"
                    $lines = $lines[0..$i] + $newLine + $lines[($i+1)..($lines.Count-1)]
                    $i++ # Skip the line we just inserted
                    $modified = $true
                }
            }
            # For project-level <ClCompile> with Condition-based properties
            elseif ($i -lt $lines.Count - 1 -and $lines[$i+1] -match 'Condition') {
                # Check if AdditionalOptions already exists
                $hasAdditionalOptions = $false
                $closeTagIndex = -1
                for ($j = $i + 1; $j -lt [Math]::Min($i + 50, $lines.Count); $j++) {
                    if ($lines[$j] -match '</ClCompile>') {
                        $closeTagIndex = $j
                        break
                    }
                    if ($lines[$j] -match '<AdditionalOptions') {
                        $hasAdditionalOptions = $true
                        break
                    }
                }
                
                if (-not $hasAdditionalOptions -and $closeTagIndex -gt 0) {
                    # Insert conditional AdditionalOptions before </ClCompile>
                    $indent = $lines[$closeTagIndex] -replace '</ClCompile>.*', ''
                    $newLines = @(
                        "$indent  <AdditionalOptions Condition=""'`$(Configuration)|`$(Platform)'=='Release|x64'"">-Wno-error=int-conversion -Wno-int-conversion %(AdditionalOptions)</AdditionalOptions>",
                        "$indent  <AdditionalOptions Condition=""'`$(Configuration)|`$(Platform)'=='Debug|x64'"">-Wno-error=int-conversion -Wno-int-conversion %(AdditionalOptions)</AdditionalOptions>"
                    )
                    $lines = $lines[0..($closeTagIndex-1)] + $newLines + $lines[$closeTagIndex..($lines.Count-1)]
                    $i = $closeTagIndex + 2
                    $modified = $true
                }
            }
        }
    }
    
    if ($modified) {
        Set-Content $file.FullName $lines
        Write-Host "  Updated: $($file.Name)" -ForegroundColor Green
    }
}

Write-Host "Done!"