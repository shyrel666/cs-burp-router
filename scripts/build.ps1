Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Move-ReleaseOutput($Source, $Destination, $IsDirectory) {
    if ($IsDirectory) {
        [System.IO.Directory]::Move($Source, $Destination)
    }
    else {
        [System.IO.File]::Move($Source, $Destination)
    }
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$DistRoot = Join-Path $RepoRoot "dist"
$ReleaseLock = $null
$StageRoot = $null
$KeepStage = $false
Push-Location -LiteralPath $RepoRoot

try {
    $DistDir = [System.IO.Directory]::CreateDirectory($DistRoot)
    if ($DistDir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Release directory is a reparse point: $DistRoot"
    }
    $ReleaseLock = [System.IO.FileStream]::new(
        (Join-Path $DistRoot ".build.lock"),
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::DeleteOnClose
    )

    $BridgeSrcDir = Join-Path $RepoRoot "third_party\proxybridge"
    $RequiredBridgeFiles = @(
        "ProxyBridge_CLI.exe",
        "ProxyBridgeCore.dll",
        "WinDivert.dll",
        "WinDivert64.sys",
        "LICENSE.ProxyBridge.txt",
        "LICENSE.WinDivert.txt"
    )
    foreach ($File in $RequiredBridgeFiles) {
        $Source = Join-Path $BridgeSrcDir $File
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
            throw "Missing required package file: $Source"
        }
    }

    Write-Host "==> [1/6] Generating embedded Windows PE resources (.syso)..." -ForegroundColor Cyan
    $SysoPath = Join-Path $RepoRoot "cmd\router\rsrc_windows_amd64.syso"
    $ManifestPath = Join-Path $RepoRoot "packaging\cs-burp-router.exe.manifest"
    $IconPath = Join-Path $RepoRoot "packaging\cs-burp-router.ico"
    go run ./cmd/genrsrc -manifest $ManifestPath -icon $IconPath -out $SysoPath -version "1.0.0.0"
    if ($LASTEXITCODE -ne 0) {
        throw "genrsrc failed with exit code $LASTEXITCODE"
    }

    Write-Host "==> [2/6] Running go vet ./..." -ForegroundColor Cyan
    go vet ./...
    if ($LASTEXITCODE -ne 0) {
        throw "go vet failed with exit code $LASTEXITCODE"
    }

    Write-Host "==> [3/6] Running go test -race ./..." -ForegroundColor Cyan
    go test -race ./...
    if ($LASTEXITCODE -ne 0) {
        throw "go test -race failed with exit code $LASTEXITCODE"
    }

    $StageRoot = Join-Path $DistRoot (".build-" + [Guid]::NewGuid().ToString("N"))
    $StagePkgDir = Join-Path $StageRoot "cs-burp-router"
    $PackageDir = Join-Path $DistRoot "cs-burp-router"
    $ZipName = "cs-burp-router-windows-amd64.zip"
    $StageZip = Join-Path $StageRoot $ZipName
    $ZipPath = Join-Path $DistRoot $ZipName
    [System.IO.Directory]::CreateDirectory($StagePkgDir) | Out-Null

    Write-Host "==> [4/6] Building windows/amd64 executable (symbols & PE VersionInfo preserved)..." -ForegroundColor Cyan
    $PrevGOOS = $env:GOOS
    $PrevGOARCH = $env:GOARCH
    $PrevCGO = $env:CGO_ENABLED
    try {
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "0"
        $StageExe = Join-Path $StagePkgDir "cs-burp-router.exe"
        # 保留标准符号表（不使用 -s -w），降低杀毒软件启发式引擎对无符号 Go 程序的静态误报率
        go build -trimpath -o $StageExe ./cmd/router
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        $env:GOOS = $PrevGOOS
        $env:GOARCH = $PrevGOARCH
        $env:CGO_ENABLED = $PrevCGO
    }

    Write-Host "==> [5/6] Assembling portable package (manifest embedded in .exe)..." -ForegroundColor Cyan
    Copy-Item -LiteralPath (Join-Path $RepoRoot "packaging\使用说明.txt") -Destination (Join-Path $StagePkgDir "使用说明.txt")
    foreach ($File in $RequiredBridgeFiles) {
        Copy-Item -LiteralPath (Join-Path $BridgeSrcDir $File) -Destination (Join-Path $StagePkgDir $File)
    }

    Write-Host "==> [6/6] Validating and publishing portable release..." -ForegroundColor Cyan
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $StageFiles = @(Get-ChildItem -LiteralPath $StagePkgDir -File)
    $Archive = [System.IO.Compression.ZipFile]::Open($StageZip, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($File in $StageFiles) {
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $Archive, $File.FullName, "cs-burp-router/$($File.Name)", [System.IO.Compression.CompressionLevel]::Optimal
            ) | Out-Null
        }
    }
    finally {
        $Archive.Dispose()
    }
    $Hash = [System.Security.Cryptography.SHA256]::Create()
    $Archive = [System.IO.Compression.ZipFile]::OpenRead($StageZip)
    try {
        if ($Archive.Entries.Count -ne $StageFiles.Count) {
            throw "Unexpected file count in staged archive"
        }
        foreach ($File in $StageFiles) {
            $Entry = $Archive.GetEntry("cs-burp-router/$($File.Name)")
            if ($null -eq $Entry) {
                throw "Missing archive entry: $($File.Name)"
            }
            $Stream = $Entry.Open()
            try {
                $ArchiveHash = [Convert]::ToBase64String($Hash.ComputeHash($Stream))
                $StagedHash = [Convert]::ToBase64String($Hash.ComputeHash([System.IO.File]::ReadAllBytes($File.FullName)))
                if ($ArchiveHash -cne $StagedHash) {
                    throw "Archive entry differs from staged file: $($File.Name)"
                }
            }
            finally {
                $Stream.Dispose()
            }
        }
    }
    finally {
        $Hash.Dispose()
        $Archive.Dispose()
    }

    $Outputs = @(
        @{
            Staged = $StagePkgDir
            Published = $PackageDir
            Backup = Join-Path $StageRoot "previous-package"
            IsDirectory = $true
            Saved = $false
            Installed = $false
        },
        @{
            Staged = $StageZip
            Published = $ZipPath
            Backup = Join-Path $StageRoot "previous.zip"
            IsDirectory = $false
            Saved = $false
            Installed = $false
        }
    )
    foreach ($Output in $Outputs) {
        if (Test-Path -LiteralPath $Output.Published) {
            $Existing = Get-Item -LiteralPath $Output.Published -Force
            if ($Existing.PSIsContainer -ne $Output.IsDirectory -or
                ($Existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
                [System.IO.Path]::GetDirectoryName($Existing.FullName) -ne $DistDir.FullName) {
                throw "Unexpected release output: $($Existing.FullName)"
            }
        }
    }
    try {
        # Keep both previous outputs until both replacements have been installed.
        foreach ($Output in $Outputs) {
            if (Test-Path -LiteralPath $Output.Published) {
                Move-ReleaseOutput $Output.Published $Output.Backup $Output.IsDirectory
                $Output.Saved = $true
            }
        }
        foreach ($Output in $Outputs) {
            Move-ReleaseOutput $Output.Staged $Output.Published $Output.IsDirectory
            $Output.Installed = $true
        }
    }
    catch {
        for ($Index = $Outputs.Count - 1; $Index -ge 0; $Index--) {
            $Output = $Outputs[$Index]
            try {
                if ($Output.Installed) {
                    Move-ReleaseOutput $Output.Published $Output.Staged $Output.IsDirectory
                }
                if ($Output.Saved) {
                    Move-ReleaseOutput $Output.Backup $Output.Published $Output.IsDirectory
                }
            }
            catch {
                $KeepStage = $true
                Write-Warning "Could not restore $($Output.Published). Recovery files are in $StageRoot. $($_.Exception.Message)"
            }
        }
        throw
    }

    $ZipInfo = Get-Item -LiteralPath $ZipPath
    $ExeInfo = Get-Item -LiteralPath (Join-Path $PackageDir "cs-burp-router.exe")
    Write-Host ""
    Write-Host "Build & packaging succeeded!" -ForegroundColor Green
    Write-Host ("  Executable   : {0} ({1:N2} MB, Version={2})" -f $ExeInfo.FullName, ($ExeInfo.Length / 1MB), $ExeInfo.VersionInfo.FileVersion)
    Write-Host ("  Description  : {0}" -f $ExeInfo.VersionInfo.FileDescription)
    Write-Host ("  Portable Zip : {0} ({1:N2} MB)" -f $ZipInfo.FullName, ($ZipInfo.Length / 1MB))
}
finally {
    try {
        if ($StageRoot -and -not $KeepStage -and (Test-Path -LiteralPath $StageRoot)) {
            $StageDir = Get-Item -LiteralPath $StageRoot -Force
            if (-not $StageDir.PSIsContainer -or
                ($StageDir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
                $StageDir.Parent.FullName -ne $DistDir.FullName) {
                throw "Unexpected staging path: $($StageDir.FullName)"
            }
            [System.IO.Directory]::Delete($StageDir.FullName, $true)
        }
    }
    catch {
        Write-Warning "Could not clean staging directory $StageRoot. $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $ReleaseLock) {
            $ReleaseLock.Dispose()
        }
        Pop-Location
    }
}
