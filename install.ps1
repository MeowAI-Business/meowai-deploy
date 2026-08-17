$ErrorActionPreference = 'Stop'

# Override these variables when testing a private release mirror.
$releaseBaseUrl = if ($env:MEOWAI_DEPLOY_RELEASE_BASE_URL) {
    $env:MEOWAI_DEPLOY_RELEASE_BASE_URL.TrimEnd('/')
} else {
    'https://github.com/MeowAI-Business/meowai-deploy/releases/latest/download'
}
$installDir = if ($env:MEOWAI_DEPLOY_INSTALL_DIR) {
    [Environment]::ExpandEnvironmentVariables($env:MEOWAI_DEPLOY_INSTALL_DIR)
} else {
    Join-Path $env:LOCALAPPDATA 'Programs\meowai-deploy'
}
$checksumName = 'checksums-sha256.txt'
$temporaryDir = Join-Path ([IO.Path]::GetTempPath()) ('meowai-deploy.' + [Guid]::NewGuid().ToString('N'))

function Test-PathEntryMatches {
    param(
        [string]$Entry,
        [string]$Target
    )
    if ([string]::IsNullOrWhiteSpace($Entry)) {
        return $false
    }
    try {
        $expanded = [Environment]::ExpandEnvironmentVariables($Entry.Trim('"'))
        return [IO.Path]::GetFullPath($expanded).TrimEnd('\') -ieq $Target
    } catch {
        return $false
    }
}

try {
    $effectiveArchitecture = if ($env:PROCESSOR_ARCHITEW6432) {
        $env:PROCESSOR_ARCHITEW6432
    } else {
        $env:PROCESSOR_ARCHITECTURE
    }
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'meowai-deploy Windows installer supports 64-bit Windows only.'
    }
    $normalizedArchitecture = $effectiveArchitecture.ToUpperInvariant()
    if ($normalizedArchitecture -in @('AMD64', 'X86_64')) {
        $targetArch = 'amd64'
    } elseif ($normalizedArchitecture -in @('ARM64', 'AARCH64')) {
        $targetArch = 'arm64'
    } else {
        throw "meowai-deploy Windows installer does not support architecture $effectiveArchitecture."
    }
    $artifactName = "meowai-deploy-windows-$targetArch.zip"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    New-Item -ItemType Directory -Path $temporaryDir -Force | Out-Null
    $archivePath = Join-Path $temporaryDir $artifactName
    $checksumPath = Join-Path $temporaryDir $checksumName
    Invoke-WebRequest -UseBasicParsing -Uri "$releaseBaseUrl/$artifactName" -OutFile $archivePath
    Invoke-WebRequest -UseBasicParsing -Uri "$releaseBaseUrl/$checksumName" -OutFile $checksumPath

    $checksumLine = Get-Content -LiteralPath $checksumPath | Where-Object {
        $_ -match ('\s' + [Regex]::Escape($artifactName) + '$')
    } | Select-Object -First 1
    if (-not $checksumLine -or -not ($checksumLine -match '^([0-9a-fA-F]{64})\s+')) {
        throw "Release checksum does not contain $artifactName."
    }
    $expectedHash = $Matches[1].ToLowerInvariant()
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($expectedHash -ne $actualHash) {
        throw 'SHA256 verification failed.'
    }

    $extractDir = Join-Path $temporaryDir 'extract'
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir -Force
    $binaryPath = Join-Path $extractDir 'meowai-deploy.exe'
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
        throw 'Release archive does not contain meowai-deploy.exe.'
    }

    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    $destination = Join-Path $installDir 'meowai-deploy.exe'
    $staged = Join-Path $installDir 'meowai-deploy.exe.new'
    Copy-Item -LiteralPath $binaryPath -Destination $staged -Force
    try {
        Move-Item -LiteralPath $staged -Destination $destination -Force
    } catch {
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        throw 'Could not replace meowai-deploy.exe. Close a running copy and retry.'
    }
    Write-Host "Installed meowai-deploy to $destination"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $pathEntries = @()
    if ($userPath) {
        $pathEntries = $userPath -split ';' | Where-Object { $_ -ne '' }
    }
    $normalizedInstall = [IO.Path]::GetFullPath($installDir).TrimEnd('\')
    $alreadyPresent = $pathEntries | Where-Object { Test-PathEntryMatches $_ $normalizedInstall }
    if (-not $alreadyPresent) {
        $updatedPath = (($pathEntries + $installDir) -join ';')
        [Environment]::SetEnvironmentVariable('Path', $updatedPath, 'User')
        if (($env:Path -split ';' | Where-Object { Test-PathEntryMatches $_ $normalizedInstall }).Count -eq 0) {
            $env:Path = "$installDir;$env:Path"
        }
        Write-Host "Added $installDir to the current user's PATH."
    }
    Write-Host 'Open a new terminal if PATH was changed.'
    Write-Host 'Run: meowai-deploy doctor'
    Write-Host 'Then: meowai-deploy onboard --ssh user@linux-host'
} finally {
    if (Test-Path -LiteralPath $temporaryDir) {
        Remove-Item -LiteralPath $temporaryDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
