#
# Build application and installer script.
#

[CmdletBinding(PositionalBinding = $false)]
param (
    [switch]$OnlyBuild = $false
)

$projDir = 'Vault\Explorer'

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$workingDir = $pwd
Write-Output "Working directory: $workingDir"

# Find MSBuild.
$msBuildPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe `
    -prerelease | Select-Object -First 1
Write-Output "MSBuild: $((Get-Command $msBuildPath).Path)"

# Load current Git tag.
$tag = $(git describe --tags)
Write-Output "Tag: $tag"

# Trim tag.
$version = $tag.TrimStart('v').Split('-')[0]
Write-Output "Version: $version"

# Build the aplication
Push-Location $projDir
try {
    Write-Output 'Running init.cmd'
    Start-Process -Wait $workingDir\init.cmd

    Write-Output 'Restoring:'
    dotnet restore -r win-x64
    
    Write-Output 'Building:'
    $msBuildVerbosityArg = '/v:m'
    if ($env:CI) {
        $msBuildVerbosityArg = ''
    }

    & $msBuildPath /target:build `
        /p:ApplicationVersion=$version `
        /p:Configuration=Release /p:Platform=x64 `
        $msBuildVerbosityArg
} finally {
    Pop-Location
    Write-Output 'Application build process completed.'
}


if ($OnlyBuild) {
    Write-Output 'Build finished.'
    exit
}

# Build the installer
try {
    Write-Output 'Building installer...'
    Write-Output "Version to use: $version"
    
    & iscc.exe "Installer\installer.iss" /DVERSION=$version

    # Measure installer size.
    $installerFile = "Installer\vault-explorer-installer.exe"
    if (Test-Path $installerFile) {
        $installerSize = (Get-Item -Path $installerFile).Length / 1Mb
        Write-Output ('Finished installer size: {0:N2} MB' -f $installerSize)
    } else {
        Write-Output "Installer file not found: $installerFile"
    }
} finally {
    Write-Output 'Installer build process completed.'
}
