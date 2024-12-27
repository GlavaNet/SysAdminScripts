# Requires elevation (Run as Administrator)
#Requires -Version 5.1

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantID,
    
    [Parameter(Mandatory=$true)]
    [string]$LoginEmail,
    
    [Parameter(Mandatory=$true)]
    [string]$MsiUrl,
    
    [Parameter()]
    [string]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [string]$ScriptUrl = "https://raw.githubusercontent.com/YOUR-USERNAME/YOUR-REPO/main/Join-EntraDomain.ps1",

    [Parameter()]
    [string]$ExpectedMsiHash,  # SHA256 hash for verification
    
    [Parameter()]
    [switch]$DisableScriptLogging
)

# Disable PowerShell script logging if requested
if ($DisableScriptLogging) {
    $LogPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (!(Test-Path $LogPath)) {
        New-Item -Path $LogPath -Force
    }
    Set-ItemProperty -Path $LogPath -Name EnableScriptBlockLogging -Value 0
}

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-MSIPackage {
    param (
        [string]$MsiPath
    )
    
    try {
        # Verify MSI hash if provided
        if ($ExpectedMsiHash) {
            $actualHash = (Get-FileHash -Path $MsiPath -Algorithm SHA256).Hash
            if ($actualHash -ne $ExpectedMsiHash) {
                throw "MSI hash verification failed! File may be corrupted or tampered with."
            }
            Write-Host "MSI hash verification successful" -ForegroundColor Green
        }

        Write-Host "Installing MSI package..."
        $args = @(
            "/i"
            "`"$MsiPath`""
            "/qn"
            "/norestart"
            "/L*v `"$env:TEMP\msi_install_log.txt`""  # Verbose logging to temp directory
        )
        
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Host "MSI package installed successfully." -ForegroundColor Green
        } else {
            throw "MSI installation failed with exit code: $($process.ExitCode)"
        }
    }
    catch {
        throw "Failed to install MSI: $($_.Exception.Message)"
    }
}

# Create a unique temporary directory with random name
$randomGuid = [System.Guid]::NewGuid().ToString()
$tempDir = Join-Path $env:TEMP "EntraDomainJoin_$randomGuid"

try {
    # Check for admin privileges first
    if (!(Test-AdminPrivileges)) {
        throw "This script requires administrator privileges. Please run as administrator."
    }

    # Create temp directory
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    # Set directory permissions to restrict access
    $acl = Get-Acl $tempDir
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl $tempDir $acl

    # Configure security for TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Download and install MSI package
    Write-Host "Downloading MSI package..."
    $msiPath = Join-Path $tempDir "package.msi"
    $curlArgs = @(
        "-L",
        "--fail",  # Fail on HTTP errors
        "--silent",
        "--show-error",
        "-o", $msiPath,
        $MsiUrl
    )
    
    $curlProcess = Start-Process -FilePath "curl.exe" -ArgumentList $curlArgs -Wait -PassThru -WindowStyle Hidden
    if ($curlProcess.ExitCode -ne 0) {
        throw "Failed to download MSI package using curl"
    }

    # Install the MSI package
    Install-MSIPackage -MsiPath $msiPath

    # Download the domain join script
    Write-Host "Downloading domain join script..."
    $scriptPath = Join-Path $tempDir "Join-EntraDomain.ps1"
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("User-Agent", "PowerShell Script")
    $webClient.DownloadFile($ScriptUrl, $scriptPath)

    # Execute the script with parameters
    Write-Host "Executing domain join script..."
    & $scriptPath -TenantID $TenantID -LoginEmail $LoginEmail -ComputerName $ComputerName
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    # Always clean up, even if there's an error
    if (Test-Path $tempDir) {
        # Securely delete files
        Get-ChildItem -Path $tempDir -Recurse | ForEach-Object {
            $stream = [System.IO.File]::OpenWrite($_.FullName)
            $stream.SetLength(0)
            $stream.Close()
        }
        Remove-Item -Path $tempDir -Recurse -Force
    }
}