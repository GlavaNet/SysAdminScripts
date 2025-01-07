# Requires elevation (Run as Administrator)
#Requires -Version 5.1

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantID,
    
    [Parameter(Mandatory=$true)]
    [string]$LoginEmail,
    
    [Parameter()]
    [string]$ComputerName = $env:COMPUTERNAME
)

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Join-EntraDomain {
    try {
        # Ensure we have the required module
        if (!(Get-Module -ListAvailable -Name AzureAD)) {
            Write-Host "Installing AzureAD module..."
            Install-Module AzureAD -Force -AllowClobber
        }

        # Import the module
        Import-Module AzureAD

        # Connect to Azure AD
        Write-Host "Connecting to Entra ID..."
        Connect-AzureAD -TenantId $TenantID

        # Join the device to Entra ID
        Write-Host "Joining device to Entra ID..."
        Add-AzureADDevice -AccountId $LoginEmail -DeviceName $ComputerName

        Write-Host "Device successfully joined to Entra ID domain." -ForegroundColor Green
        Write-Host "Please restart your computer to complete the process."
    }
    catch {
        Write-Host "Error joining domain: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Check for admin privileges
if (!(Test-AdminPrivileges)) {
    Write-Host "This script requires administrator privileges. Please run as administrator." -ForegroundColor Red
    exit 1
}

# Execute domain join
Join-EntraDomain