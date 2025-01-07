# Requires elevation (Run as Administrator)
#Requires -Version 5.1

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantID,
    
    [Parameter(Mandatory=$true)]
    [string]$LoginEmail
)

function Join-EntraDomain {
    try {
        # Install AzureAD module if not present
        if (!(Get-Module -ListAvailable -Name AzureAD)) {
            Write-Host "Installing AzureAD module..."
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-Module AzureAD -Force -AllowClobber -Scope CurrentUser
        }

        # Import the module
        Import-Module AzureAD

        # Connect to Azure AD
        Write-Host "Connecting to Entra ID..."
        Connect-AzureAD -TenantId $TenantID

        # Join the device
        Write-Host "Joining device to Entra ID..."
        Add-AzureADDevice -AccountId $LoginEmail -DeviceName $env:COMPUTERNAME

        Write-Host "Device successfully joined to Entra ID domain." -ForegroundColor Green
        Write-Host "Please restart your computer to complete the process." -ForegroundColor Yellow
    }
    catch {
        Write-Host "Error joining domain: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires administrator privileges. Please run as administrator." -ForegroundColor Red
    exit 1
}

# Execute domain join
Join-EntraDomain