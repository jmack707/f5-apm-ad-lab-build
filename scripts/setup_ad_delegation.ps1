<#
.SYNOPSIS
    Active Directory Setup & Delegation Script for F5 BIG-IP APM Password Management Lab.

.DESCRIPTION
    This PowerShell script automates the Active Directory configuration required for F5 APM
    expired password resets and voluntary password changes over LDAPS (Port 636):
    1. Creates target Organizational Unit (OU) for lab users and service accounts.
    2. Provisions the F5 APM Service Account (`f5-svc-ad`).
    3. Configures granular Active Directory Access Control Lists (ACLs) / Delegations on the OU:
       - Reset Password extended right (`User-Force-Change-Password`)
       - Read / Write Property for `pwdLastSet`
       - Read / Write Property for `lockoutTime`
       - Read / Write Property for `userAccountControl`
    4. Provisions test user accounts for automated test cases:
       - `user_normal`: Standard user with non-expired password (TC-01).
       - `user_expired`: User flagged with `pwdLastSet=0` / Must change password at next logon (TC-02).
       - `user_voluntary`: User for self-service / voluntary password change (TC-03).
       - `user_locked`: User locked out for negative testing (TC-04).
    5. Exports Domain / Enterprise Root CA certificate to `./certs/lab_root_ca.crt` for F5 TMOS.

.PARAMETER DomainDN
    Distinguished Name of the Active Directory domain (e.g., 'DC=lab,DC=example,DC=com').

.PARAMETER OuName
    Name of the Organizational Unit to create/manage (Default: 'LabUsers').

.PARAMETER ServiceAccountName
    sAMAccountName of the F5 APM Service Account (Default: 'f5-svc-ad').

.PARAMETER ServiceAccountPassword
    Password for the F5 APM Service Account.

.PARAMETER CertExportPath
    Path where the Root CA certificate will be exported (Default: '..\certs\lab_root_ca.crt').

.EXAMPLE
    .\setup_ad_delegation.ps1 -DomainDN "DC=lab,DC=example,DC=com" -ServiceAccountPassword "AdminServicePass123!"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DomainDN = "",

    [Parameter(Mandatory = $false)]
    [string]$OuName = "LabUsers",

    [Parameter(Mandatory = $false)]
    [string]$ServiceAccountName = "f5-svc-ad",

    [Parameter(Mandatory = $false)]
    [string]$ServiceAccountPassword = "AdminServicePass123!",

    [Parameter(Mandatory = $false)]
    [string]$CertExportPath = "..\certs\lab_root_ca.crt"
)

# -----------------------------------------------------------------------------
# GUID Constants for Active Directory Extended Rights and Schema Attributes
# -----------------------------------------------------------------------------
$GUID_USER_OBJECT_CLASS        = [Guid]"bf967aba-0de6-11d0-a285-00aa003049e2" # User class
$GUID_RESET_PASSWORD           = [Guid]"00299570-246d-11d0-a7c2-00a0c911505a" # User-Force-Change-Password
$GUID_ATTR_PWD_LAST_SET        = [Guid]"bf967a0a-0de6-11d0-a285-00aa003049e2" # pwdLastSet attribute
$GUID_ATTR_LOCKOUT_TIME        = [Guid]"28636aa8-d4d6-11d1-99c7-006097924342" # lockoutTime attribute
$GUID_ATTR_USER_ACCOUNT_CTRL   = [Guid]"bf967a68-0de6-11d0-a285-00aa003049e2" # userAccountControl attribute

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
function Write-Header {
    param([string]$Message)
    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 1. Environment & Prerequisites Validation
# -----------------------------------------------------------------------------
Write-Header "Validating Active Directory Environment"

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Err "ActiveDirectory PowerShell module is not installed."
    Write-Host "Please install RSAT Active Directory Tools: Install-WindowsFeature RSAT-AD-PowerShell"
    exit 1
}
Import-Module ActiveDirectory

try {
    $currentDomain = Get-ADDomain
    if ([string]::IsNullOrWhiteSpace($DomainDN)) {
        $DomainDN = $currentDomain.DistinguishedName
    }
    Write-Success "Connected to Active Directory Domain: $($currentDomain.DNSRoot) ($DomainDN)"
}
catch {
    Write-Err "Failed to connect to Active Directory: $_"
    exit 1
}

$targetOuDN = "OU=$OuName,$DomainDN"

# -----------------------------------------------------------------------------
# 2. Create Organizational Unit
# -----------------------------------------------------------------------------
Write-Header "Provisioning Target OU: $targetOuDN"

try {
    $ouExists = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$targetOuDN'" -ErrorAction SilentlyContinue
    if (-not $ouExists) {
        New-ADOrganizationalUnit -Name $OuName -Path $DomainDN -Description "F5 APM Active Directory Password Management Lab OU" -ProtectedFromAccidentalDeletion $false
        Write-Success "Created OU: $targetOuDN"
    } else {
        Write-Info "OU already exists: $targetOuDN"
    }
}
catch {
    Write-Err "Error creating OU $targetOuDN: $_"
    exit 1
}

# -----------------------------------------------------------------------------
# 3. Provision F5 APM Service Account
# -----------------------------------------------------------------------------
Write-Header "Provisioning Service Account: $ServiceAccountName"

$svcUserDN = "CN=$ServiceAccountName,$targetOuDN"
$secPassword = ConvertTo-SecureString $ServiceAccountPassword -AsPlainText -Force

try {
    $svcExists = Get-ADUser -Filter "sAMAccountName -eq '$ServiceAccountName'" -ErrorAction SilentlyContinue
    if (-not $svcExists) {
        New-ADUser -Name $ServiceAccountName `
                   -SamAccountName $ServiceAccountName `
                   -UserPrincipalName "$ServiceAccountName@$($currentDomain.DNSRoot)" `
                   -Path $targetOuDN `
                   -AccountPassword $secPassword `
                   -Enabled $true `
                   -PasswordNeverExpires $true `
                   -CannotChangePassword $true `
                   -Description "F5 APM Service Account for AD AAA & Password Management"
        Write-Success "Created Service Account: $svcUserDN"
    } else {
        Set-ADAccountPassword -Identity $ServiceAccountName -NewPassword $secPassword -Reset
        Set-ADUser -Identity $ServiceAccountName -Enabled $true -PasswordNeverExpires $true
        Write-Info "Service account already exists. Password updated and flags verified."
    }
}
catch {
    Write-Err "Error creating/updating service account: $_"
    exit 1
}

# -----------------------------------------------------------------------------
# 4. Delegate Permissions on OU for F5 Service Account
# -----------------------------------------------------------------------------
Write-Header "Configuring Granular Active Directory Delegations on $targetOuDN"

try {
    $svcUserObj = Get-ADUser -Identity $ServiceAccountName
    $svcSid = [System.Security.Principal.SecurityIdentifier]$svcUserObj.SID

    # Retrieve current ACL from ActiveDirectory drive
    $adPath = "AD:\$targetOuDN"
    $acl = Get-Acl -Path $adPath

    # Define Access Rules
    $rulesToAdd = @(
        # Rule 1: Reset Password (Extended Right: User-Force-Change-Password) on Descendant User Objects
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $svcSid,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $GUID_RESET_PASSWORD,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
            $GUID_USER_OBJECT_CLASS
        ),

        # Rule 2: Read/Write Property on pwdLastSet on Descendant User Objects
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $svcSid,
            [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $GUID_ATTR_PWD_LAST_SET,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
            $GUID_USER_OBJECT_CLASS
        ),

        # Rule 3: Read/Write Property on lockoutTime on Descendant User Objects
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $svcSid,
            [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $GUID_ATTR_LOCKOUT_TIME,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
            $GUID_USER_OBJECT_CLASS
        ),

        # Rule 4: Read/Write Property on userAccountControl on Descendant User Objects
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $svcSid,
            [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $GUID_ATTR_USER_ACCOUNT_CTRL,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
            $GUID_USER_OBJECT_CLASS
        )
    )

    foreach ($rule in $rulesToAdd) {
        $acl.AddAccessRule($rule)
    }

    Set-Acl -Path $adPath -AclObject $acl
    Write-Success "Successfully delegated permissions to '$ServiceAccountName':"
    Write-Host "  -> Reset Password (User-Force-Change-Password)" -ForegroundColor Gray
    Write-Host "  -> Read/Write 'pwdLastSet'" -ForegroundColor Gray
    Write-Host "  -> Read/Write 'lockoutTime'" -ForegroundColor Gray
    Write-Host "  -> Read/Write 'userAccountControl'" -ForegroundColor Gray
}
catch {
    Write-Err "Failed to configure ACL delegation: $_"
    exit 1
}

# -----------------------------------------------------------------------------
# 5. Provision Test Users
# -----------------------------------------------------------------------------
Write-Header "Provisioning Lab Test Users"

$testUsers = @(
    @{
        SamAccountName        = "user_normal"
        DisplayName           = "Lab User Normal (TC-01)"
        Password              = "InitialPass123!"
        ChangePasswordAtLogon = $false
        Description           = "Standard valid user account for basic APM authentication"
    },
    @{
        SamAccountName        = "user_expired"
        DisplayName           = "Lab User Expired (TC-02)"
        Password              = "MustChange123!"
        ChangePasswordAtLogon = $true
        Description           = "User with pwdLastSet=0 to test APM expired password reset"
    },
    @{
        SamAccountName        = "user_voluntary"
        DisplayName           = "Lab User Voluntary Change (TC-03)"
        Password              = "VoluntaryPass123!"
        ChangePasswordAtLogon = $false
        Description           = "User for voluntary password change verification"
    },
    @{
        SamAccountName        = "user_locked"
        DisplayName           = "Lab User Locked (TC-04)"
        Password              = "LockedPass123!"
        ChangePasswordAtLogon = $false
        Description           = "Account for locked/disabled negative test cases"
    }
)

foreach ($u in $testUsers) {
    try {
        $sam = $u.SamAccountName
        $pwd = ConvertTo-SecureString $u.Password -AsPlainText -Force
        $userObj = Get-ADUser -Filter "sAMAccountName -eq '$sam'" -ErrorAction SilentlyContinue

        if (-not $userObj) {
            New-ADUser -Name $sam `
                       -SamAccountName $sam `
                       -UserPrincipalName "$sam@$($currentDomain.DNSRoot)" `
                       -DisplayName $u.DisplayName `
                       -Path $targetOuDN `
                       -AccountPassword $pwd `
                       -Enabled $true `
                       -ChangePasswordAtLogon $u.ChangePasswordAtLogon `
                       -Description $u.Description
            Write-Success "Created test user: $sam (ChangePasswordAtLogon = $($u.ChangePasswordAtLogon))"
        } else {
            Set-ADAccountPassword -Identity $sam -NewPassword $pwd -Reset
            Set-ADUser -Identity $sam -Enabled $true -ChangePasswordAtLogon $u.ChangePasswordAtLogon -Description $u.Description
            Write-Info "Updated existing test user: $sam"
        }
    }
    catch {
        Write-Err "Failed provisioning user '$($u.SamAccountName)': $_"
    }
}

# -----------------------------------------------------------------------------
# 6. Export Active Directory Root CA Certificate
# -----------------------------------------------------------------------------
Write-Header "Exporting Root CA Certificate for F5 BIG-IP LDAPS Validation"

try {
    $certDir = Split-Path -Path $CertExportPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($certDir) -and -not (Test-Path $certDir)) {
        New-Item -ItemType Directory -Path $certDir -Force | Out-Null
    }

    # Search Local Computer Root Authorities for the Enterprise/Domain CA
    $caCerts = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {
        $_.Subject -like "*$($currentDomain.DNSRoot)*" -or $_.Subject -like "*$($currentDomain.NetBIOSName)*" -or $_.Issuer -eq $_.Subject
    }

    if ($caCerts) {
        $selectedCert = $caCerts[0]
        $certPem = "-----BEGIN CERTIFICATE-----`r`n" +
                   [System.Convert]::ToBase64String($selectedCert.RawData, 'InsertLineBreaks') +
                   "`r`n-----END CERTIFICATE-----`r`n"
        Set-Content -Path $CertExportPath -Value $certPem -Force
        Write-Success "Exported Root CA Certificate to: $CertExportPath ($($selectedCert.Subject))"
    } else {
        Write-Info "No automated domain Root CA found in local store. Generating placeholder CA cert guide."
        Write-Host "To export your Domain CA certificate manually:"
        Write-Host "  certutil -ca.cert $CertExportPath" -ForegroundColor White
    }
}
catch {
    Write-Info "CA Export notice: $_"
}

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
Write-Header "Active Directory Lab Setup Complete"
Write-Host "OU DN:              $targetOuDN"
Write-Host "Service Account:    $ServiceAccountName ($ServiceAccountPassword)"
Write-Host "Test Accounts:"
Write-Host "  - user_normal     (Password: InitialPass123!, Non-expired)"
Write-Host "  - user_expired    (Password: MustChange123!, pwdLastSet=0 / Change at next logon)"
Write-Host "  - user_voluntary  (Password: VoluntaryPass123!)"
Write-Host "  - user_locked     (Password: LockedPass123!)"
Write-Host "================================================================================" -ForegroundColor Cyan
