# STIG-Implementation-WN11-CC-000100

## The initial scan results

In the initial scan, over 148 audits failed out of 263.

The failed audit I will be remediating is:

> WN11-CC-000100 - Downloading print driver packages over HTTP must be prevented.

[image]

## Research on the stig

After doing some research on the WN11-CC-000100, I found out that this version that of the DISA STIG that I am using is actually the outdated version. The updated version is DISA Microsoft Windows 11 STIG v2r7 and was updated on June 16, 2026 while the version I am using for these audits is actually DISA Windows 11 STIG v1r6 from August of 2024.

For the sake of the lab, I will ignore this but it is something worthwhile to note, and the solution is still provided on the Tenable scan results. 

[image]

## Manual remediation 

With the instructions from Tenable to manually remediate this issue, I must:

> Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings >> 'Turn off downloading of print drivers over HTTP' to 'Enabled'.

[image]

Now, I will restart the machine and rerun the scan to see if the manual remediation for this audit was successful.

[image]

As you can see from the results above, the scan showed that the manual remediation was successful! Now im going to undo what i did and redo the scan to confirm manual remediation was removed so i can move on to a pragmatic solution.

## Scan results after removing manual remediation 

```powershell
# STIG WN11-CC-000100: Downloading print driver packages over HTTP must be prevented
$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
$Name    = 'DisableWebPnPDownload'
$Desired = 1   # 1 = Enabled (block print driver downloads over HTTP)

# Create the registry path if it does not exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
    Write-Host "Created registry path: $RegPath"
}

# Apply the DisableWebPnPDownload value
Set-ItemProperty -Path $RegPath -Name $Name -Value $Desired -Type DWord -Force
Write-Host "Set $Name to $Desired in $RegPath"

# Verify
$Current = (Get-ItemProperty -Path $RegPath -Name $Name).$Name
if ($Current -eq $Desired) {
    Write-Host "Compliant: $Name = $Current"
} else {
    Write-Warning "Non-compliant: $Name = $Current, expected $Desired"
}
```





[image]

As you can see, the manual remediation was successfully removed because the audit has switched back to failed.

## I am now going to create a pragmatic solution 

Bellow is the pragmatic solution for this STIG i created with claude.
