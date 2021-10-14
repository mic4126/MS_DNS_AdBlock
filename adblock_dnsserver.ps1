[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $SkipRemoveOldPolicy = $false,
    [Parameter()]
    [switch]
    $RemoveOldPolicyOnly = $false

)

$rawHostFile = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
$policyNamePrefix = "adblock"
$groupSize = 1000
$computernames = @("dns-server", "dns-server01", "dns-server02")
# whitelist references https://discourse.pi-hole.net/t/commonly-whitelisted-domains/212
$whiteList = @(
    "clients2.google.com",
    "clients4.google.com",
    "s.youtube.com",
    "video-stats.l.google.com",
    "android.clients.google.com",
    "reminders-pa.googleapis.com",
    "firestore.googleapis.com",
    "gstaticadssl.l.google.com",
    "googleapis.l.google.com",
    "dl.google.com",
    "redirector.gvt1.com",
    "www.msftncsi.com",
    "outlook.office365.com",
    "products.office.com",
    "c.s-microsoft.com",
    "i.s-microsoft.com",
    "login.live.com",
    "g.live.com"
)


$hostFile = $rawHostFile.Content.Split('# End of custom host records.')[1].Split('# End yoyo.org')[0]
$array = ($hostFile -split '\r?\n')
# $sb = [System.Text.StringBuilder]::new()
if (!$SkipRemoveOldPolicy) {
    # remove existing rule
    foreach ($computername in $computernames) {
        
        $policyToBeRemoved = Get-DnsServerQueryResolutionPolicy -ComputerName $computername | where { $_.name -match "adblock" } 
        
        for ($i = 0; $i -lt $policyToBeRemoved.Count; $i++) {
            Write-Progress -Activity "Remove Old policy" -Status "$i of $($policyToBeRemoved.Count)" -PercentComplete (($i / $policyToBeRemoved.Count) * 100)
            $policyToBeRemoved[$i] | Remove-DnsServerQueryResolutionPolicy -ComputerName $computername -Force
        }
        Write-Progress -Activity "Remove Old policy"-Completed
    }
}
if (!$RemoveOldPolicyOnly) {
    
    $FilteredList = New-Object -TypeName "System.Collections.ArrayList"
    $tempList = New-Object -TypeName "System.Collections.ArrayList"
    for ($i = 0; $i -lt $array.Count; $i++) {
        if ( $array[$i] -match '0.0.0.0\s(?<adserver>[\w\-\.]+)([ \t].+)?' && $array[$i] -notin $whiteList) {
            $FilteredList.Add($Matches.adserver) > $null            
        }
    }
    $numberOfRule = [math]::Ceiling(($FilteredList.Count / $groupSize))
    
    foreach ($computername in $computernames) {
        [int]$policyIndex = 1
        for ($i = 0; $i -lt $FilteredList.Count; $i = $i + $groupSize ) {
            $blockedservers = $FilteredList.GetRange($i, [math]::min($groupSize, ($FilteredList.Count - $i))).toArray() | Join-String -Separator ','
            Write-Progress -Activity "Adding Block Rule" -PercentComplete ($policyIndex / $numberOfRule * 100) -Status "Adding $policyIndex of $numberOfRule"
            $fqdn = "EQ,$($blockedservers)"
            Add-DnsServerQueryResolutionPolicy -Name "$policyNamePrefix-$policyIndex" -Fqdn $fqdn -ComputerName $computername -Action "DENY"   
            $policyIndex++
            $tempList.Clear()
        }

    
        Write-Progress -Activity "Adding Block Rule" -Completed
    }
}
