[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $SkipRemoveOldPolicy = $false,
    [Parameter()]
    [switch]
    $RemoveOldPolicyOnly = $false

)
$hostFileURL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
$policyNamePrefix = "adblock"
$groupSize = 5000
$computernames = @("dns-server", "dns-server01", "dns-server02")

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
    "g.live.com",
    "tracking-protection.cdn.mozilla.net",
    "dl.delivery.mp.microsoft.com", 
    "geo-prod.do.dsp.mp.microsoft.com", 
    "displaycatalog.mp.microsoft.com"
    "sls.update.microsoft.com.akadns.net",
    "fe3.delivery.dsp.mp.microsoft.com.nsatc.net",
    "tlu.dl.delivery.mp.microsoft.com",
    "msedge.api.cdp.microsoft.com",
    "clientconfig.passport.net",
    "v10.events.data.microsoft.com",
    "v20.events.data.microsoft.com",
    "client-s.gateway.messenger.live.com",
    "arc.msn.com",
    "activity.windows.com",
    "xbox.ipv6.microsoft.com",
    "device.auth.xboxlive.com",
    "xbox.ipv6.microsoft.com",
    "device.auth.xboxlive.com",
    "www.msftncsi.com",
    "title.mgt.xboxlive.com",
    "xsts.auth.xboxlive.com",
    "title.auth.xboxlive.com",
    "ctldl.windowsupdate.com",
    "attestation.xboxlive.com",
    "xboxexperiencesprod.experimentation.xboxlive.com",
    "xflight.xboxlive.com",
    "cert.mgt.xboxlive.com",
    "xkms.xboxlive.com",
    "def-vef.xboxlive.com",
    "notify.xboxlive.com",
    "help.ui.xboxlive.com",
    "licensing.xboxlive.com",
    "eds.xboxlive.com",
    "www.xboxlive.com",
    "v10.vortex-win.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "s.gateway.messenger.live.com",
    "client-s.gateway.messenger.live.com",
    "ui.skype.com",
    "pricelist.skype.com",
    "apps.skype.com",
    "m.hotmail.com",
    "sa.symcb.com",
    "s1.symcb.com",
    "s2.symcb.com",
    "s3.symcb.com",
    "s4.symcb.com", 
    "s5.symcb.com",
    "officeclient.microsoft.com",
    "dev.virtualearth.net",
    "ecn.dev.virtualearth.net",
    "t0.ssl.ak.dynamic.tiles.virtualearth.net",
    "t0.ssl.ak.tiles.virtualearth.net",
    "connectivitycheck.android.com",
    "android.clients.google.com",
    "clients3.google.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.gstatic.com",
    "msftncsi.com",
    "www.msftncsi.com",
    "ipv6.msftncsi.com",
    "captive.apple.com",
    "gsp1.apple.com",
    "www.apple.com",
    "www.appleiphonecell.com",
    "itunes.apple.com",
    "s.mzstatic.com",
    "appleid.apple.com"
    
    )
    
    
    $MyInvocation.MyCommand.Name -match '(?<filename>.+)\.ps1' > $null
    Start-Transcript -Path (Get-Location | Join-Path -ChildPath "$($Matches.filename).log" ) 
    
    if ($PSVersionTable.PSVersion.Major -lt 7){
        Write-Warning "Please use Powershell 7 for better performance especially for host file processing."
    }
    # Fix TLS problem on Powershell 5.1
    [System.Net.ServicePointManager]::SecurityProtocol = "tls12,tls11"
    
    $rawHostFile = Invoke-WebRequest -Uri $hostFileURL
    # whitelist references https://discourse.pi-hole.net/t/commonly-whitelisted-domains/212
    
    
$hostFile = (($rawHostFile.Content -Split '# Start StevenBlack')[1] -Split '# End yoyo.org')[0]
$array = ($hostFile -split '\r?\n')
# $sb = [System.Text.StringBuilder]::new()
if (!$SkipRemoveOldPolicy) {
    # remove existing rule
    foreach ($computername in $computernames) {
        
        $policyToBeRemoved = Get-DnsServerQueryResolutionPolicy -ComputerName $computername | Where-Object { $_.name -match "adblock" } 
        
        for ($i = 0; $i -lt $policyToBeRemoved.Count; $i++) {
            Write-Progress -Activity "Remove Old policy on $computername" -Status "$i of $($policyToBeRemoved.Count)" -PercentComplete (($i / $policyToBeRemoved.Count) * 100)
            $policyToBeRemoved[$i] | Remove-DnsServerQueryResolutionPolicy -ComputerName $computername -Force
        }
        Write-Progress -Activity "Remove Old policy on $computername" -Completed
        Write-Host "Remove old policy from $computername done."
    }
}
if (!$RemoveOldPolicyOnly) {
    
    $FilteredList = New-Object -TypeName "System.Collections.ArrayList"
    $tempList = New-Object -TypeName "System.Collections.ArrayList"
    [regex]$hostMatch = [regex]::new( '0.0.0.0\s(?<adserver>[\w\-\.]+)([ \t].+)?', 'Compiled')
    for ($i = 0; $i -lt $array.Count; $i++) {
        
        $RegexMatch = $hostMatch.Match(($array[$i]))
        if (  $RegexMatch.Success -and $array[$i] -notin $whiteList) {
            $FilteredList.Add($RegexMatch.Groups["adserver"].Value) > $null                  
        }
        
        Write-Progress -Activity "Process HostFile" -Status "Line $i of $($array.Count)" -PercentComplete ($i / $array.Count * 100)
        # if ( $array[$i] -match '0.0.0.0\s(?<adserver>[\w\-\.]+)([ \t].+)?' -and $array[$i] -notin $whiteList) {
        
    }
    Write-Progress -Activity  "Process HostFile" -Completed
    Write-Host "Process HostFile done."
    $numberOfRule = [math]::Ceiling(($FilteredList.Count / $groupSize))
    
    foreach ($computername in $computernames) {
        [int]$policyIndex = 1
        for ($i = 0; $i -lt $FilteredList.Count; $i = $i + $groupSize ) {
            $blockedservers = $FilteredList.GetRange($i, [math]::min($groupSize, ($FilteredList.Count - $i))).toArray() -join ','
            Write-Progress -Activity "Adding Block Rule on $computername" -PercentComplete ($policyIndex / $numberOfRule * 100) -Status "Adding $policyIndex of $numberOfRule"
            $fqdn = "EQ, $($blockedservers)"
            Add-DnsServerQueryResolutionPolicy -Name "$policyNamePrefix-$policyIndex" -Fqdn $fqdn -ComputerName $computername -Action "DENY"   
            $policyIndex++
            $tempList.Clear()
        }

    
        Write-Progress -Activity "Adding Block Rule on $computername" -Completed
        Write-Host "Adding Block Rule on $computername done."
    }
}

Stop-Transcript
