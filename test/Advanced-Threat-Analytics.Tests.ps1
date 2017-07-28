$ModuleManifestName = 'Advanced-Threat-Analytics.psd1'
$ModuleManifestPath = "$PSScriptRoot\..\$ModuleManifestName"

Describe 'Module Manifest Tests' {
    It 'Passes Test-ModuleManifest' {
        Test-ModuleManifest -Path $ModuleManifestPath
        $? | Should Be $true
    }
}

function Test-ATACommand([System.Management.Automation.ScriptBlock]$ScriptBlock) {
    try{
        .$ScriptBlock | Out-Null
        Write-Host "Success: $ScriptBlock" -ForegroundColor Green
    }
    catch{Write-Host $Error[0] -ForegroundColor Red}
}

Import-Module Advanced-Threat-Analytics
Resolve-ATASelfSignedCert
Set-ATACenterURL 'atacenter.k45515.com'

test-atacommand -ScriptBlock {$Script:Test_SA = Get-ATASuspiciousActivity | ? {$_.Type -match 'SAMR'}}
test-atacommand -ScriptBlock {Get-ATAUniqueEntity ($Script:Test_SA).sourcecomputerid}
test-atacommand -ScriptBlock {Get-ATAMonitoringAlert -status Closed}
test-atacommand -ScriptBlock {Get-ATAStatus -center}
test-atacommand -ScriptBlock {Get-ATAStatus -gateway}
test-atacommand -ScriptBlock {Get-ATAStatus -license}
test-atacommand -ScriptBlock {$Script:Test_SA | Set-ATASuspiciousActivity -status Closed -Force}
test-atacommand -ScriptBlock {$Script:Test_SA | Set-ATASuspiciousActivity -status Open -Force}
test-atacommand -ScriptBlock {$Script:Test_SA | foreach {Get-ATASuspiciousActivity -id $_.id -export C:\}}