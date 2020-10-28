<#
	.NOTES
	===========================================================================
	Script name: RP4VMs-Protect.ps1
	Created on: 2020-10-27
	Author: Idan Kentor (@IdanKentor, idan.kentor@dell.com)
	Dependencies: None known
	===Tested Against Environment====
	vSphere Version: 6.5, 6.7, 7.0
	PowerCLI Version: PowerCLI 12.0
	PowerShell Version: 7.0
	OS Version: Windows 10, Windows Server 2012, 2016 and 2019
	RecoverPoint for VMs Version: 5.3
	===========================================================================
	.DESCRIPTION
	Protects VMs using RecoverPoint for VMs for a given ESX cluster.
	Facilitates auto-VM protection and tag-based protection.
	.Example
	$credentials = Get-Credential
	.\RP4VMs-Protect.ps1 -vc vc.idan.lab -credentials $credentials -esxcluster Venice -pluginserver pluginserver.idan.lab -list $true
	.Example
	.\RP4VMs-Protect.ps1 -vc vc.idan.lab -credentials $credentials -esxcluster Venice -pluginserver pluginserver.idan.lab
	.Example
	.\RP4VMs-Protect.ps1 -vc vc.idan.lab -vcuser idan@vsphere.local -vcpassword MyPassword -esxcluster Venice -pluginserver pluginserver.idan.lab
	.Example
	.\RP4VMs-Protect.ps1 -vc vc.idan.lab -credentials $credentials -esxcluster Venice -pluginserver pluginserver.idan.lab -tag prod
	.Example
	.\RP4VMs-Protect.ps1 -vc vc.idan.lab -credentials $credentials -esxcluster Venice -pluginserver pluginserver.idan.lab -excludevms Win2k19
#>
param(
    [Parameter(Mandatory = $true)]
    [String]$vc,

    [Parameter(Mandatory = $false)]
    [String]$vcport = '443',

    [Parameter(Mandatory = $false)]
    [String]$vcuser,

    [Parameter(Mandatory = $false)]
    [String]$vcpassword,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$credentials,

    [Parameter(Mandatory = $true)]
    [String]$esxcluster,

    [Parameter(Mandatory = $true)]
    [String]$pluginserver,

    [Parameter(Mandatory = $false)]
    [String]$rpvmcluster,

    [Parameter(Mandatory = $false)]
    [String]$excludevms,

    [Parameter(Mandatory = $false)]
    [Bool]$list = $false,

    [Parameter(Mandatory = $false)]
    [String]$tag,

    [Parameter(Mandatory = $false)]
    [Bool]$nomonitor = $false
)

function Get-VMsByCluster($esxcluster, $excludevms) {
    # Get all non-protected VMs per ESX cluster
    $unprotectedvms = New-Object System.Collections.Generic.List[System.Object]
    $esxclusterfinal = Get-Cluster -Name *$esxcluster*
    if ($esxclusterfinal) {
        $vms = Get-Cluster -Name $esxclusterfinal | Get-VM
        foreach ($vm in $vms){
            $settings = Get-AdvancedSetting -Entity $vm -Name RecoverPoint*
            if (!$settings) {
                if ($vm.name -notlike "*Plugin-Server*"){
                    if (!$vm.name.Contains($excludevms)){
                        $unprotectedvms.Add($vm)
                    }
                }
            }
        }
    }
    else {
        Write-Host "Could not find ESX cluster by name, existing" -ForegroundColor Red
        exit
    }
    return $unprotectedvms
}

function Get-RP4VMsClusters($uri, $headers) {
    # Get registered RP4VMs clusters
    $uri += "/rp-clusters?isRegistered=True"
    $response = Invoke-RestMethod -Method GET -uri $uri -SkipCertificateCheck -Headers $headers
    return $response
}

function Build-Payload($rpvmcluster, $vms){
    # Build payload for the recommendation/protection defaults API based on RP4VMs cluster and non-protected VMs
    $vmhash=@{}
    $clusterhash=@{}
    $finalarray = @{}
    $clusterhash["rpCluster"] = $rpvmcluster
    foreach ($vm in $vms.name){
        $vmhash["vm"]=$vm
        $vmarray+=@($vmhash)
        $vmhash=@{}
    }
    $finalarray["vms"] = $vmarray
    $finalarray += $clusterhash
    return $finalarray
}

function Get-ProtectDefaults($uri, $headers, $payload, $rpvmsystemid) {
    # Execute the recommendation API
    $uri += "/rp-systems/"+$rpvmsystemid+"/vms/protect-multiple/defaults"
    $payload = $payload | ConvertTo-Json
    $response = Invoke-RestMethod -Method POST -uri $uri -SkipCertificateCheck -Headers $headers -Body $payload | ConvertTo-Json -Depth 10
    return $response
}

function Protect-VMs($uri, $headers, $payload, $rpvmsystemid) {
    # Protect VMs based on the list of non-protected VMs
    $uri += "/rp-systems/"+$rpvmsystemid+"/vms/protect-multiple"
    $response = Invoke-RestMethod -Method POST -uri $uri -SkipCertificateCheck -Headers $headers -Body "$payload"
    return $response
}

function Select-ByTag($unprotectedvms, $tag) {
    # Returns a list of non-protected VMs with a user input tag
    $taggedvms = New-Object System.Collections.Generic.List[System.Object]
    foreach ($vm in $unprotectedvms){
        $vmtag = Get-TagAssignment $vm
        if ($vmtag.Tag.Name -eq $tag){
            $taggedvms.Add($vm)
        }
    }
    return $taggedvms
}

function Watch-Protection($uri, $headers, $transactionid) {
    # Monitor the protection transaction
    $uri += "/transactions/"+$transactionid
    $timeout = 30
    $interval = 5
    While ($timeout -gt 0 -or $status -ne "COMPLETED"){
        $response = Invoke-RestMethod -Method GET -uri $uri -SkipCertificateCheck -Headers $headers
        $status = $response.status
        Write-Host "The status for transaction $transactionid is $status"
        $timeout -= $interval
        Start-Sleep $interval
    }
    return $status
}

# Enforcing the use of credentials of vCenter username/password
if (!$credentials -and !$vcpassword -and !$vcuser){
    Write-Host "-credentials or -vcuser and -vcpassword must be provided" -ForegroundColor Red
    exit
}

# Constants
$endpoint = "/api/v1"
$uri = "https://{0}{1}" -f $pluginserver, $endpoint
$counter = 0

# Connecting to vCenter using creds or username/password
Write-Host "-> Connecting to vCenter:" -ForegroundColor Yellow
if (!$credentials){
    $credspair = "$($vcuser):$($vcpassword)"
    Connect-VIServer -Server $vc -Port $vcport -User $vcuser -Password $vcpassword
}
else {
    $credspair ="$($credentials.UserName):$($credentials.GetNetworkCredential().Password)"
    Connect-VIServer -Server $vc -Port $vcport -Credential $credentials
}
Write-Host

# Computing encrypted credentials and headers
$enccreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credspair))
$basicauthvalue = "Basic $enccreds"
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization","$basicauthvalue")
$headers.Add("Content-Type", "application/json")

# Setting up VM exclusion parameter
if (!$excludevms){
    $excludevms = "null"
}
else {
    Write-Host "-> Excluding VMs with names containing $excludevms" -ForegroundColor Yellow
}

# Getting a list of non-protected VMs
$unprotectedvms = Get-VMsByCluster $esxcluster $excludevms
if ($unprotectedvms.Length -eq 0){
    Write-Host "No unprotected VMs detected" -ForegroundColor Red
    exit
}

# List all non-protected VMs
if ($list){
    Write-Host "-> List of unprotected VMs:" -ForegroundColor Blue
    $unprotectedvms.name
    exit
}

# Get RP4VMs clusters and match with the user input
$rpvmclusters = Get-RP4VMsClusters $uri $headers
if ($rpvmclusters.Length -eq 0){
    Write-Host "No registered RP4VMs clusters, configure through Deployer or register vCenter through the API" -ForegroundColor Red
    exit
}
elseif ($rpvmclusters.Length -eq 1){
    if ($rpvmcluster){
        if ($rpvmcluster -like $rpvmclusters.name){
           $rpvmcluster = $rpvmclusters.name
           $rpvmsystemid = $rpvmclusters.rpSystemId
        }
        else {
            Write-Host "Provided RP4VMs cluster name could not be found" -ForegroundColor Red
            exit
        }
    }
    else {
        $rpvmcluster = $rpvmclusters.name
        $rpvmsystemid = $rpvmclusters.rpSystemId
    }
}
else {
    if (!rpvmcluster){
    Write-Host "Multiple RP4VMs clusters detected, narrow down the results using -rpvmcluster parameter" -ForegroundColor Red
    exit
    }
    else {
        foreach ($cluster in $rpvmclusters){
            if ($cluster.name -like $rpvmcluster){
                $rpvmcluster = $cluster.name
                $rpvmsystemid = $rpvmclusters.rpSystemId
                $counter++
            }
        }
        if ($counter -gt 1){
            Write-Host "Matched multiple RP4VMs clusters, narrow down the results using -rpvmcluster parameter" -ForegroundColor Red
            exit
        }
        elseif ($counter -is 0){
            Write-Host "Could not match any RP4VMs cluster" -ForegroundColor Red
            exit
        }
    }
}

# Filter list of non-protected VMs based on tag
if ($tag){
    Write-Host "-> Filtering by tag $tag" -ForegroundColor Yellow
    $unprotectedvms = Select-ByTag $unprotectedvms $tag
    if ($unprotectedvms.Length -eq 0){
        Write-Host "Specific Tag could not be found" -ForegroundColor Red
        exit
    }
}

# Get recommended settings for protection and protect VMs
Disconnect-VIServer -Server $vc -Confirm:$false
$payload = Build-Payload $rpvmcluster $unprotectedvms
Write-Host "-> Retrieving recommended protection parameters" -ForegroundColor Yellow
$defaults = Get-ProtectDefaults $uri $headers $payload $rpvmsystemid
Write-Host "-> Protecting VMs:" -ForegroundColor Yellow
Write-Host $unprotectedvms
Write-Host
$transactionid = Protect-VMs $uri $headers $defaults $rpvmsystemid

# Monitor status of protection transaction
if (!$nomonitor){
    Write-Host "-> Monitoring" -ForegroundColor Yellow
    $status = Watch-Protection $uri $headers $transactionid.id
    if ($status -ne "COMPLETED"){
        Write-Host "Reached timeout while monitoring protect transaction" -ForegroundColor Red
        exit
    }
    else {
        Write-Host "Completed successfully" -ForegroundColor Blue
    }
}
else {
    Write-Host "Skipping monitoring, transaction ID is $transactionid" -ForegroundColor Blue
}
