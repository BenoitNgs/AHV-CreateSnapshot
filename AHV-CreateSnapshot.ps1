param(
    [Parameter(Mandatory=$true)][string]$VMTargetAction,
    [Parameter(Mandatory=$true)][string]$PassFile,
    [Parameter(Mandatory=$false)][string]$SnapshotName="$(Get-Date -Format "yyyyMMdd-HHmmss")_RunByAPI"
)


# Param globaux
$Credential=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, (Get-Content $Passfile | ConvertTo-SecureString)
$username=$Credential.UserName
$password=$Credential.GetNetworkCredential().password
$cstAHVListClusters=@("cluster001.teddycorp.lab","cluster002.teddycorp.lab","clusterXXX.teddycorp.lab")

#Log File
#$logPath=$(Get-Location).Path+"\Logs\"
if(!$(Test-Path -path $logPath)){New-Item -Path $logPath -ItemType "directory" | out-null}
$LogFile=$logPath+"AHV-SnapshotVM_$(get-date -Format "yyyyMMddHHmmss").log"


#################### Function ####################
function zGet-AHVAPIv2ListeVMs{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$cluster,
        [Parameter(Mandatory=$true)]$username,
        [Parameter(Mandatory=$true)]$password,
        [Parameter(Mandatory=$false)]$LogFile
    )

    $res = @()
    $lstVM = ""

    $Header = @{
        "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ));
        "Accept-Charset" = "utf-8";
    }

    # Param spe
add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;

            public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if(![string]::IsNullOrEmpty($LogFile)){"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - action - RUN Invoke-RestMethod -Method Get -Uri https://$($cluster):9440/api/nutanix/v2.0/vms/" >> $LogFile}

    try {
        $lstVM = (Invoke-RestMethod -Method Get -Uri "https://$($cluster):9440/api/nutanix/v2.0/vms/" -Headers $Header)
    } catch {
        if(![string]::IsNullOrEmpty($LogFile)){"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - error - Rest APi StatusCode: $($_.Exception.Response.StatusCode.value__)" >> $LogFile}
        if(![string]::IsNullOrEmpty($LogFile)){"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - error - Rest APi StatusCode: $($_.Exception.Response.StatusDescription)" >> $LogFile}
        return $_.Exception.Response.StatusCode.value__
    }
    
    foreach ($VM in $lstVM.entities) {
        if(![string]::IsNullOrEmpty($LogFile)){"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - VM: $($VM.name) on $($cluster)" >> $LogFile}
        $objVM = New-Object System.object
        $objVM | Add-Member -name ‘VMCluster’ -MemberType NoteProperty -Value $cluster
        $objVM | Add-Member -name ‘VMName’ -MemberType NoteProperty -Value $VM.name
        $objVM | Add-Member -name ‘VMuuid’ -MemberType NoteProperty -Value $VM.uuid
        $objVM | Add-Member -name ‘AGENT_VM’ -MemberType NoteProperty -Value $VM.vm_features.AGENT_VM
        $objVM | Add-Member -name ‘VMPowerState’ -MemberType NoteProperty -Value $VM.power_state
        $res+=$objVM
    }

    return $res
}


function zSet-AHVVMAPIv2SnapShotVM{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$cluster,
        [Parameter(Mandatory=$true)][string]$VMUiid,
        [Parameter(Mandatory=$true)]$username,
        [Parameter(Mandatory=$true)]$password,
        [Parameter(Mandatory=$true)][string]$SnapShotName,
        [Parameter(Mandatory=$false)]$LogFile
    )
    $res=$false

    $Header = @{
        "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ));
        "Accept-Charset" = "utf-8";
    }

    # Param spe
add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;

            public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@

    $Body = '{"snapshot_specs":[{"snapshot_name":"'+$SnapShotName+'","vm_uuid":"'+$VMUiid+'"}]}'
    $URI="https://$($cluster):9440/api/nutanix/v2.0/snapshots/"

    try {
        if(![string]::IsNullOrEmpty($LogFile)){"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - action - Invoke-RestMethod -Method POST -Uri $URI -Headers $Header -Body $Body -ContentType application/json)" >> $LogFile}
        $PostReturn = (Invoke-RestMethod -Method POST -Uri $URI -Headers $Header -Body $Body -ContentType 'application/json')
        $objRes = New-Object System.object
        $objRes | Add-Member -name ‘task_uuid’ -MemberType NoteProperty -Value $PostReturn.task_uuid
        $objRes | Add-Member -name ‘VMCluster’ -MemberType NoteProperty -Value $cluster
        $objRes | Add-Member -name ‘VMUiid’ -MemberType NoteProperty -Value $VMUiid
        $objRes | Add-Member -name ‘SnapShotName’ -MemberType NoteProperty -Value $SnapShotName
        $objRes | Add-Member -name ‘URLApi’ -MemberType NoteProperty -Value $URI
        $res=$objRes
    } catch {
        if(![string]::IsNullOrEmpty($LogFile)){"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - error - Rest APi StatusCode: $($_.Exception.Response.StatusCode.value__)" >> $LogFile}
        if(![string]::IsNullOrEmpty($LogFile)){"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - error - Rest APi StatusCode: $($_.Exception.Response.StatusDescription)" >> $LogFile}
        return $_.Exception.Response.StatusDescription
    }

    return $res
}


function zGet-AHVAPIv2VMInfos{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$cluster,
        [Parameter(Mandatory=$true)][string]$VMUiid,
        [Parameter(Mandatory=$true)]$username,
        [Parameter(Mandatory=$true)]$password
    )

    $res=$false

    $Header = @{
        "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ));
        "Accept-Charset" = "utf-8";
    }

    # Param spe
add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;

            public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


    try {
        $VM = (Invoke-RestMethod -Method Get -Uri "https://$($cluster):9440/api/nutanix/v2.0/vms/$VMUiid/" -Headers $Header)
    } catch {
        Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
        Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
        return $false
    }

    $objVM = New-Object System.object
    $objVM | Add-Member -name ‘VMCluster’ -MemberType NoteProperty -Value $cluster
    $objVM | Add-Member -name ‘VMName’ -MemberType NoteProperty -Value $VM.name
    $objVM | Add-Member -name ‘VMuuid’ -MemberType NoteProperty -Value $VM.uuid
    $objVM | Add-Member -name ‘AGENT_VM’ -MemberType NoteProperty -Value $VM.vm_features.AGENT_VM
    $objVM | Add-Member -name ‘VMPowerState’ -MemberType NoteProperty -Value $VM.power_state
    $objVM | Add-Member -name ‘allow_live_migrate’ -MemberType NoteProperty -Value $vm.allow_live_migrate
    $objVM | Add-Member -name ‘gpus_assigned’ -MemberType NoteProperty -Value $vm.gpus_assigned
    $objVM | Add-Member -name ‘description’ -MemberType NoteProperty -Value $vm.description
    $objVM | Add-Member -name ‘ha_priority’ -MemberType NoteProperty -Value $vm.ha_priority
    $objVM | Add-Member -name ‘host_uuid’ -MemberType NoteProperty -Value $vm.host_uuid
    $objVM | Add-Member -name ‘memory_mb’ -MemberType NoteProperty -Value $vm.memory_mb
    $objVM | Add-Member -name ‘num_cores_per_vcpu’ -MemberType NoteProperty -Value $vm.num_cores_per_vcpu
    $objVM | Add-Member -name ‘num_vcpus’ -MemberType NoteProperty -Value $vm.num_vcpus
    $objVM | Add-Member -name ‘timezone’ -MemberType NoteProperty -Value $vm.timezone
    $objVM | Add-Member -name ‘VGA_CONSOLE’ -MemberType NoteProperty -Value $vm.vm_features.VGA_CONSOLE

    $res=$objVM

    return $res
}



#################### Main ####################
"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - Start process" >> $LogFile


$lstVM = @()
foreach($Cluster in $cstAHVListClusters){

    "$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - Start list VM in cluster $Cluster" >> $LogFile
    $lstVM += zGet-AHVAPIv2ListeVMs -cluster $Cluster -username $username -password $password -LogFile $LogFile
    "$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - End list VM in cluster $Cluster" >> $LogFile

}


$objVM = ""
$objVM = $lstVM | Where-Object {$_.VMName -eq $VMTargetAction}
"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - find VM: $VMTargetAction" >> $LogFile
"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - VM: $($objVM.VMuuid)" >> $LogFile


if([string]::IsNullOrEmpty($objVM)){
    "$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - error - VM: $VMTargetAction not found" >> $LogFile
    return $false
}else{
    "$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - action - Create snapshot run ask: $($objVM.VMuuid)" >> $LogFile
    $AHVTsPowergmt=zSet-AHVVMAPIv2SnapShotVM -cluster $objVM.VMCluster -username $username -password $password -VMUiid $objVM.VMuuid -SnapShotName $SnapshotName -LogFile $LogFile
    "$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - Task info task_uuid: $($AHVTsPowergmt.task_uuid)" >> $LogFile
    "$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - Task info VMCluster: $($AHVTsPowergmt.VMCluster)" >> $LogFile
    "$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - Task info VMUiid: $($AHVTsPowergmt.VMUiid)" >> $LogFile
    "$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - Task info SnapShotName: $($AHVTsPowergmt.SnapShotName)" >> $LogFile
    "$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - Task info URLApi: $($AHVTsPowergmt.URLApi)" >> $LogFile

    if([string]::IsNullOrEmpty($AHVTsPowergmt.task_uuid)){return $false}
}

"$(Get-Date -Format "yyyy/MM/dd-HH:mm:ss") - info - End process" >> $LogFile
return $true
