# Author: Romain Decker
# Website: cloudmaniac.net
# Description: PowerCLI script to deploy a functional vSphere 6.5 lab consisting of 3
#               Nested ESXi hosts enable w/vSAN + VCSA 6.5. Expects a single physical ESXi host
#               as the endpoint and all four VMs will be deployed to physical ESXi host
# Reference: 
# Credit: Thanks to William Lam as I borrowed a lot of his script, and to Timo Sugliani for the debug

# General variables
$verboseLogFile = "Logs/vsphere65-cloudmaniac-lab-deployment.log"
$vSphereVersion = "6.5"

# Answerfile import
$ConfigFile = ".\lab01-answerfile.json"
$NestedLabConfig = (Get-Content $($ConfigFile) -Raw) | ConvertFrom-Json

# Path to the Nested ESXi 6.5 VA + extracted VCSA 6.5 ISO
$VCSAInstallerPath  = "$($NestedLabConfig.sources.extractedvcsadir)"
$NestedESXiApplianceOVA  = "$($NestedLabConfig.sources.nestedesxiova)"

#### DO NOT EDIT BEYOND HERE ####

# Triggers to execute specific pieces of the script (for debug or re-configuration purpose)
$preCheck = 1
$confirmDeployment = 1
$deployNestedESXi = 1
$deployVCSA = 1
$setupDataCenter = 1
$configureVSANDiskGroups = 0
$clearVSANHealthCheckAlarm = 0
$moveVMsIntovApp = 1

$StartTime = Get-Date

Function My-Logger {
    param(
    [Parameter(Mandatory=$true)]
    [String]$message
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_hh:mm:ss"

    Write-Host -NoNewline -ForegroundColor White "[$timestamp] "
    if($message -eq "drawline") {
        for($i=0; $i -lt ((get-host).ui.rawui.buffersize.width -22); $i++) {write-host -nonewline -foregroundcolor Green "-"}
    } else {
        Write-Host -ForegroundColor Green "$message"
    }
    $logMessage = "[$timeStamp] $message"
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
}

if($preCheck -eq 1) {
    if(!(Test-Path $NestedESXiApplianceOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $NestedESXiApplianceOVA ...`nexiting"
        exit
    }

    if(!(Test-Path $VCSAInstallerPath)) {
        Write-Host -ForegroundColor Red "`nUnable to find $VCSAInstallerPath ...`nexiting"
        exit
    }

}

if($confirmDeployment -eq 1) {
    Write-Host -ForegroundColor Magenta "`nPlease confirm the following configuration will be deployed:`n"

    Write-Host -ForegroundColor Yellow "---- vSphere 6.5 Automated Lab Deployment Configuration ---- "

    Write-Host -NoNewline -ForegroundColor Green "vSphere Version: "
    Write-Host -ForegroundColor White  "vSphere $vSphereVersion"
    Write-Host -NoNewline -ForegroundColor Green "Nested ESXi Image Path: "
    Write-Host -ForegroundColor White $NestedESXiApplianceOVA
    Write-Host -NoNewline -ForegroundColor Green "VCSA Image Path: "
    Write-Host -ForegroundColor White $VCSAInstallerPath

    Write-Host -ForegroundColor Yellow "`n---- vCenter Server Deployment Target Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "Deployment Target: "
    Write-Host -ForegroundColor White $NestedLabConfig.target.server
    Write-Host -NoNewline -ForegroundColor Green "Username: "
    Write-Host -ForegroundColor White $NestedLabConfig.target.username

    Write-Host -NoNewline -ForegroundColor Green "Cluster: "
    Write-Host -ForegroundColor White $NestedLabConfig.target.deploycluster
    Write-Host -NoNewline -ForegroundColor Green "vApp: "
    Write-Host -ForegroundColor White $NestedLabConfig.general.vapp

    Write-Host -ForegroundColor Yellow "`n---- vESXi Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "# of Nested ESXi VMs: "
    Write-Host -ForegroundColor White $NestedLabConfig.esxi.hosts.Count
    Write-Host -NoNewline -ForegroundColor Green "Netmask "
    Write-Host -ForegroundColor White $NestedLabConfig.general.network.netmask
    Write-Host -NoNewline -ForegroundColor Green "Gateway: "
    Write-Host -ForegroundColor White $NestedLabConfig.general.network.gateway
    Write-Host -NoNewline -ForegroundColor Green "DNS: "
    Write-Host -ForegroundColor White $NestedLabConfig.general.network.dns
    Write-Host -NoNewline -ForegroundColor Green "NTP: "
    Write-Host -ForegroundColor White $NestedLabConfig.general.ntp
    Write-Host -NoNewline -ForegroundColor Green "Syslog: "
    Write-Host -ForegroundColor White $NestedLabConfig.general.syslog
    Write-Host -NoNewline -ForegroundColor Green "Root Password: "
    Write-Host -ForegroundColor White $NestedLabConfig.general.password

    Write-Host -ForegroundColor Yellow "`n---- VCSA Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "Deployment Size: "
    Write-Host -ForegroundColor White $NestedLabConfig.vcsa.deploymentsize
    Write-Host -NoNewline -ForegroundColor Green "SSO Domain: "
    Write-Host -ForegroundColor White $NestedLabConfig.vcsa.sso.domain
    Write-Host -NoNewline -ForegroundColor Green "SSO Site: "
    Write-Host -ForegroundColor White $NestedLabConfig.vcsa.sso.site
    Write-Host -NoNewline -ForegroundColor Green "SSO Password: "
    Write-Host -ForegroundColor White $NestedLabConfig.vcsa.sso.password
    Write-Host -NoNewline -ForegroundColor Green "Root Password: "
    Write-Host -ForegroundColor White $NestedLabConfig.vcsa.rootpassword
    Write-Host -NoNewline -ForegroundColor Green "Hostname: "
    Write-Host -ForegroundColor White $NestedLabConfig.vcsa.hostname
    Write-Host -NoNewline -ForegroundColor Green "IP Address: "
    Write-Host -ForegroundColor White $NestedLabConfig.vcsa.ip
    Write-Host -NoNewline -ForegroundColor Green "Netmask "
    Write-Host -ForegroundColor White $NestedLabConfig.general.network.netmask
    Write-Host -NoNewline -ForegroundColor Green "Gateway: "
    Write-Host -ForegroundColor White $NestedLabConfig.general.network.gateway

    Write-Host -ForegroundColor Magenta "`nWould you like to proceed with this deployment?`n"
    $answer = Read-Host -Prompt "Do you accept (Y or N)"
    if($answer -ne "Y" -or $answer -ne "y") {
        exit
    }
    Clear-Host
}

My-Logger "Connecting to $($NestedLabConfig.target.server) ..."
$viConnection = Connect-VIServer $NestedLabConfig.target.server -User $NestedLabConfig.target.username -Password $NestedLabConfig.target.password -WarningAction SilentlyContinue

if($NestedLabConfig.deploytriggers.deploytype -eq "esxi") {
    $esxideploydatastore = Get-Datastore -Server $viConnection -Name $NestedLabConfig.esxi.deploydatastore
    if($NestedLabConfig.deploytriggers.switchtype -eq "vss") {
        $network = Get-VirtualPortGroup -Server $viConnection -Name $NestedLabConfig.esxi.deployportgroup

    } else {
        $network = Get-VDPortgroup -Server $viConnection -Name $NestedLabConfig.esxi.deployportgroup
    }
    $vmhost = Get-VMHost -Server $viConnection

    if($esxideploydatastore.Type -eq "vsan") { # TODO/// adapt following
        My-Logger "VSAN Datastore detected, enabling Fake SCSI Reservations ..."
        Get-AdvancedSetting -Entity $vmhost -Name "VSAN.FakeSCSIReservations" | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
    }
} else {
    $esxideploydatastore = Get-Datastore -Server $viConnection -Name $NestedLabConfig.esxi.deploydatastore | Select-Object -First 1
    if($NestedLabConfig.deploytriggers.switchtype -eq "vss") {
        $network = Get-VirtualPortGroup -Server $viConnection -Name $NestedLabConfig.esxi.deployportgroup | Select-Object -First 1
    } else {
        $network = Get-VDPortgroup -Server $viConnection -Name $NestedLabConfig.esxi.deployportgroup | Select-Object -First 1
    }
    $cluster = Get-Cluster -Server $viConnection -Name $NestedLabConfig.target.deploycluster
    $datacenter = $cluster | Get-Datacenter
    $vmhost = $cluster | Get-VMHost | Select-Object -First 1

    if($esxideploydatastore.Type -eq "vsan") { # TODO/// adapt following
        My-Logger "VSAN Datastore detected, enabling Fake SCSI Reservations ..."
        Get-AdvancedSetting -Entity $vmhost -Name "VSAN.FakeSCSIReservations" | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
    }
}

if($deployNestedESXi -eq 1) {
    $NestedLabConfig.esxi.hosts | ForEach-Object {
        $NestedName = $_.name
        
        # Test if the nested is not already deployed
        if(-Not(Get-VM $NestedName -ErrorAction SilentlyContinue)) {
       
            $ESXiName = $_.name
            $ESXiIPAddress = $_.vmkmgtip
            $ESXiVlan = $_.vmkmgtvlan

            $ovfconfig = Get-OvfConfiguration $NestedLabConfig.sources.nestedesxiova
            $ovfconfig.NetworkMapping.VM_Network.value = $NestedLabConfig.esxi.deployportgroup

            $ovfconfig.common.guestinfo.hostname.value = $ESXiName
            $ovfconfig.common.guestinfo.ipaddress.value = $ESXiIPAddress
            $ovfconfig.common.guestinfo.vlan.value = $ESXiVlan
            $ovfconfig.common.guestinfo.netmask.value = $NestedLabConfig.general.network.netmask
            $ovfconfig.common.guestinfo.gateway.value = $NestedLabConfig.general.network.gateway
            $ovfconfig.common.guestinfo.dns.value = $NestedLabConfig.general.network.dns
            $ovfconfig.common.guestinfo.domain.value = $NestedLabConfig.general.network.domain
            $ovfconfig.common.guestinfo.ntp.value = $NestedLabConfig.general.ntp
            $ovfconfig.common.guestinfo.syslog.value = $NestedLabConfig.general.syslog
            $ovfconfig.common.guestinfo.password.value = $NestedLabConfig.general.password
            $ovfconfig.common.guestinfo.ssh.value = $NestedLabConfig.general.activatessh

            My-Logger "Deploying Nested ESXi VM $ESXiName ..."
            $vm = Import-VApp -Source $NestedLabConfig.sources.nestedesxiova -OvfConfiguration $ovfconfig -Name $ESXiName -Location $cluster -VMHost $vmhost -Datastore $esxideploydatastore -DiskStorageFormat thin

            My-Logger "Updating vCPU count to $($_.cpu) & vMEM to $($_.memory) GB ..."
            Set-VM -Server $viConnection -VM $vm -NumCpu $_.cpu -MemoryGB $_.memory -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

            # Check if we need additional disks for vsan for this particular host
            if($_.cachedisk -ne "none") {
                My-Logger "Updating vSAN caching VMDK size to $($_.cachedisk) GB ..."
                Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $_.cachedisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            } else {
                # Remove Hard disk 2 as we don't need it
                $hdd = Get-HardDisk -VM $vm -Name "Hard disk 2"
                Remove-HardDisk -HardDisk $hdd -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            }

            if($_.capacitydisk -ne "none") {
                My-Logger "Updating vSAN capacity VMDK size to $($_.capacitydisk) GB ..."
                Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $_.capacitydisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            } else {
                # Remove Hard disk 3 as we don't need it. Note that the parameter is still 'Hard disk 2' as we removed already one disk
                $hdd = Get-HardDisk -VM $vm -Name "Hard disk 2"
                Remove-HardDisk -HardDisk $hdd -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            }

            My-Logger "Powering On $ESXiName ..."
            $vm | Start-Vm -RunAsync | Out-Null
         }
    }
}

if($deployVCSA -eq 1) {
    # Test if the nested is not already deployed
    if(-Not(Get-VM $NestedLabConfig.vcsa.name -ErrorAction SilentlyContinue)) {
        $config = (Get-Content -Raw "$($VCSAInstallerPath)\vcsa-cli-installer\templates\install\embedded_vCSA_on_VC.json") | convertfrom-json
        $config.'new.vcsa'.vc.hostname = $NestedLabConfig.target.server
        $config.'new.vcsa'.vc.username = $NestedLabConfig.target.username
        $config.'new.vcsa'.vc.password = $NestedLabConfig.target.password
        $config.'new.vcsa'.vc.'deployment.network' = $NestedLabConfig.vcsa.deployportgroup
        $config.'new.vcsa'.vc.datastore = $NestedLabConfig.vcsa.deploydatastore
        $config.'new.vcsa'.vc.datacenter = $datacenter.name
        $config.'new.vcsa'.vc.target = $NestedLabConfig.target.deploycluster
        $config.'new.vcsa'.appliance.'thin.disk.mode' = $true
        $config.'new.vcsa'.appliance.'deployment.option' = $NestedLabConfig.vcsa.deploymentsize
        $config.'new.vcsa'.appliance.name = $NestedLabConfig.vcsa.name
        $config.'new.vcsa'.network.'ip.family' = "ipv4"
        $config.'new.vcsa'.network.mode = "static"
        $config.'new.vcsa'.network.ip = $NestedLabConfig.vcsa.ip
        $config.'new.vcsa'.network.'dns.servers'[0] = $NestedLabConfig.general.network.dns
        $config.'new.vcsa'.network.prefix = $NestedLabConfig.general.network.prefix
        $config.'new.vcsa'.network.gateway = $NestedLabConfig.general.network.gateway
        $config.'new.vcsa'.network.'system.name' = $NestedLabConfig.vcsa.hostname
        $config.'new.vcsa'.os.password = $NestedLabConfig.vcsa.rootpassword
        $config.'new.vcsa'.os.'ssh.enable' = $NestedLabConfig.general.activatessh
        $config.'new.vcsa'.sso.password = $NestedLabConfig.vcsa.sso.password
        $config.'new.vcsa'.sso.'domain-name' = $NestedLabConfig.vcsa.sso.domain
        $config.'new.vcsa'.sso.'site-name' = $NestedLabConfig.vcsa.sso.site

        My-Logger "Creating VCSA JSON configuration file for deployment ..."
        $config | ConvertTo-Json | Set-Content -Path "$($ENV:Temp)\jsontemplate.json"

        My-Logger "Deploying the VCSA ..."
        Invoke-Expression "$($VCSAInstallerPath)\vcsa-cli-installer\win32\vcsa-deploy.exe install --no-esx-ssl-verify --accept-eula --terse --acknowledge-ceip $($ENV:Temp)\jsontemplate.json"| Out-File -Append -LiteralPath $verboseLogFile
    }
}

if($moveVMsIntovApp -eq 1) {
    # Test if vApp already exists before creating it
    if(-Not(Get-VApp $NestedLabConfig.general.vapp -ErrorAction SilentlyContinue)) {
        My-Logger "Creating vApp $($NestedLabConfig.general.vapp) ..."
        New-VApp -Name $NestedLabConfig.general.vapp -Server $viConnection -Location $cluster | Out-File -Append -LiteralPath $verboseLogFile       
    }

    $NestedLabConfig.esxi.hosts | ForEach-Object {
        $NestedName = $_.name
        # Test if nested ESXi not already in the vApp
        if(-Not(Get-VM $NestedName -Location $NestedLabConfig.general.vapp -ErrorAction SilentlyContinue)) {
            My-Logger "Moving $($NestedName) into $($NestedLabConfig.general.vapp) vApp ..."
            $vm = Get-VM -Name $NestedName -Server $viConnection
            Move-VM -VM $vm -Server $viConnection -Destination $NestedLabConfig.general.vapp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }
    }

    # Test if vCSA not already in the vApp
    if(-Not(Get-VM $NestedLabConfig.vcsa.name -Location $NestedLabConfig.general.vapp -ErrorAction SilentlyContinue)) {
        My-Logger "Moving $($NestedLabConfig.vcsa.name) into $($NestedLabConfig.general.vapp) vApp ..."
        Move-VM -VM $NestedLabConfig.vcsa.name -Server $viConnection -Destination $NestedLabConfig.general.vapp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
    }
}

My-Logger "Disconnecting from $($NestedLabConfig.target.server) ..."
Disconnect-VIServer $viConnection -Confirm:$false

My-Logger "Connecting to the new VCSA $($NestedLabConfig.vcsa.hostname) ..."
$vc = Connect-VIServer $NestedLabConfig.vcsa.hostname -User "administrator@$($NestedLabConfig.vcsa.sso.domain)" -Password $NestedLabConfig.vcsa.sso.password -WarningAction SilentlyContinue

if($setupDataCenter -eq 1) {
    # Datacenter creation
    if(-Not(Get-Datacenter $NestedLabConfig.mysddc.datacentername -ErrorAction SilentlyContinue)) {
        My-Logger "Creating Datacenter $($NestedLabConfig.mysddc.datacentername) ..."
        New-Datacenter -Server $vc -Name $NestedLabConfig.mysddc.datacentername -Location (Get-Folder -Type Datacenter -Server $vc) | Out-File -Append -LiteralPath $verboseLogFile
    }

    # Network configuration
    $NestedLabConfig.mysddc.distributedswitches | ForEach-Object {
        # Distributed switches creation
        $VDSToCreate = $_.name
        if(-Not(Get-VDSwitch $VDSToCreate -ErrorAction SilentlyContinue)) {
            My-Logger "Creating Distributed Switch $VDSToCreate ..."
            New-VDSwitch -Name $VDSToCreate -Location $NestedLabConfig.mysddc.datacentername -LinkDiscoveryProtocol "CDP" -LinkDiscoveryProtocolOperation "Both" -MTU 9000 -NumUplinkPorts 1 | Out-File -Append -LiteralPath $verboseLogFile
        }

        # Distributed portgroups creation
        if($_.portgroups -ne "none") {
            $_.portgroups | ForEach-Object {
                $DPGNameToCreate = $_.name
                $DPGVlanToCreate = $_.vlan

                if(-Not(Get-VDPortgroup $DPGNameToCreate -ErrorAction SilentlyContinue)) {
                    My-Logger "Create $($DPGNameToCreate) distributed port group ..."
                    New-VDPortgroup -VDSwitch $VDSToCreate -Name $DPGNameToCreate -VlanId $DPGVlanToCreate | Out-File -Append -LiteralPath $verboseLogFile
                }
            }
        }
    }

    # Loop to configure sddc based on the esxi.hosts array in the anwserfile
    $NestedLabConfig.esxi.hosts | ForEach-Object {
        # First check to see if cluster exists already; if not, cluster is created
        $ClusterToCreate = $_.cluster
        if(-Not(Get-Cluster $ClusterToCreate -ErrorAction SilentlyContinue)) {
            My-Logger "Creating Cluster $($ClusterToCreate) ..."
            New-Cluster -Server $vc -Name $ClusterToCreate -Location (Get-Datacenter -Name $NestedLabConfig.mysddc.datacentername -Server $vc) -DrsEnabled | Out-File -Append -LiteralPath $verboseLogFile       
        }

        # Parameters definition
        $NestedName = $_.name
        $NestedFQDN = "$($_.name).$($NestedLabConfig.general.network.domain)"
        $NFSVMkernelIP = $_.vmknfsip
        $NestedCluster = $_.cluster
        $NestedVDS = $_.distributedswitch
        $PgNFSVLAN = $_.vmknfsvlan

        My-Logger "drawline"
        My-Logger "> Working on ESXi host $($NestedName):"
        My-Logger "drawline"

        # Add host to respective clusters
        My-Logger ">> Adding host to $NestedCluster ..."
        Add-VMHost -Server $vc -Location (Get-Cluster -Name $NestedCluster) -User "root" -Password $NestedLabConfig.general.password -Name $NestedFQDN -Force | Out-File -Append -LiteralPath $verboseLogFile

        # Configure DNS
        My-Logger ">> Configure DNS ..."
        Get-VMHostNetwork -VMHost $NestedFQDN | Set-VMHostNetwork -DomainName $NestedLabConfig.general.network.domain -DNSAddress $NestedLabConfig.general.network.dns -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        # Start NTP
        My-Logger ">> Starting NTP service ..."
        Get-VMHost $NestedFQDN | Get-VMHostFirewallException | Where-Object {$_.Name -eq "NTP client"} | Set-VMHostFirewallException -Enabled:$true | Out-File -Append -LiteralPath $verboseLogFile
        Get-VMHost $NestedFQDN | Get-VMHostService | Where-Object {$_.key -eq "ntpd"} | Start-VMHostService | Out-File -Append -LiteralPath $verboseLogFile
        Get-VMhost $NestedFQDN | Get-VMHostService | Where-Object {$_.key -eq "ntpd"} | Set-VMHostService -policy "automatic" | Out-File -Append -LiteralPath $verboseLogFile

        # Remove VM Network portgroup on vSwitch0 because I'm picky > TODO/// check if still needed
        My-Logger ">> Cleaning default 'VM Network' port group on vSwitch0 ..."
        Get-VirtualSwitch -Name $NestedLabConfig.mysddc.defaultvswitch | Get-VirtualPortGroup -Name $NestedLabConfig.mysddc.legacyvmportgroup | Remove-VirtualPortGroup -Confirm:$False | Out-File -Append -LiteralPath $verboseLogFile

        # Add host to respective distributed switches
        My-Logger ">> Adding host to $($NestedVDS) VDS ..."
        Add-VDSwitchVMHost -VDSwitch $NestedVDS -VMHost $NestedFQDN | Out-File -Append -LiteralPath $verboseLogFile

        # Connect vmnic1 from each host to the VDS
        My-Logger ">> Connect vmnic1 on $($NestedVDS) VDS ..."
        $vmhostNetworkAdapter = Get-VMHost $NestedFQDN | Get-VMHostNetworkAdapter -Physical -Name vmnic1
        Get-VDSwitch $NestedVDS | Add-VDSwitchPhysicalNetworkAdapter -VMHostPhysicalNic $vmhostNetworkAdapter -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
                    
        # Create NFS VMkernel
        My-Logger ">> Create NFS VMkernel ..."
        New-VMHostNetworkAdapter -VMHost $NestedFQDN -PortGroup $NestedLabConfig.mysddc.nfsvmkname -VirtualSwitch $NestedLabConfig.mysddc.defaultvswitch -IP $NFSVMkernelIP -SubnetMask $NestedLabConfig.general.network.netmask -Mtu 9000 | Out-File -Append -LiteralPath $verboseLogFile
        Get-VirtualPortGroup -VMHost $NestedFQDN -VirtualSwitch $NestedLabConfig.mysddc.defaultvswitch -Name $NestedLabConfig.mysddc.nfsvmkname | Set-VirtualPortGroup -VLanId $PgNFSVLAN | Out-File -Append -LiteralPath $verboseLogFile

        # Connect NFS datastore, regardless of a possible vSAN configuration
        My-Logger ">> Connect $($NestedLabConfig.mysddc.nfsdatastorename) datastore ..."
        Get-VMHost $NestedFQDN | New-Datastore -NFS -Name $NestedLabConfig.mysddc.nfsdatastorename -Path $NestedLabConfig.mysddc.nfsdatastorepath -nfshost $NestedLabConfig.mysddc.nfsdatastorehost | Out-File -Append -LiteralPath $verboseLogFile

    }

}

if($configureVSANDiskGroups -eq 1) {
    $NestedLabConfig.clusters | ForEach-Object {
        if($_.usevsan -eq "true") {
            $ClusterWithvSAN = $_.name
            My-Logger "Enabling VSAN on $($ClusterWithvSAN) ..."
            # Tag 'Hard Disk 3' as capacityFlash before starting ??? TODO MAYBE
            Set-Cluster -Server $vc -Cluster $ClusterWithvSAN -VsanEnabled:$true -VsanDiskClaimMode 'Manual' -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

            My-Logger "Enabling VSAN Space Efficiency/De-Dupe & disabling VSAN Health Check ..."
            Get-VsanClusterConfiguration -Server $vc -Cluster $ClusterWithvSAN | Set-VsanClusterConfiguration -SpaceEfficiencyEnabled $true -HealthCheckIntervalMinutes 0 | Out-File -Append -LiteralPath $verboseLogFile

            $NestedLabConfig.esxi.hosts | Where-Object {$_.cluster -eq $ClusterWithvSAN } | ForEach-Object {
                $NestedFQDN = "$($_.name).$($NestedLabConfig.general.network.domain)"
                $NestedESXiCachingvDisk = $_.cachedisk
                $NestedESXiCapacityvDisk = $_.capacitydisk
                $vmhost = Get-Cluster -Name $ClusterWithvSAN -Server $vc | Get-VMHost -Name $NestedFQDN
                $luns = $vmhost | Get-ScsiLun | Select-Object CanonicalName, CapacityGB

                My-Logger "Querying ESXi host disks to create VSAN Diskgroups ..."
                foreach ($lun in $luns) {
                    if(([int]($lun.CapacityGB)).toString() -eq "$NestedESXiCachingvDisk") {
                        $vsanCacheDisk = $lun.CanonicalName
                        }
                    if(([int]($lun.CapacityGB)).toString() -eq "$NestedESXiCapacityvDisk") {
                        $vsanCapacityDisk = $lun.CanonicalName
                        }
                    }
                
                $vmhost
                $vsanCacheDisk
                $vsanCapacityDisk
                
                My-Logger "Creating VSAN DiskGroup for $vmhost ..."
                New-VsanDiskGroup -VMHost $vmhost -SsdCanonicalName $vsanCacheDisk -DataDiskCanonicalName $vsanCapacityDisk | Out-File -Append -LiteralPath $verboseLogFile
            }
        }
    }
}

if($clearVSANHealthCheckAlarm -eq 1) {
    My-Logger "Clearing default VSAN Health Check Alarms, not applicable in Nested ESXi env ..."
    $alarmMgr = Get-View AlarmManager -Server $vc
    Get-Cluster -Server $vc | Where-Object {$_.ExtensionData.TriggeredAlarmState} | Foreach-Object{
        $cluster = $_
        $Cluster.ExtensionData.TriggeredAlarmState | ForEach-Object{
            $alarmMgr.AcknowledgeAlarm($_.Alarm,$cluster.ExtensionData.MoRef)
        }
    }
}

My-Logger "Disconnecting from new VCSA ..."
Disconnect-VIServer $vc -Confirm:$false

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes,2)

My-Logger "vSphere $vSphereVersion Lab Deployment Complete!"
My-Logger "StartTime: $StartTime"
My-Logger "  EndTime: $EndTime"
My-Logger " Duration: $duration minutes"
