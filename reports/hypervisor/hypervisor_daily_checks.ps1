<#
.DESCRIPTION
  This is a report to check the health of hypervisors (vmware and rhv).
.PARAMETER <Parameter_Name>
  None yet
.INPUTS
  Requires Windows Vault entry for "hypervisor-query"
.OUTPUTS
  Log file stored in "C:\temp\hypervisor_daily_checks$(Get-Date –f yyyy-MM-dd-HHmm).log"
  Email will be sent to list of addresses in $msgto array.
.NOTES
  Version:        1.0
  Author:         Joshua Perry
  Creation Date:  16/11/2022
  Purpose/Change: This is an evolution of a previous script (vmware_daily_checks.ps1) to include multiple hypervisors.
  
.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>

#----------------------------------------------------------[Logging Start]---------------------------------------------------------

# Begin Log

    Start-Transcript -Path "C:\temp\hypervisor_daily_checks$(Get-Date -f yyyy-MM-dd-HHmm).log"

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

# Import Settings

    $settingsfile = "c:\temp\test.txt"
    $settings = Get-Content $settingsfile | Out-String | ConvertFrom-StringData

    # Example File Structre: See example_hypervisor_daily_checks_settings.txt file.


# Set Error Action to Silently Continue
    
    $ErrorActionPreference = "SilentlyContinue"

# Import PowerCLI Powershell Modules

    Get-Module -Name VMware* -ListAvailable | Import-Module
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
    Set-PowerCLIConfiguration -ParticipateInCeip $false -Confirm:$false
    Set-PowerCLIConfiguration -DefaultVIServerMode multiple -Confirm:$false

# Enforce TLS Version

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# SSL Error Handling & Bypass

    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
    $certCallback = @"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class ServerCertificateValidationCallback
        {
            public static void Ignore()
            {
                if(ServicePointManager.ServerCertificateValidationCallback ==null)
                {
                    ServicePointManager.ServerCertificateValidationCallback += 
                        delegate
                        (
                            Object obj, 
                            X509Certificate certificate, 
                            X509Chain chain, 
                            SslPolicyErrors errors
                        )
                        {
                            return true;
                        };
                }
            }
        }
"@ # I can't tab this line in, it is driving me crazy!!!  It is a limitation of 'here-strings'.
        Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()

# Initialise Arrays

    $datacenters = @()
    $clusters = @()
    $hosts = @()
    $vms = @()
    $results = @()
    $hvconns = @()
    $unhstorage = @()
    $incompathw = @()
    $nicpwronresult = @()
    $vmguesttools = @()
    $datastorewarn = @()
    $datastorecrit = @()
    $datastoreothr = @()
    $datastorewarns = @()
    $datastorecrits = @()
    $datastoreothrs = @()
    $mntcds = @()
    $snaps = @()

# Create HTML Header

    $Header = @("
    <style>
    TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
    TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #21c465;}
    TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
    </style>
    ")

#----------------------------------------------------------[Declarations]----------------------------------------------------------

    # General
    
        $currentdate = Get-Date –f yyyyMMddHHmm
    
    # Hypervisors
    
        #$vcenters = @(
        #    "vcsa01.example.com",
        #    "vcsa02.example.com"
        #    )

        #$rhvmgrs = @(
        #    "rhvm01.example.com",
        #    "rhvm02.example.com"
        #    )

        $vcenters = $settings.vcenters | convertfrom-json

        $rhvmgrs = $settings.rhvmgrs | convertfrom-json

    # SMTP Settings
    
        #$msgfrom = "hypervisors@example.com"
        #$msgto = "user@example.com"
        #$smtpServer = “smtp1.example.com”
        $msgsubj = $settings.msgsubj
        $msgfrom = $settings.msgfrom
        $msgto = $settings.msgto | convertfrom-json
        $smtpServer = $settings.smtpsrv
        $smtp = New-Object Net.Mail.SmtpClient($SmtpServer, 25)
        
#-----------------------------------------------------------[Functions]------------------------------------------------------------

# N/A

#-----------------------------------------------------[Connect to Hypervisors]-----------------------------------------------------

# Get Account for Hypervisor Authentication

    [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $vaultresource="hypervisor-query" # Be sure to store hypervisor readonly credentials in password vault with this resource name
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $username = ( $vault.RetrieveAll() | Where-Object { $_.Resource -eq $vaultresource } | Select-Object -First 1 ).UserName
    $password = ( $vault.Retrieve( $vaultresource, $username ) | Select-Object -First 1 ).Password
    $securepass = ConvertTo-SecureString -String $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($username, $securepass)
    Remove-Variable password # So that we don't have the unsecure password lingering in memory

# Connect to Hypervisor

    # VCSAs

        foreach ($vcenter in $vcenters) {
            Connect-VIServer $vcenter -Credential $credential
        }
        foreach ($vcsaconn in $Global:DefaultVIServers) {
                $hvconns += New-Object -TypeName PSObject -Property @{
                    name = $vcsaconn.Name;
                    user = $vcsaconn.User;
                    hypervisor = "vCenter"
                    version = $vcsaconn.version
                }
        }

    # RHV Ovirt-Engine (not required, but closest equivilent and a good test, if this step fails, others are likely to as well)

        foreach ($rhvmgr in $rhvmgrs) {
            $rhvmgrconn = invoke-restmethod -uri "https://$rhvmgr/ovirt-engine/api" -credential $credential
            $rhvmgrusr = invoke-restmethod -uri "https://$rhvmgr$($rhvmgrconn.api.authenticated_user.href)" -credential $credential
            $hvconns += New-Object -TypeName PSObject -Property @{
                name = $rhvmgr;
                user = $rhvmgrusr.user.principal;
                hypervisor = $rhvmgrconn.api.product_info.name
                version = $rhvmgrconn.api.product_info.version.full_version;
            }
        }

    # Build Hypervisor Connection Table

        # Setup HTML Table Section

            $hvconn_html = ”<strong>Hypervisor Connections:</strong>`n <br />”
            $hvconn_html += ”`n <br />”

        # Setup HTML Table & Headings

            $hvconn_html += "<table>`n"
            $hvconn_html += "<th style='font-weight:bold'>Name</th>"
            $hvconn_html += "<th style='font-weight:bold'>User</th>"
            $hvconn_html += "<th style='font-weight:bold'>Hypervisor</th>"
            $hvconn_html += "<th style='font-weight:bold'>Version</th>"

        # Populate Table

            foreach ($hvconn in $hvconns) {
                $hvconn_html += "<tr>`n"
                $hvconn_html += "<td>$($hvconn.Name)</td>`n"
                $hvconn_html += "<td>$($hvconn.User)</td>`n"
                $hvconn_html += "<td>$($hvconn.Hypervisor)</td>`n"
                $hvconn_html += "<td>$($hvconn.Version)</td>`n"
                $hvconn_html += "</tr>`n"
            }
        
        # Close HTML Table
        
            $hvconn_html += "</table>`n"

        # Spacing before next HTML section
        
            $hvconn_html += ”`n <br />”

#---------------------------------------------------------[Storage Checks]---------------------------------------------------------

# Get Hosts with Unhealthy Storage

    # VMware

        $vmhosts = get-vmhost
        foreach ($vmhost in $vmhosts) {
            $luns = get-vmhost $vmhost | Get-ScsiLun -LunType disk | where-object {$_.ExtensionData.OperationalState -ne "ok"}
            foreach ($lun in $luns) {
                $unhstorage += New-Object -TypeName PSObject -Property @{
                    host = $vmhost.name;
                    vendor = $lun.vendor;
                    state = $lun.extensiondata.operationalstate;
                    name = $lun.canonicalname;
                    capacitygb = $lun.capacitygb;
                    hypervisor = ([System.Uri]$vmhost.ExtensionData.Client.ServiceUrl).Host;
                }
            }
        }

    # RHV Ovirt-Engine

        # Commented out until i can find a way to determine if a RHV Storage Device is in an unhealthy state.
        # Can possibly use the $rhvstorage.logical_units.logical_unit.status variable -ne "used"
    
        #foreach ($rhvmgr in $rhvmgrs) {
        #    $rhvhosts = invoke-restmethod -uri "https://$rhvmgr/ovirt-engine/api/hosts" -credential $credential
        #    foreach ($rhvhost in $rhvhosts.hosts.host) {
        #        $rhvhostid = $rhvhost.id
        #        $rhvhoststorage = invoke-restmethod -uri "https://$rhvmgr/ovirt-engine/api/hosts/$rhvhostid/storage" -credential $credential
        #        foreach ($rhvstorage in $rhvhoststorage.host_storages.host_storage) {
        #            $storage_domain_id = $rhvstorage.logical_units.logical_unit.storage_domain_id
        #            $storage_domain = invoke-restmethod -uri "https://$rhvmgr/ovirt-engine/api/storagedomains/$storage_domain_id" -credential $credential
        #            $unhstorage += New-Object -TypeName PSObject -Property @{
        #                host = $rhvhost.name;
        #                vendor = $rhvstorage.logical_units.logical_unit.vendor_id;
        #                state = "TBD";
        #                name = $storage_domain.storage_domain.name;
        #                capacitygb = (([long]$storage_domain.storage_domain.available + [long]$storage_domain.storage_domain.used)/1GB);
        #                hypervisor = $rhvmgr;
        #            }
        #        }
        #    }
        #}


    # Build Unhealthy Storage Table

        # Setup HTML Table Section

            $unhstorage_html = ”<strong>Hosts with Unhealthy Storage:</strong>`n <br />”
            $unhstorage_html += ”`n <br />”

        # Setup HTML Table & Headings

            $unhstorage_html += "<table>`n"
            $unhstorage_html += "<th style='font-weight:bold'>Host</th>"
            $unhstorage_html += "<th style='font-weight:bold'>Vendor</th>"
            $unhstorage_html += "<th style='font-weight:bold'>State</th>"
            $unhstorage_html += "<th style='font-weight:bold'>Name</th>"
            $unhstorage_html += "<th style='font-weight:bold'>CapacityGB</th>"
            $unhstorage_html += "<th style='font-weight:bold'>Hypervisor Manager</th>"

        # Populate Table
            if ($unhstorage.count -eq 0) {
                    $unhstorage_html += "<tr>`n"
                    $unhstorage_html += "<td colspan='6'>No Storage Health Issues Found</td> `n"
                    $unhstorage_html += "</tr>`n"
            } else {
                foreach ($unhs in $unhstorage) {
                    $unhstorage_html += "<tr>`n"
                    $unhstorage_html += "<td>$($unhs.host)</td>`n"
                    $unhstorage_html += "<td>$($unhs.vendor)</td>`n"
                    $unhstorage_html += "<td>$($unhs.state)</td>`n"
                    $unhstorage_html += "<td>$($unhs.name)</td>`n"
                    $unhstorage_html += "<td>$($unhs.capacitygb)</td>`n"
                    $unhstorage_html += "<td>$($unhs.hypervisor)</td>`n"
                    $unhstorage_html += "</tr>`n"
                }
            }
        
        # Close HTML Table
        
            $unhstorage_html += "</table>`n"
        
        # Spacing before next HTML section
        
            $unhstorage_html += ”`n <br />”

#---------------------------------------------[Check for Incompatible Audio Hardware]----------------------------------------------

# Get VMs with Incompatible Audio Hardware

    # VMware

    $vms = get-vm
    
    foreach ($vm in $vms) {
        $vmdevices = $vm.ExtensionData.Config.Hardware.Device | where-object {$_.GetType().Name}
    
        if ($vmdevices -match 'VirtualHdAudioCard') {
            $incompathw += New-Object -TypeName PSObject -Property @{
                vm = $vm.name;
                powerstate = $vm.powerstate;
                device = "VirtualHdAudioCard";
                hypervisormgr = ([System.Uri]$vm.ExtensionData.Client.ServiceUrl).Host;
            }
        }
    }

    # RHV Ovirt-Engine

        # This only affects VMware, no RHV equivalent

    # Build Incompatible Audio Hardware Table

        # Setup HTML Table Section

            $incompathw_html = ”<strong>VMs with Incompatible Audio Hardware:</strong>`n <br />”
            $incompathw_html += ”`n <br />”

        # Setup HTML Table & Headings

            $incompathw_html += "<table>`n"
            $incompathw_html += "<th style='font-weight:bold'>VM</th>"
            $incompathw_html += "<th style='font-weight:bold'>Power State</th>"
            $incompathw_html += "<th style='font-weight:bold'>Device</th>"
            $incompathw_html += "<th style='font-weight:bold'>Hypervisor Manager</th>"
            
        # Populate Table
            if ($incompathw.count -eq 0) {
                    $incompathw_html += "<tr>`n"
                    $incompathw_html += "<td colspan='4'>No VMs with Incompatible Audio Hardware Found</td> `n"
                    $incompathw_html += "</tr>`n"
            } else {
                foreach ($ichw in $incompathw) {
                    $incompathw_html += "<tr>`n"
                    $incompathw_html += "<td>$($ichw.vm)</td>`n"
                    $incompathw_html += "<td>$($ichw.powerstate)</td>`n"
                    $incompathw_html += "<td>$($ichw.device)</td>`n"
                    $incompathw_html += "<td>$($ichw.hypervisormgr)</td>`n"
                    $incompathw_html += "</tr>`n"
                }
            }

        # Close HTML Table

            $incompathw_html += "</table>`n"

        # Spacing before next HTML section

            $incompathw_html += ”`n <br />”

#-------------------------------------------[Network Adapters Not Connected at Power On]-------------------------------------------

    # VMware

        $vms = get-vm
        
        foreach ($vm in $vms) {
            $nics = $vm | Get-NetworkAdapter
            foreach ($nic in $nics) {
                if($Nic.ConnectionState.Connected -eq $true -and $nic.ConnectionState.StartConnected -eq $false) {
                $nicpwronresult += New-Object -TypeName PSObject -Property @{
                    vmname = $nic.Parent;
                    nicname = $nic.Name;
                    networkname = $nic.NetworkName;
                    nictype = $nic.Type;
                    nicmac = $nic.MacAddress;
                    niccon = $nic.ConnectionState.Connected;
                    nicpwrcon = $nic.ConnectionState.StartConnected;
                    hvmgr = ([System.Uri]$vm.ExtensionData.Client.ServiceUrl).Host;
                    }
                }
            }
        }

    # RHV Ovirt-Engine

        # TBD

    # Build Network Adapters Not Connected at Power On Table
    
        # Setup HTML Table Section

            $nicpwron_html = ”<strong>VMs with Network Adapters Not Connected at Power On:</strong>`n <br />”
            $nicpwron_html += ”`n <br />”

        # Setup HTML Table & Headings

            $nicpwron_html += "<table>`n"
            $nicpwron_html += "    <th style='font-weight:bold'>Name</th>"
            $nicpwron_html += "    <th style='font-weight:bold'>Interface</th>"
            $nicpwron_html += "    <th style='font-weight:bold'>Network Name</th>"
            $nicpwron_html += "    <th style='font-weight:bold'>NIC Type</th>"
            $nicpwron_html += "    <th style='font-weight:bold'>MAC Address</th>"
            $nicpwron_html += "    <th style='font-weight:bold'>NIC Connected</th>"
            $nicpwron_html += "    <th style='font-weight:bold'>NIC Connect at Power On</th>"
            $nicpwron_html += "    <th style='font-weight:bold'>Hypervisor Manager</th>"

        # Populate Table

        if ($nicpwronresult.count -eq 0) {
            $nicpwron_html += "<tr>`n"
            $nicpwron_html += "<td colspan='8'>No Network Adapters Not Connected at Power On Found</td> `n"
            $nicpwron_html += "</tr>`n"
        } else {
            foreach ($nicpwronres in $nicpwronresult) {
                $nicpwron_html += "  <tr>`n"
                $nicpwron_html += "    <td>$($nicpwronres.vmname)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.nicname)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.networkname)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.nictype)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.nicmac)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.niccon)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.nicpwrcon)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.hvmgr)</td>`n"
                $nicpwron_html += "  </tr>`n"
            }
        }

        # Close HTML Table

            $nicpwron_html += "</table>`n"

        # Spacing before next HTML section

            $nicpwron_html += ”`n <br />”

#-----------------------------------------------------[VM Guest Tool Issues]-------------------------------------------------------

    # VMware
    
        $vms = get-vm | where-object {$_.PowerState -ne "PoweredOff" -and $_.extensiondata.Guest.toolsstatus -ne "toolsok"}

        foreach ($vm in $vms) {
            $vmguesttools += New-Object -TypeName PSObject -Property @{
                vmname = $vm.name;
                toolsstatus = $vm.extensiondata.Guest.toolsstatus;
                toolsversion = $vm.extensiondata.Guest.ToolsVersionStatus;
                toolsrunning = $vm.extensiondata.Guest.ToolsRunningStatus;
                toolsversionno = $vm.extensiondata.Guest.ToolsVersion;
                }
        }

    # RHV Ovirt-Engine

        # TBD
    
    # Build VM Guest Tool Issues Table    
    
        # Setup HTML Table Section

            $vmgtools_html = ”<strong>VMs with Guest Tool Issues:</strong>`n <br />”
            $vmgtools_html += ”`n <br />”

        # Setup HTML Table & Headings

            $vmgtools_html += "<table>`n"
            $vmgtools_html += "    <th style='font-weight:bold'>VM Name</th>"
            $vmgtools_html += "    <th style='font-weight:bold'>Guest Tools Status</th>"
            $vmgtools_html += "    <th style='font-weight:bold'>Guest Tools Version</th>"
            $vmgtools_html += "    <th style='font-weight:bold'>Guest Tools Running</th>"
            $vmgtools_html += "    <th style='font-weight:bold'>Guest Tools Version</th>"
            $vmgtools_html += ”`n <br />”

        # Populate Table

        if ($vmguesttools.count -eq 0) {
            $vmgtools_html += "<tr>`n"
            $vmgtools_html += "<td colspan='5'>No VM Guest Tool Issues Found</td> `n"
            $vmgtools_html += "</tr>`n"
        } else {
            foreach ($vmguesttool in $vmguesttools) {
                $vmgtools_html += "  <tr>`n"
                $vmgtools_html += "    <td>$($vmguesttool.vmname)</td>`n"
                $vmgtools_html += "    <td>$($vmguesttool.toolsstatus)</td>`n"
                $vmgtools_html += "    <td>$($vmguesttool.toolsversion)</td>`n"
                $vmgtools_html += "    <td>$($vmguesttool.toolsrunning)</td>`n"
                $vmgtools_html += "    <td>$($vmguesttool.toolsversionno)</td>`n"
                $vmgtools_html += "  </tr>`n"
            }
        }

        # HTML Table Close

            $vmgtools_html += "</table>`n"

        # Spacing before next HTML section

            $vmgtools_html += ”`n <br />”

#-----------------------------------------[Datastores Below Minimum Free Space Threshold]------------------------------------------

    # VMware
    
            $datastorewarn = get-datastore | where-object {$_.FreeSpaceGB -lt 300 -and $_.Name -notlike "*log*" -and $_.Name -notlike "*rsc*"}
                foreach ($dswarn in $datastorewarn) {
                    $datastorewarns += New-Object -TypeName PSObject -Property @{
                        dsname = $dswarn.name;
                        freespacegb = $dswarn.FreeSpaceGB;
                        capacitygb = $dswarn.CapacityGB;
                        hvmgr = ([System.Uri]$dswarn.ExtensionData.Client.ServiceUrl).Host;
                        }
                }
            
            $datastorecrit = get-datastore | where-object {$_.FreeSpaceGB -lt 500 -and $_.FreeSpaceGB -gt 300 -and $_.Name -notlike "*log*" -and $_.Name -notlike "*rsc*"}
                foreach ($dsvrit in $datastorecrit) {
                    $datastorecrits += New-Object -TypeName PSObject -Property @{
                        dsname = $dswarn.name;
                        freespacegb = $dswarn.FreeSpaceGB;
                        capacitygb = $dswarn.CapacityGB;
                        hvmgr = ([System.Uri]$dswarn.ExtensionData.Client.ServiceUrl).Host;
                        }
                }

            $datastoreothr = get-datastore | where-object {$_.FreeSpaceGB -lt 50 -and $_.Name -like "*log*" -or $_.FreeSpaceGB -lt 50 -and $_.Name -like "*rsc*"}
                foreach ($dsothr in $datastoreothr) {
                    $datastoreothrs += New-Object -TypeName PSObject -Property @{
                        dsname = $dswarn.name;
                        freespacegb = $dswarn.FreeSpaceGB;
                        capacitygb = $dswarn.CapacityGB;
                        hvmgr = ([System.Uri]$dswarn.ExtensionData.Client.ServiceUrl).Host;
                        }
                }

    # RHV Ovirt-Engine

        # TBD

    # Build VM Guest Tool Issues Table    
    
        # Setup HTML Table Section

            $datastore_html = ”<strong>Datastores Below Minimum Free Space Threshold:</strong>`n <br />”
            $datastore_html += ”`n <br />”

        # Setup HTML Table & Headings
    
            $datastore_html += "<table>`n"
            $datastore_html += "    <th style='font-weight:bold'>Name</th>"
            $datastore_html += "    <th style='font-weight:bold'>Free Space (GB)</th>"
            $datastore_html += "    <th style='font-weight:bold'>Capacity (GB)</th>"
            $datastore_html += "    <th style='font-weight:bold'>Hypervisor Manager</th>"
            $datastore_html += ”`n <br />”

        # Populate Table

        if ($datastorewarns.count -eq 0 -and $datastorecrits.count -eq 0 -and $datastoreothrs.count -eq 0) {
            $datastore_html += "<tr>`n"
            $datastore_html += "<td colspan='4'>No Datastores Below Minimum Free Space Threshold Found</td> `n"
            $datastore_html += "</tr>`n"
        } else {
            foreach ($dswarn in $datastorewarns) {
                $datastore_html += "  <tr>`n"
                $datastore_html += "    <td>$($dswarn.dsname)</td>`n"
                $datastore_html += "    <td bgcolor=#FFFF00>$($dswarn.FreeSpaceGB)</td>`n"
                $datastore_html += "    <td>$($dswarn.CapacityGB)</td>`n"
                $datastore_html += "    <td>$($dswarn.hvmgr)</td>`n"
                $datastore_html += "  </tr>`n"
            }

            foreach ($dscrit in $datastorecrits) {
                $datastore_html += "  <tr>`n"
                $datastore_html += "    <td>$($dscrit.dsname)</td>`n"
                $datastore_html += "    <td bgcolor=#FF0000>$($dswarn.FreeSpaceGB)</td>`n"
                $datastore_html += "    <td>$($dscrit.CapacityGB)</td>`n"
                $datastore_html += "    <td>$($dscrit.hvmgr)</td>`n"
                $datastore_html += "  </tr>`n"
            }

            foreach ($dsothr in $datastoreothrs) {
                $datastore_html += "  <tr>`n"
                $datastore_html += "    <td>$($dsothr.dsname)</td>`n"
                $datastore_html += "    <td>$($dsothr.FreeSpaceGB)</td>`n"
                $datastore_html += "    <td>$($dsothr.CapacityGB)</td>`n"
                $datastore_html += "    <td>$($dsothr.hvmgr)</td>`n"
                $datastore_html += "  </tr>`n"
            }
        }

        # HTML Table Close

            $datastore_html += "</table>`n"

        # Spacing before next HTML section

            $datastore_html += ”`n <br />”

#------------------------------------------------------[VMs with mounted CDs]------------------------------------------------------

    # VMware

        $mountedcds = Get-VM | Get-CDDrive | where-object {$_.IsoPath -ne $null}
        foreach ($mountedcd in $mountedcds) {
            $isopath = $mountedcd.IsoPath
            if ($($mountedcd.IsoPath) -eq "[]") {
                Get-VM $($mountedcd.parent) | Get-CDDRive | Where-Object {$_.IsoPath} | Set-CDDrive -NoMedia -Confirm:$false
                $isopath = "'[]' (this has automatically been dismounted)"
            }
            $mntcds += New-Object -TypeName PSObject -Property @{
               vmname = $mountedcd.parent;
               mountedcd = $isopath;
               hvmgr = ([System.Uri](get-vm | where-object {$_.id -like ($mountedcd.parentid)}).ExtensionData.Client.ServiceUrl).host;
            }
        }

    # RHV Ovirt-Engine

        # Some RedHat code goes here

    # Build VM Guest Tool Issues Table    
    
        # Setup HTML Table Section

        $mntdiso_html = ”<strong>VMs with mounted CDs:</strong>`n <br />”
        $mntdiso_html += ”`n <br />”

    # Setup HTML Table & Headings

        $mntdiso_html += "<table>`n"
        $mntdiso_html += "    <th style='font-weight:bold'>Name</th>"
        $mntdiso_html += "    <th style='font-weight:bold'>Mounted CD</th>"
        $mntdiso_html += "    <th style='font-weight:bold'>Hypervisor Manager</th>"
        $mntdiso_html += ”`n <br />”

    # Populate Table

    if ($mntcds.count -eq 0) {
        $mntdiso_html += "<tr>`n"
        $mntdiso_html += "<td colspan='3'>No VMs with mounted CDs Found</td> `n"
        $mntdiso_html += "</tr>`n"
    } else {
        foreach ($mntcd in $mntcds) {
            $mntdiso_html += "  <tr>`n"
            $mntdiso_html += "    <td>$($mntcd.vmname)</td>`n"
            $mntdiso_html += "    <td>$($mntcd.mountedcd)</td>`n"
            $mntdiso_html += "    <td>$($mntcd.hvmgr)</td>`n"
            $mntdiso_html += "  </tr>`n"
        }
    }

    # HTML Table Close

        $mntdiso_html += "</table>`n"

    # Spacing before next HTML section

        $mntdiso_html += ”`n <br />”

#-------------------------------------------------------[VMs with Snapshots]-------------------------------------------------------

    # VMware

        $snapshots = get-vm | get-snapshot
        foreach ($snapshot in $snapshots) {
            $snaps += New-Object -TypeName PSObject -Property @{
                vmname = $snapshot.vm.name;
                snapname = $snapshot.name;
                snapcreated = $snapshot.created;
                snapsizegb = [math]::Round($snapshot.sizegb,2);
                snapdesc = $snapshot.description;
                hvmgr = ([System.Uri](get-vm | where-object {$_.id -like ($snapshot.vmid)}).ExtensionData.Client.ServiceUrl).host;
            }
        }

    # RHV Ovirt-Engine

        # Some RedHat code goes here

    # Build VMs with Snapshots Table    
    
        # Setup HTML Table Section

            $snapshots_html = ”<strong>VMs with Snapshots:</strong>`n <br />”
            $snapshots_html += ”`n <br />”

        # Setup HTML Table & Headings

            $snapshots_html += "<table>`n"
            $snapshots_html += "    <th style='font-weight:bold'>VM Name</th>"
            $snapshots_html += "    <th style='font-weight:bold'>Snapshot Name</th>"
            $snapshots_html += "    <th style='font-weight:bold'>Snapshot Created</th>"
            $snapshots_html += "    <th style='font-weight:bold'>Snapshot Size (GB)</th>"
            $snapshots_html += "    <th style='font-weight:bold'>Snapshot Description</th>"
            $snapshots_html += "    <th style='font-weight:bold'>Hypervisor Manager</th>"
            $snapshots_html += ”`n <br />”

        # Populate Table

        if ($snaps.count -eq 0) {
            $snapshots_html += "<tr>`n"
            $snapshots_html += "<td colspan='6'>No VMs with Snapshots Found</td> `n"
            $snapshots_html += "</tr>`n"
        } else {
            foreach ($snap in ($snaps | sort-object snapcreated)) {
                $snapshots_html += "  <tr>`n"
                $snapshots_html += "    <td>$($snap.vmname)</td>`n"
                $snapshots_html += "    <td>$($snap.snapname)</td>`n"
                if ($snap.snapcreated -lt ([DateTime]::Now.AddDays(-1)) -and $snap.snapdesc -notlike '*<RPData*' -and '*/>*') {
                    $snapshots_html += "    <td bgcolor=#F88379>$($snap.snapcreated)</td>`n"
                } else {
                    $snapshots_html += "    <td>$($snap.snapcreated)</td>`n"
                }
                $snapshots_html += "    <td>$($snap.snapsizegb)</td>`n"
                if ($snap.snapdesc -like '*<RPData*' -and '*/>*') {
                    $snapshots_html += "    <td bgcolor=#F5F5DC>Appears to be a Veeam Replication Snapshot</td>`n"
                } elseif ([string]::IsNullOrEmpty($snap.snapdesc)) {
                    $snapshots_html += "    <td bgcolor=#F88379>No Snapshot Description Provided</td>`n"
                } else {
                    $snapshots_html += "    <td>$($snap.snapdesc)</td>`n"
                }
                $snapshots_html += "    <td>$($snap.hvmgr)</td>`n"
                $snapshots_html += "  </tr>`n"
            }
        }

        # HTML Table Close

            $snapshots_html += "</table>`n"

        # Spacing before next HTML section

            $snapshots_html += ”`n <br />”

#----------------------------------------------------------[Host Alarms]-----------------------------------------------------------

        # TBD

#--------------------------------------------------------[Datastore Alarms]--------------------------------------------------------

        # TBD

#------------------------------------------------------[Disconnect vCenters]-------------------------------------------------------

        #foreach ($vcenter in $vcenters) {
        #     Disconnect-VIServer -Server $vcenter -confirm:$False
        #}

#-----------------------------------------------------[Create and Send Email]------------------------------------------------------

    # Create New Message Object

        $msg = new-object Net.Mail.MailMessage
       
    # Message Subject
        
        $msg.Subject = $msgsubj
    
    # From Address
        
        $msg.From = $msgfrom

    # To Address, to add additional recipients, update the array $msgto at the top of this script.
        
        foreach ($recipient in $msgto) {
            $msg.To.Add($recipient)
            }
    
    # Build Message Body

        $msg.IsBodyHtml = $true
        $msg.Body=$header
        $msg.Body+=$hvconn_html
        $msg.Body+=$unhstorage_html
        $msg.Body+=$incompathw_html
        $msg.Body+=$nicpwron_html
        $msg.Body+=$vmgtools_html
        $msg.Body+=$datastore_html
        $msg.Body+=$mntdiso_html
        $msg.Body+=$snapshots_html


    # Send Message
            
        $smtp.Send($msg)
    
    # Debug Message Output

        write-output $msg | format-list

    # Destroy Message Object
    
        $msg.Dispose();

#---------------------------------------------------------[Logging  Stop]----------------------------------------------------------

    # Stop Log

        Stop-Transcript
