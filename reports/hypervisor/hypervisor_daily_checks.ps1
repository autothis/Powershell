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

        $settingsfile = "c:\temp\hypervisor_daily_check.config"
        $settings = Get-Content $settingsfile | Out-String | ConvertFrom-StringData

        # Example File Structre: See example_hypervisor_daily_checks_settings.config file.


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

        $rhvauth = @()
        $vms = @()
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
        $snapshotvms = @()
        $snaps = @()
        $halarms = @()
        $dalarms = @()

    # Create HTML Header

        $Header = @("
        <style>
        TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
        TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #21c465;}
        TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
        .header {
            padding: 60px;
            text-align: center;
            background: #FFFFFF;
            color: black;
            font-size: 45px;
            line-height: 45px;
        }
        </style>
        <div class='header'>
            <h1>Hypervisor Health Check Report</h1>
        </div>
        ")

#----------------------------------------------------------[Declarations]----------------------------------------------------------

    # General
    
        # N/A
    
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

    # Get Account for Hypervisor Authentication

        # All

            [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
            $vaultresource="hypervisor-query" # Be sure to store hypervisor readonly credentials in password vault with this resource name
            $vault = New-Object Windows.Security.Credentials.PasswordVault
            $username = ( $vault.RetrieveAll() | Where-Object { $_.Resource -eq $vaultresource } | Select-Object -First 1 ).UserName
            $user = ($username.split("@"))[0]
            $domain = ($username.split("@"))[1]
            $password = ( $vault.Retrieve( $vaultresource, $username ) | Select-Object -First 1 ).Password
            $securepass = ConvertTo-SecureString -String $password -AsPlainText -Force
                
        # VMware
            
            $credential = New-Object System.Management.Automation.PSCredential ($username, $securepass)
        
        # RHV Ovirt-Engine 

            foreach ($rhvmgr in $rhvmgrs) {
                $AuthPayload = "grant_type=password&scope=ovirt-app-api&username=$user%40$domain&password=$password"
                $AuthHeaders = @{"Accept" = "application/json"}
                $URI = "https://$rhvmgr/ovirt-engine/sso/oauth/token"
                $AuthResponse = Invoke-WebRequest -Uri $URI -Method Post -body $AuthPayload -Headers $AuthHeaders -ContentType 'application/x-www-form-urlencoded'
                $AuthToken = ((($AuthResponse.Content) -split '"')[3])
                $rhvauth += New-Object -TypeName PSObject -Property @{
                    rhvmgr = $rhvmgr;
                    token = $AuthToken;
                    headers = @{
                        Authorization="Bearer $Authtoken"
                    }
                }
            }

        # Clean Up

            Remove-Variable password # So that we don't have the unsecure password lingering in memory

#----------------------------------------------------------[Gather Data]-----------------------------------------------------------

    # VMware

        # TBD

    # RHV Ovirt-Engine 

        # Fields to Follow
        
        #    $rhvfollow = 'cdroms,nics,diskattachments,snapshots,tags'
        
        ## Gather Data
    #
        #    foreach ($rhvmgr in $rhvmgrs) {
#
        #        # Get Hosts Data
#
        #            $rhvallhosts += (invoke-restmethod -uri "https://$rhvmgr/ovirt-engine/api/hosts" -Headers $headers).hosts.host
#
        #        # Get Storage Domains Data
#
        #            $rhvallstoragedomains += (invoke-restmethod -uri "https://$rhvmgr/ovirt-engine/api/storagedomains" -Headers $headers).storage_domains.storage_domain
        #    
        #        # Get VM Data
#
        #            $rhvvms += (invoke-restmethod -uri "https://$rhvmgr/ovirt-engine/api/vms" -Headers $headers).vms.vm
        #            foreach ($rhvvm in $rhvvms) {
        #            	$rhvallvms += (invoke-restmethod -uri "https://$rhvmgr/ovirt-engine/api/vms/$($rhvvm.id)?follow=$rhvfollow" -Headers $headers).vm
        #            }
#
        #    }

#-----------------------------------------------------------[Functions]------------------------------------------------------------

    # N/A

#-----------------------------------------------------[Connect to Hypervisors]-----------------------------------------------------

    # VCSAs

        foreach ($vcenter in $vcenters) {
            Connect-VIServer $vcenter -Credential $credential
        }
        foreach ($vcsaconn in $Global:DefaultVIServers) {
                $hvconns += New-Object -TypeName PSObject -Property @{
                    name = $vcsaconn.Name;
                    user = $vcsaconn.User;
                    hypervisor = "VMware vCenter";
                    version = "$($vcsaconn.version)" + "." + "$($vcsaconn.build)";
                }
        }

    # RHV Ovirt-Engine (not required, but closest equivilent and a good test, if this step fails, others are likely to as well)

        foreach ($rhvmgr in $rhvauth) {
            $rhvmgrconn = invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)/ovirt-engine/api" -headers $rhvmgr.headers
            $rhvmgrusr = invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)$($rhvmgrconn.api.authenticated_user.href)" -headers $rhvmgr.headers
            $hvconns += New-Object -TypeName PSObject -Property @{
                name = $rhvmgr.rhvmgr;
                user = $rhvmgrusr.user.principal;
                hypervisor = $rhvmgrconn.api.product_info.name;
                version = $rhvmgrconn.api.product_info.version.full_version;
            }
        }

    # Build Hypervisor Connection Table

        # Setup HTML Table Section

            $hvconn_html = ”<strong style='font-size:20px'>vCenter Connections:</strong><br />”
            $hvconn_html += ”<em>Hypervisors clusters covered by this report.</em><br />”
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

            $unhstorage_html = ”<strong style='font-size:20px'>Hosts with Unhealthy Storage:</strong>`n <br />”
            $unhstorage_html += ”<em>List of storage presented to Hosts in an unhealthy state.</em><br />”
            $unhstorage_html += ”<em>Manual intervention is required, this may affect host stability or failover capabilities.</em><br />”
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

            $incompathw_html = ”<strong style='font-size:20px'>VMs with Incompatible Virtual Hardware (HD Audio):</strong>`n <br />”
            $incompathw_html += ”<em>Hardware incompatible prevents maintenance within the hypervisor environment preventing automatic rescheduling of the VM.</em><br />”
            $incompathw_html += ”<em>Manual intervention is required to Maintain service in many circumstances.</em><br />”
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

        foreach ($rhvmgr in $rhvauth) {
            $rhvvms = (invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)/ovirt-engine/api/vms" -Headers $rhvmgr.headers).vms.vm
            foreach ($rhvvm in $rhvvms) {
                $nics = (invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)/ovirt-engine/api/vms/$($rhvvm.id)/nics" -Headers $rhvmgr.headers).nics.nic
                foreach ($nic in $nics) {
                    $netadapter = (invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)/ovirt-engine/api/vms/$($rhvvm.id)/nics/$($nic.id)" -Headers $rhvmgr.headers).nic
                    if (($netadapter.linked -eq 'true' -and $netadapter.plugged -eq 'false') -or ($netadapter.linked -eq 'false' -and $netadapter.plugged -eq 'true')) {
                        $nicpwronresult += New-Object -TypeName PSObject -Property @{
                            vmname = $rhvvm.name;
                            nicname = $netadapter.Name;
                            networkname = (invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)/ovirt-engine/api/vnicprofiles/$($netadapter.vnic_profile.id)" -Headers $rhvmgr.headers).vnic_profile.name;
                            nictype = $netadapter.interface;
                            nicmac = $netadapter.mac.address;
                            niccon = $netadapter.linked;
                            nicpwrcon = $netadapter.plugged;
                            hvmgr = $rhvmgr.rhvmgr;
                        }
                    }
                }
            }
        }

    # Build Network Adapters Not Connected at Power On Table
    
        # Setup HTML Table Section

            $nicpwron_html = ”<strong style='font-size:20px'>VMs with NIC Connected, but not Connected at Start Up:</strong>`n <br />”
            $nicpwron_html += ”<em>VMs that do not have this options ticked, will require manual intervention to re-establish network connectivity, in the event a failure scenario occurs.</em><br />”
            $nicpwron_html += ”<em>RedHat doesnt have the same option, but it does have the option to have the NIC 'Plugged In' but without link, which is included here.</em><br />”
            $nicpwron_html += ”<em>'NIC Connected' = 'Link'</em><br />”
            $nicpwron_html += ”<em>'NIC Connect at Power On' = 'Plugged In'</em><br />”
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
    
        $vms = get-vm | where-object {$_.PowerState -ne "PoweredOff" -and $_.extensiondata.Guest.toolsstatus -ne "toolsok" -and $_.extensiondata.Guest.ToolsVersionStatus -ne "guestToolsUnmanaged"}

        foreach ($vm in $vms) {
            $vmguesttools += New-Object -TypeName PSObject -Property @{
                vmname = $vm.name;
                toolsstatus = if (($vm.extensiondata.Guest.toolsstatus) -eq "toolsOld") {
                        "Guest Agent Out of Date"
                    } elseif (($vm.extensiondata.Guest.toolsstatus) -eq "toolsNotInstalled") {
                        "Guest Agent Not Installed"
                    } elseif (($vm.extensiondata.Guest.toolsstatus) -eq "toolsNotRunning") {
                        "Guest Agent Not Running"
                    } else {
                        $vm.extensiondata.Guest.toolsstatus
                    };
                toolsrunning = if (($vm.extensiondata.Guest.ToolsRunningStatus) -eq "guestToolsNotRunning") {
                        "Not Running"
                    } elseif (($vm.extensiondata.Guest.ToolsRunningStatus) -eq "guestToolsRunning") {
                        "Running"
                    } else {
                        $vm.extensiondata.Guest.ToolsRunningStatus
                    };
                toolsversionno = if (($vm.extensiondata.Guest.ToolsVersion) -eq "0") {
                        "N/A"
                    } else {
                        $vm.extensiondata.Guest.ToolsVersion
                    };
                hvmgr = ([System.Uri]$vm.ExtensionData.Client.ServiceUrl).Host;
            }
        }

    # RHV Ovirt-Engine

        foreach ($rhvmgr in $rhvauth) {
            $vmguests = (invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)/ovirt-engine/api/vms?follow=applications" -Headers $rhvmgr.headers).vms.vm
            foreach ($vmguest in ($vmguests | where-object {($_.applications.application.name).count -eq 0})) {
                $vmguesttools += New-Object -TypeName PSObject -Property @{
                    vmname = $vmguest.name;
                    toolsstatus = if (($vmguest.applications.application.name).count -ge 1) {
                            "Guest Agent Installed"
                        } elseif (($vmguest.applications.application.name).count -eq 0) {
                            "Guest Agent Not Installed"
                        };
                    toolsrunning = "N/A";
                    toolsversionno = if (($vmguest.applications.application.name).count -eq 1) {
                            $vmguest.applications.application.name
                        } elseif (($vmguest.applications.application.name).count -gt 1) {
                            $vmguest.applications.application.name[1]
                        } elseif (($vmguest.applications.application.name).count -eq 0) {
                            "N/A"
                        };
                    hvmgr = $rhvmgr.rhvmgr;
                }
            }
        }

    # Build VM Guest Tool Issues Table    
    
        # Setup HTML Table Section

            $vmgtools_html = ”<strong style='font-size:20px'>VMs with VM Guest Tool Issues:</strong>`n <br />”
            $vmgtools_html += ”<em>Guest tools are installed at the guest layer (Windows, Linux, etc....), these should be updated during regular guest maintenance (patching).</em><br />”
            $vmgtools_html += ”<em>Guest tools provide a number of functions including, but not limited to, drivers, and enabling advanced features used for backups, and VM management.</em><br />”
            $vmgtools_html += ”`n <br />”

        # Setup HTML Table & Headings

            $vmgtools_html += "<table>`n"
            $vmgtools_html += "    <th style='font-weight:bold'>VM Name</th>"
            $vmgtools_html += "    <th style='font-weight:bold'>Guest Tools Status</th>"
            $vmgtools_html += "    <th style='font-weight:bold'>Guest Tools Running</th>"
            $vmgtools_html += "    <th style='font-weight:bold'>Guest Tools Version</th>"
            $nicpwron_html += "    <th style='font-weight:bold'>Hypervisor Manager</th>"
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
                    $vmgtools_html += "    <td>$($vmguesttool.toolsrunning)</td>`n"
                    $vmgtools_html += "    <td>$($vmguesttool.toolsversionno)</td>`n"
                    $vmgtools_html += "    <td>$($vmguesttool.hvmgr)</td>`n"
                    $vmgtools_html += "  </tr>`n"
                }
            }

        # HTML Table Close

            $vmgtools_html += "</table>`n"

        # Spacing before next HTML section

            $vmgtools_html += ”`n <br />”

#-----------------------------------------[Datastores Below Minimum Free Space Threshold]------------------------------------------

    # VMware
    
        #$datastorewarn = get-datastore | where-object {$_.FreeSpaceGB -lt 300 -and $_.Name -notlike "*log*" -and $_.Name -notlike "*rsc*"}
        #    foreach ($dswarn in $datastorewarn) {
        #        $datastorewarns += New-Object -TypeName PSObject -Property @{
        #            dsname = $dswarn.name;
        #            freespacegb = $dswarn.FreeSpaceGB;
        #            capacitygb = $dswarn.CapacityGB;
        #            hvmgr = ([System.Uri]$dswarn.ExtensionData.Client.ServiceUrl).Host;
        #            }
        #    }
        #
        #$datastorecrit = get-datastore | where-object {$_.FreeSpaceGB -lt 500 -and $_.FreeSpaceGB -gt 300 -and $_.Name -notlike "*log*" -and $_.Name -notlike "*rsc*"}
        #    foreach ($dsvrit in $datastorecrit) {
        #        $datastorecrits += New-Object -TypeName PSObject -Property @{
        #            dsname = $dswarn.name;
        #            freespacegb = $dswarn.FreeSpaceGB;
        #            capacitygb = $dswarn.CapacityGB;
        #            hvmgr = ([System.Uri]$dswarn.ExtensionData.Client.ServiceUrl).Host;
        #            }
        #    }
#
        #$datastoreothr = get-datastore | where-object {$_.FreeSpaceGB -lt 50 -and $_.Name -like "*log*" -or $_.FreeSpaceGB -lt 50 -and $_.Name -like "*rsc*"}
        #    foreach ($dsothr in $datastoreothr) {
        #        $datastoreothrs += New-Object -TypeName PSObject -Property @{
        #            dsname = $dswarn.name;
        #            freespacegb = $dswarn.FreeSpaceGB;
        #            capacitygb = $dswarn.CapacityGB;
        #            hvmgr = ([System.Uri]$dswarn.ExtensionData.Client.ServiceUrl).Host;
        #            }
        #    }
        
        $datastorefreegbs = get-datastore | where-object {$_.FreeSpaceGB -lt 500}
            foreach ($datastorefreegb in $datastorefreegbs) {
                $datastorefree += New-Object -TypeName PSObject -Property @{
                    dsname = $datastorefreegb.name;
                    freespacegb = $datastorefreegb.FreeSpaceGB;
                    capacitygb = $datastorefreegb.CapacityGB;
                    hvmgr = ([System.Uri]$datastorefreegb.ExtensionData.Client.ServiceUrl).Host;
                    }
            }

    # RHV Ovirt-Engine

        # TBD

    # Build VM Guest Tool Issues Table    
    
        # Setup HTML Table Section

            $datastore_html = ”<strong style='font-size:20px'>Datastores Below Minimum Free Space Threshold:</strong>`n <br />”
            $datastore_html += ”<em>List of datastores below the minimum free space thresholds, less than 500GB warning, less than 300GB is critical.</em><br />”
            $datastore_html += ”<em>Non VM datastores (RSC, LOG, etc....) are monitored for free space below 50GB.</em><br />”
            $datastore_html += ”`n <br />”

        # Setup HTML Table & Headings
    
            $datastore_html += "<table>`n"
            $datastore_html += "    <th style='font-weight:bold'>Name</th>"
            $datastore_html += "    <th style='font-weight:bold'>Free Space (GB)</th>"
            $datastore_html += "    <th style='font-weight:bold'>Capacity (GB)</th>"
            $datastore_html += "    <th style='font-weight:bold'>Hypervisor Manager</th>"
            $datastore_html += ”`n <br />”

        # Populate Table

            if ($datastorefree.count -eq 0) {
                $datastore_html += "<tr>`n"
                $datastore_html += "<td colspan='4'>No Datastores Below Minimum Free Space Threshold Found</td> `n"
                $datastore_html += "</tr>`n"
            } else {
                foreach ($dsfree in $datastorefree) {
                    $datastore_html += "  <tr>`n"
                    $datastore_html += "    <td>$($dsfree.dsname)</td>`n"
                    $datastore_html += if ($dsfree.FreeSpaceGB -lt 300 -and $dsfree.Name -notlike "*log*" -and $dsfree.Name -notlike "*rsc*") {
                            "    <td bgcolor=#FF0000>$($dsfree.FreeSpaceGB)</td>`n"
                        } elseif ($dsfree.FreeSpaceGB -gt 300 -and $dsfree.FreeSpaceGB -lt 500 -and $dsfree.Name -notlike "*log*" -and $dsfree.Name -notlike "*rsc*") {
                            "    <td bgcolor=#FFFF00>$($dsfree.FreeSpaceGB)</td>`n"
                        } elseif (($dsfree.FreeSpaceGB -lt 50 -and $dsfree.Name -like "*log*") -or ($dsfree.FreeSpaceGB -lt 50 -and $dsfree.Name -like "*rsc*")) {
                            "    <td>$($dsfree.FreeSpaceGB)</td>`n"
                        }
                    $datastore_html += "    <td>$($dsfree.CapacityGB)</td>`n"
                    $datastore_html += "    <td>$($dsfree.hvmgr)</td>`n"
                    $datastore_html += "  </tr>`n"
                }
                
                #foreach ($dswarn in $datastorewarns) {
                #    $datastore_html += "  <tr>`n"
                #    $datastore_html += "    <td>$($dswarn.dsname)</td>`n"
                #    $datastore_html += "    <td bgcolor=#FFFF00>$($dswarn.FreeSpaceGB)</td>`n"
                #    $datastore_html += "    <td>$($dswarn.CapacityGB)</td>`n"
                #    $datastore_html += "    <td>$($dswarn.hvmgr)</td>`n"
                #    $datastore_html += "  </tr>`n"
                #}
#
                #foreach ($dscrit in $datastorecrits) {
                #    $datastore_html += "  <tr>`n"
                #    $datastore_html += "    <td>$($dscrit.dsname)</td>`n"
                #    $datastore_html += "    <td bgcolor=#FF0000>$($dswarn.FreeSpaceGB)</td>`n"
                #    $datastore_html += "    <td>$($dscrit.CapacityGB)</td>`n"
                #    $datastore_html += "    <td>$($dscrit.hvmgr)</td>`n"
                #    $datastore_html += "  </tr>`n"
                #}
#
                #foreach ($dsothr in $datastoreothrs) {
                #    $datastore_html += "  <tr>`n"
                #    $datastore_html += "    <td>$($dsothr.dsname)</td>`n"
                #    $datastore_html += "    <td>$($dsothr.FreeSpaceGB)</td>`n"
                #    $datastore_html += "    <td>$($dsothr.CapacityGB)</td>`n"
                #    $datastore_html += "    <td>$($dsothr.hvmgr)</td>`n"
                #    $datastore_html += "  </tr>`n"
                #}
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

            $mntdiso_html = ”<strong style='font-size:20px'>VMs with mounted CDs:</strong>`n <br />”
            $mntdiso_html += ”<em>Mounted CDs in some cases can prevent automatic rescheduling of the VM and require manual intervention in the event of a failure scenario.</em><br />”
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

        # Get Snapshots
        $snapshots = get-vm | get-snapshot

        # Add Results to $snaps Array
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

        # Get Snapshots
        foreach ($rhvmgr in $rhvauth) {
            $snapshotvms = @()
            $rhvvms = (invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)/ovirt-engine/api/vms" -Headers $rhvmgr.headers).vms.vm
            foreach ($rhvvm in $rhvvms) {
                $snapshotvms += (invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)/ovirt-engine/api/vms/$($rhvvm.id)?follow=diskattachments,snapshots" -Headers $rhvmgr.headers).vm | where-object {$_.snapshots.snapshot.description -ne 'Active VM'}
            }
            foreach ($snapshot in ($snapshotvms.snapshots.snapshot | where-object {$_.description -ne 'Active VM'})) {
                
                # Calculate Snapshot Size
                $disks = (invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)/ovirt-engine/api/vms/$($snapshot.vm.id)/snapshots/$($snapshot.id)/disks" -Headers $rhvmgr.headers).disks.disk
                $snapsize = $null
                $snapdesc = $null
                foreach ($disk in $disks) {
                    $disksnap = (invoke-restmethod -uri "https://$($rhvmgr.rhvmgr)/ovirt-engine/api/disks/$($disks.id)/disksnapshots" -Headers $rhvmgr.headers).disk_snapshots.disk_snapshot | where-object {$_.snapshot.id -eq $($snapshot.id)}
                   	$snapsize += [long]$disksnap.actual_size
                    if ($disks.id.count -le 1) {
                        $snapdesc = "$($disk.alias)"
                    } else {
                        if ($null -eq $snapdesc) {
                            $snapdesc = "$($disk.alias)"
                        } else {
                            $snapdesc =  "$($snapdesc)" + ", " + "$($disk.alias)"
                        }
                    }
                }

                # Add Results to $snaps Array
                $snaps += New-Object -TypeName PSObject -Property @{
                    vmname = $snapshot.vm.name;
                    snapname = $snapshot.description;
                    snapcreated = [datetime]$snapshot.date;
                    snapsizegb = [math]::Round($($snapsize/1GB),2);
                    snapdesc = $snapdesc;
                    hvmgr = $rhvmgr.rhvmgr;
                }
            }
        }    

    # Build VMs with Snapshots Table    
    
        # Setup HTML Table Section

            $snapshots_html = ”<strong style='font-size:20px'>Current Snapshots:</strong>`n <br />”
            $snapshots_html += ”<em>Snapshots grow in size the longer they are active and will increasingly impact performance.</em><br />”
            $snapshots_html += ”<em>Consolidating snapshots can also impact performance and in some cases actually drop the service for a brief period.</em><br />”
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

    # VMware

        $hostalarms = Get-View -ViewType HostSystem | where-object {$_.TriggeredAlarmstate -ne "{}"}
        foreach ($hostalarm in $hostalarms) {
            $alarmdef = get-alarmdefinition -id $hostalarm.TriggeredAlarmState.alarm
            $halarms += New-Object -TypeName PSObject -Property @{
                hostname = $hostalarm.name;
                status = $hostalarm.overallstatus;
                alarm = $hostalarm.TriggeredAlarmState.alarm.tostring();
                alarmname = $alarmdef.name
                alarmdesc = $alarmdef.description
                hvmgr = ([System.Uri]($hostalarm).Client.ServiceUrl).host;
            }
        }

    # RHV Ovirt-Engine

        # Some RedHat code goes here

    # Build VM Guest Tool Issues Table    
    
        # Setup HTML Table Section

            $halarms_html = ”<strong style='font-size:20px'>Host Alarms:</strong>`n <br />”
            $halarms_html += ”<em>List of hosts with active alarms.</em><br />”
            $halarms_html += ”`n <br />”

        # Setup HTML Table & Headings

            $halarms_html += "<table>`n"
            $halarms_html += "    <th style='font-weight:bold'>Name</th>"
            $halarms_html += "    <th style='font-weight:bold'>Status</th>"
            $halarms_html += "    <th style='font-weight:bold'>Alarm</th>"
            $halarms_html += "    <th style='font-weight:bold'>Alarm Name</th>"
            $halarms_html += "    <th style='font-weight:bold'>Alarm Description</th>"
            $halarms_html += "    <th style='font-weight:bold'>Hypervisor Manager</th>"
            $halarms_html += ”`n <br />”

        # Populate Table

        if ($halarms.count -eq 0) {
            $halarms_html += "<tr>`n"
            $halarms_html += "<td colspan='6'>No Host Alarms Found</td> `n"
            $halarms_html += "</tr>`n"
        } else {
            foreach ($halarm in $halarms) {
                $halarms_html += "  <tr>`n"
                $halarms_html += "    <td>$($halarm.hostname)</td>`n"
                if ($halarm.status -eq "red") {
                    $halarms_html += "    <td bgcolor=#F88379>$($halarm.status)</td>`n"
                } elseif ($halarm.status -eq "yellow") {
                    $halarms_html += "    <td bgcolor=#F5F5DC>$($halarm.status)</td>`n"
                } else {
                    $halarms_html += "    <td>$($halarm.status)</td>`n"
                }
                $halarms_html += "    <td>$($halarm.alarm)</td>`n"
                $halarms_html += "    <td>$($halarm.alarmname)</td>`n"
                $halarms_html += "    <td>$($halarm.alarmdesc)</td>`n"
                $halarms_html += "    <td>$($halarm.hvmgr)</td>`n"
                $halarms_html += "  </tr>`n"
            }
        }

        # HTML Table Close

            $halarms_html += "</table>`n"

        # Spacing before next HTML section

            $halarms_html += ”`n <br />”

#--------------------------------------------------------[Datastore Alarms]--------------------------------------------------------


    # VMware

        $datastorealarms = Get-View -ViewType Datastore | where-object {$_.TriggeredAlarmstate -ne "{}"}
        foreach ($datastorealarm in $datastorealarms) {
            $alarmdef = get-alarmdefinition -id $datastorealarm.TriggeredAlarmState.alarm
            $dalarms += New-Object -TypeName PSObject -Property @{
                dsname = $datastorealarm.name;
                status = $datastorealarm.overallstatus;
                alarm = $datastorealarm.TriggeredAlarmState.alarm.tostring();
                alarmname = $alarmdef.name
                alarmdesc = $alarmdef.description
                hvmgr = ([System.Uri]($datastorealarm).Client.ServiceUrl).host;
            }
        }

    # RHV Ovirt-Engine

        # Some RedHat code goes here

    # Build VM Guest Tool Issues Table    

        # Setup HTML Table Section

            $dalarms_html = ”<strong style='font-size:20px'>Datastore Alarms:</strong>`n <br />”
            $dalarms_html += ”<em>List of datastores with active alarms.</em><br />”
            $dalarms_html += ”`n <br />”

        # Setup HTML Table & Headings

            $dalarms_html += "<table>`n"
            $dalarms_html += "    <th style='font-weight:bold'>Name</th>"
            $dalarms_html += "    <th style='font-weight:bold'>Status</th>"
            $dalarms_html += "    <th style='font-weight:bold'>Alarm</th>"
            $dalarms_html += "    <th style='font-weight:bold'>Alarm Name</th>"
            $dalarms_html += "    <th style='font-weight:bold'>Alarm Description</th>"
            $dalarms_html += "    <th style='font-weight:bold'>Hypervisor Manager</th>"
            $dalarms_html += ”`n <br />”

        # Populate Table

            if ($dalarms.count -eq 0) {
                $dalarms_html += "<tr>`n"
                $dalarms_html += "<td colspan='6'>No Datastore Alarms Found</td> `n"
                $dalarms_html += "</tr>`n"
            } else {
                foreach ($dalarm in $dalarms) {
                    $dalarms_html += "  <tr>`n"
                    $dalarms_html += "    <td>$($dalarm.dsname)</td>`n"
                    if ($dalarm.status -eq "red") {
                        $dalarms_html += "    <td bgcolor=#F88379>$($dalarm.status)</td>`n"
                    } elseif ($dalarm.status -eq "yellow") {
                        $dalarms_html += "    <td bgcolor=#F5F5DC>$($dalarm.status)</td>`n"
                    } else {
                        $dalarms_html += "    <td>$($dalarm.status)</td>`n"
                    }
                    $dalarms_html += "    <td>$($dalarm.alarm)</td>`n"
                    $dalarms_html += "    <td>$($dalarm.alarmname)</td>`n"
                    $dalarms_html += "    <td>$($dalarm.alarmdesc)</td>`n"
                    $dalarms_html += "    <td>$($dalarm.hvmgr)</td>`n"
                    $dalarms_html += "  </tr>`n"
                }
            }

        # HTML Table Close

            $dalarms_html += "</table>`n"

        # Spacing before next HTML section

            $dalarms_html += ”`n <br />”


#------------------------------------------------------[Disconnect vCenters]-------------------------------------------------------

    foreach ($vcenter in $vcenters) {
         Disconnect-VIServer -Server $vcenter -confirm:$False
    }

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
        $msg.Body+=”`n <br />”
        $msg.Body+=$unhstorage_html
        $msg.Body+=”`n <br />”
        $msg.Body+=$incompathw_html
        $msg.Body+=”`n <br />”
        $msg.Body+=$nicpwron_html
        $msg.Body+=”`n <br />”
        $msg.Body+=$vmgtools_html
        $msg.Body+=”`n <br />”
        $msg.Body+=$datastore_html
        $msg.Body+=”`n <br />”
        $msg.Body+=$mntdiso_html
        $msg.Body+=”`n <br />”
        $msg.Body+=$snapshots_html
        $msg.Body+=”`n <br />”
        $msg.Body+=$halarms_html
        $msg.Body+=”`n <br />”
        $msg.Body+=$dalarms_html


    # Send Message
            
        $smtp.Send($msg)
    
    # Debug Message Output

        write-output $msg | format-list

    # Destroy Message Object
    
        $msg.Dispose();

#---------------------------------------------------------[Logging  Stop]----------------------------------------------------------

    # Stop Log

        Stop-Transcript
