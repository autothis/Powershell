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

        $vcenters = @(
            "dc3-vcsa01.nowitsolutions.com.au",
            "dc4-vcsa01.nowitsolutions.com.au"
            )

        $rhvmgrs = @(
            "qld-ndb2-vm-02.mgmt.spirit.net.au",
            "dc4-rhvm01.nowitsolutions.com.au"
            )

    # SMTP Settings
    
        $smtpServer = “smtp1.nowitsolutions.com.au”
        $smtp = New-Object Net.Mail.SmtpClient($SmtpServer, 25)
        $msgfrom = "hypervisors@example.com"
        #$msgto = "user@example.com"
        $msgto = "jperry@nowitsolutions.com.au"
    
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

    # VCSA

        $vmhosts = get-vmhost
        foreach ($vmhost in $vmhosts) {
            $luns = get-vmhost $vmhost | Get-ScsiLun -LunType disk | where {$_.ExtensionData.OperationalState -ne "ok"}
            foreach ($lun in $luns) {
                $unhstorage += New-Object -TypeName PSObject -Property @{
                    host = $vmhost.name;
                    vendor = $lun.vendor;
                    state = $lun.extensiondata.operationalstate;
                    name = $lun.canonicalname;
                    capacitygb = $lun.capacitygb;
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
            $unhstorage_html += "<th style='font-weight:bold'>Hypervisor</th>"

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

    # VCSA

    $vms = get-vm
    
    foreach ($vm in $vms) {
        $vmdevices = $vm.ExtensionData.Config.Hardware.Device | where {$_.GetType().Name}
    
        if ($vmdevices -match 'VirtualHdAudioCard') {
            $incompathw += New-Object -TypeName PSObject -Property @{
                vm = $vm.name;
                powerstate = $lun.vendor;
                device = "VirtualHdAudioCard";
                hypervisormgr = $vm.Uid.Substring($vm.Uid.IndexOf('@')+1).Split(":")[0];
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
                    $incompathw_html += "<td colspan='4'>No VMs with Incompatible Audio Hardware</td> `n"
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

    # VMware Commands

        $vms = get-vm
        
        foreach ($vm in $vms) {
            $nics = $vm | Get-NetworkAdapter
            foreach ($nic in $nics) {
                write-host "$nic"
                if($Nic.ConnectionState.Connected -eq $true -and $nic.ConnectionState.StartConnected -eq $false) {
                $nicpwronresult += New-Object -TypeName PSObject -Property @{
                    vmname = $nic.Parent;
                    nicname = $nic.Name;
                    networkname = $nic.NetworkName;
                    nictype = $nic.Type;
                    nicmac = $nic.MacAddress;
                    niccon = $nic.ConnectionState.Connected;
                    nicpwrcon = $nic.ConnectionState.StartConnected;
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

        # Populate Table

            foreach ($nicpwronres in $nicpwronresult) {
                $nicpwron_html += "  <tr>`n"
                $nicpwron_html += "    <td>$($nicpwronres.vmname)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.nicname)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.networkname)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.nictype)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.nicmac)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.niccon)</td>`n"
                $nicpwron_html += "    <td>$($nicpwronres.nicpwrcon)</td>`n"
                $nicpwron_html += "  </tr>`n"
            }

        # Close HTML Table

            $nicpwron_html += "</table>`n"

        # Spacing before next HTML section

            $nicpwron_html += ”`n <br />”

#-----------------------------------------------------[VM Guest Tool Issues]-------------------------------------------------------

    # VMware
    
        $vms = get-vm | where {$_.PowerState -ne "PoweredOff" -and $_.extensiondata.Guest.toolsstatus -ne "toolsok"}

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
            $vmgtools_html += "    <th style='font-weight:bold'></th>"

        # Populate Table

            foreach ($vmguesttool in $vmguesttools) {
                $vmgtools_html += "  <tr>`n"
                $vmgtools_html += "    <td>$($vmguesttool.vmname)</td>`n"
                $vmgtools_html += "    <td>$($vmguesttool.toolsstatus)</td>`n"
                $vmgtools_html += "    <td>$($vmguesttool.toolsversion)</td>`n"
                $vmgtools_html += "    <td>$($vmguesttool.toolsrunning)</td>`n"
                $vmgtools_html += "    <td>$($vmguesttool.toolsversionno)</td>`n"
                $vmgtools_html += "  </tr>`n"
            }

        # HTML Table Close

            $vmgtools += "</table>`n"

#-----------------------------------------------------[Create and Send Email]------------------------------------------------------

    # Create New Message Object

        $msg = new-object Net.Mail.MailMessage
       
    # Message Subject
        
        $msg.Subject = “VMware Report”
    
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

    # Send Message
            
        $smtp.Send($msg)
    
    # Debug Message Output

        echo $msg | fl

    # Destroy Message Object
    
        $msg.Dispose();

#---------------------------------------------------------[Logging  Stop]----------------------------------------------------------

    # Stop Log

        Stop-Transcript
