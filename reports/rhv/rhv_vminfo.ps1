# Based off of:
# https://github.com/NowITSolutions/NIT-SPLAReporting/blob/b0583019f76072f125aa47f1642f486d26c9b084/Scripts/Get%20RedHat%20Hosts%20and%20VMs.ps1

$Datastore="c:\temp\rhv"
$today=$(get-date).tostring("dd/MM/yyyy")
$todayymd=(get-date).tostring("yyyyMMdd")
$hostdatafile_prefix="Hosts\RedHat-Hosts"
$hostdatafile="$Datastore\$hostdatafile_prefix-$todayymd.csv"
$vmdatafile_prefix="vms\RedHat-VMs"
$vmdatafile="$Datastore\$vmdatafile_prefix-$todayymd.csv"
$dcurl = read-host -prompt "RHV Hostname (dc4-rhvm.example.com)"

# Initialise arrays
$datacenters = @()
$clusters = @()
$hosts = @()
$vms = @()

if (Test-Path $hostdatafile) { Remove-Item $hostdatafile }
if (Test-Path $vmdatafile) { Remove-Item $vmdatafile }

# Setup RedHat auth

# Need to set the TLS level from 1.0 to 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ignore SSL Errors
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
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

# Open password vault
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vaultresource="redhat-query" # Be sure to store RedHat credentials in password vault with this resource name
$vault = New-Object Windows.Security.Credentials.PasswordVault
$username = ( $vault.RetrieveAll() | Where-Object { $_.Resource -eq $vaultresource } | Select-Object -First 1 ).UserName
$password = ( $vault.Retrieve( $vaultresource, $username ) | Select-Object -First 1 ).Password
$securepass = ConvertTo-SecureString -String $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($username, $securepass)

    # Fetch data
    $vmresults = invoke-restmethod -uri "https://$dcurl/ovirt-engine/api/vms" -credential $credential

    #Process VMs
    foreach($vm in $vmresults.vms.vm){
        $vms += New-Object -TypeName PSObject -Property @{ Date = $today;
        #$vms += [PSCustomObject] @{ Date = $today;
        href = $vm.href;
        id = $vm.id;
        name = $vm.name;
        dns_name = if($vm.fqdn) {$vm.fqdn} else {$vm.name};
        description = $vm.description;
        comment = $vm.comment;
        bios_boot_menu_enabled = $vm.bios.boot_menu.enabled;
        bios_type = $vm.bios.type;
        cpu_total = [int]$vm.cpu.topology.sockets * [int]$vm.cpu.topology.cores;
        cpu_architecture = $vm.cpu.architecture;
        cpu_topology_cores = $vm.cpu.topology.cores;
        cpu_topology_sockets = $vm.cpu.topology.sockets;
        cpu_topology_threads = $vm.cpu.topology.threads;
        cpu_shares = $vm.cpu_shares;
        creation_time = $vm.creation_time;
        delete_protected = $vm.delete_protected;
        display_address = $vm.display.address;
        display_allow_override = $vm.display.allow_override;
        display_copy_paste_enabled = $vm.display.copy_paste_enabled;
        display_disconnect_action = $vm.display.disconnect_action;
        display_file_transfer_enabled = $vm.display.file_transfer_enabled;
        display_monitors = $vm.display.monitors;
        display_port = $vm.display.port;
        display_secure_port = $vm.display.secure_port;
        display_smartcard_enabled = $vm.display.smartcard_enabled;
        display_type = $vm.display.type;
        high_availability_enabled = $vm.high_availability.enabled;
        high_availability_priority = $vm.high_availability.priority;
        io_threads = $vm.io.threads;
        memory_mb = [bigint]$vm.memory/(1024*1024);
        memory = $vm.memory;
        memory_policy_ballooning = $vm.memory_policy.ballooning;
        memory_policy_guaranteed = $vm.memory_policy.guaranteed;
        memory_policy_max = $vm.memory_policy.max;
        migration_auto_converge = $vm.migration.auto_converge;
        migration_compressed = $vm.migration.compressed;
        migration_encrypted = $vm.migration.encrypted;
        migration_downtime = $vm.migration_downtime;
        multi_queues_enabled = $vm.multi_queues_enabled;
        origin = $vm.origin;
        os_boot_devices_device = $vm.os.boot.devices.device;
        os_type = $vm.os.type;
        placement_policy_affinity = $vm.placement_policy.affinity;
        sso_methods_method_id = $vm.sso.methods.method.id;
        start_paused = $vm.start_paused;
        stateless = $vm.stateless;
        storage_error_resume_behaviour = $vm.storage_error_resume_behaviour;
        time_zone_name = $vm.time_zone.name;
        type = $vm.type;
        usb_enabled = $vm.usb.enabled;
        virtio_scsi_multi_queues_enabled = $vm.virtio_scsi_multi_queues_enabled;
        next_run_configuration_exists = $vm.next_run_configuration_exists;
        run_once = $vm.run_once;
        start_time = $vm.start_time;
        status = $vm.status;
        stop_time = $vm.stop_time;
        host = $(invoke-restmethod -uri "https://$($dcurl)$($vm.host.href)" -credential $credential).host.name;
        host_href = $vm.host.href;
        host_id = $vm.host.id;
        original_template = if ($original_template_id -ne $null) {$(invoke-restmethod -uri "https://$($dcurl)$($vm.original_template.href)" -credential $credential).template.name;};
        original_template_href = $vm.original_template.href;
        original_template_id = $vm.original_template.id;
        template = $(invoke-restmethod -uri "https://$($dcurl)$($vm.template.href)" -credential $credential).template.name;
        template_href = $vm.template.href;
        template_id = $vm.template.id;
        cluster = $(invoke-restmethod -uri "https://$($dcurl)$($vm.cluster.href)" -credential $credential).cluster.name;
        cluster_href = $vm.cluster.href;
        cluster_id = $vm.cluster.id;
        cpu_profile = $(invoke-restmethod -uri "https://$($dcurl)$($vm.cpu_profile.href)" -credential $credential).cpu_profile.name;
        cpu_profile_href = $vm.cpu_profile.href;
        cpu_profile_id = $vm.cpu_profile.id;
        quota_id = $vm.quota.id;        }
    }

    $vms | sort-object | export-csv C:\temp\rhv_vminfo_$dcurl_$todayymd.csv -NoTypeInformation