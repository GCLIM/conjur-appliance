import yaml
import winrm
import re
import logging
import conjur_appliance
from conjur_orchestrator import get_value_from_vault, get_vars, print_announcement_banner

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


def get_vault_synchronizer_hostnames(yaml_file):
    # Read the YAML file
    with open(yaml_file, 'r') as file:
        yaml_dict = yaml.safe_load(file)

    # Initialize dictionaries to hold the hostnames
    vaultsync_hostnames = {
        'vaultsyncs': []
    }

    # Extract leader hostnames
    vaultsyncs_section = yaml_dict.get('vaultsyncs', {}).get('hosts', {})
    vaultsync_hostnames['vaultsyncs'] = list(vaultsyncs_section.keys())

    return vaultsync_hostnames


def winrm_remote_shell_ps_script(hostname, ps_script):
    # Create a WinRM session to the remote host using HTTPS and ignoring SSL certificate validation

    # get winrm username
    # username = get_winrm_username()
    username = get_value_from_vault("WINRM_USERNAME")

    # get winrm password
    # password = get_winrm_password()
    password = get_value_from_vault("WINRM_PASSWORD")

    # Log the masked command
    masked_command = conjur_appliance.mask_sensitive_info(ps_script)
    logging.info(f"Executing PS command: {masked_command}")

    try:
        session = winrm.Session(
            f'https://{hostname}:5986/wsman',
            auth=(username, password),
            server_cert_validation='ignore'  # Ignore SSL certificate validation
        )
        # Execute the command on the remote host
        result = session.run_ps(ps_script)

        # Print the output and error
        if hasattr(result, 'std_out'):
            logging.info(f"Output:\n{result.std_out.decode().strip()}")
        if hasattr(result, 'std_err'):
            if result.status_code == 0:
                logging.info(f"Output:\n{result.std_err.decode().strip()}")
            else:
                logging.error(f"Error:\n{result.std_err.decode().strip()}")

        # Check the output
        if result.status_code == 0:
            return result.std_out.decode().strip()
        else:
            return f"Error: {result.std_err.decode().strip()}"

    except winrm.exceptions.TransportError as e:

        logging.error(f"WinRM connection failed: {str(e)}")

        if hasattr(e, 'returncode'):
            logging.error(f"Exit status: {e.returncode}")

        if hasattr(e, 'cmd'):
            masked_cmd = conjur_appliance.mask_sensitive_info(e.cmd)
            logging.error(f"Command: {masked_cmd}")

        if hasattr(e, 'stdout') and e.stdout:
            logging.error(f"Standard output:\n{e.std_out.decode().strip()}")

        if hasattr(e, 'stderr') and e.stderr:
            logging.error(f"Standard error:\n{e.std_err.decode().strip()}")

        raise  # Re-raise the exception for higher-level handling


def check_dotnet_framework_48(hostname):
    # PowerShell command to check the .NET Framework 4.8 Release value
    ps_script = '''
    $ReleaseKey = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full" -Name Release
    if ($ReleaseKey.Release -ge 528040) {
        Write-Output "Installed"
    } else {
        Write-Output "Not Installed"
    }
    '''
    return winrm_remote_shell_ps_script(hostname, ps_script)


def check_FIPS_enabled(hostname):
    # PowerShell command to check if FIPS is enabled
    ps_script = '''
    if ((Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy").Enabled -eq 1) {
        Write-Output "Enabled"
    } else {
        Write-Output "Disabled"
    }
    '''
    return winrm_remote_shell_ps_script(hostname, ps_script)


def check_ms_visual_c_2022_x86(hostname):
    # PowerShell command to check for Microsoft Visual C++ 2022 x86 Redistributable packages
    ps_script = '''
    Get-ItemProperty -Path "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" |
    Where-Object { $_.DisplayName -like "Microsoft Visual C++ 2022*" } |
    Select-Object DisplayName, DisplayVersion
    '''

    # Execute the command
    result = winrm_remote_shell_ps_script(hostname, ps_script)

    # Define the pattern to search for
    pattern = r'Microsoft Visual C\+\+ 2022 X86'

    # Search for the pattern in the text
    matches = re.findall(pattern, result)
    if matches:
        return "Installed"
    else:
        return "Not Installed"


def remote_write_silent_ini_file(yaml_file, hostname):
    # get vault syncs vars
    vaultsyncs_vars = get_vars('vaultsyncs', yaml_file)
    # PowerShell command script to create the silent.ini file
    ps_script = f'''
$silentIniPath = "{vaultsyncs_vars['Sync_Package_Directory']}\\\silent.ini"

$newContent = @"
##############################################
### All the following values are mandatory ###
##############################################

[Main]

# Specify the target installation path for the Vault Synchronizer
InstallationTargetPath={vaultsyncs_vars['InstallationTargetPath']}

# Specify the URL of the PVWA, starting with https:// and excluding the full path
PVWAURL={vaultsyncs_vars['PVWAURL']}

# Specify Vault address. If the Vault has multiple addresses, list them separated by commas and without spaces
VaultAddress={vaultsyncs_vars['VaultAddress']}

# Specify Vault port (default=1858)
VaultPort={vaultsyncs_vars['VaultPort']}

# Specify Vault name (alias)
VaultName={vaultsyncs_vars['VaultName']}

# Specify the name of the Safe for storing accounts used to manage this Synchronizer
SyncSafeName={vaultsyncs_vars['SyncSafeName']}

# Enter the Conjur Enterprise hostname and port (port is optional) in the format of https://hostname[:port]
# Enter the Conjur Cloud API URL that you copied from the Conjur Cloud UI
ConjurServerDNS={vaultsyncs_vars['ConjurServerDNS']}

# Specify Conjur Enterprise account name
# For Conjur Cloud, this parameter is always set to 'conjur'
ConjurAccount={vaultsyncs_vars['ConjurAccount']}

# Specify the full path to the Conjur admin credentials file, created before the installation (only for PAS earlier than v11.4)
ConjurCredentialsFilePath={vaultsyncs_vars['ConjurCredentialsFilePath']}

# Specify LOB name (only for PAS v11.4 and later / Privilege Cloud)
LOBName={vaultsyncs_vars['LOBName']}

# Specify 'CyberArk Vault' platform used by the LOB account (only for PAS v11.4 and later / Privilege Cloud)
LOBPlatform={vaultsyncs_vars['LOBPlatform']}

# Specify if Synchronizer is running in multi-node mode (set false for Conjur Cloud integration!)
MultiNodeEnabled={vaultsyncs_vars['MultiNodeEnabled']}

# Specify Cluster key (keep empty for Conjur Cloud integration!)
ClusterKey={vaultsyncs_vars['ClusterKey']}

# Are you installing the Vault Synchronizer for Conjur Cloud (enter true/false)?
ConjurCloudSelected={vaultsyncs_vars['ConjurCloudSelected']}

# Enter the Vault Synchronizer credentials that you copied from the Conjur Cloud UI
ConjurCloudHostAndToken={vaultsyncs_vars['ConjurCloudHostAndToken']}
"@
# echo silentIni_File_Path: 
# echo $silentIniPath
# echo Write_to_silent_ini_file:
Set-Content -Path $silentIniPath -Value $newContent -Force
# Get-Content -Path $silentIniPath
'''
    result = winrm_remote_shell_ps_script(hostname, ps_script)
    return result


def remote_install_vault_synchronizer(yaml_file, hostname):
    # get vault syncs vars
    vaultsyncs_vars = get_vars('vaultsyncs', yaml_file)
    # Need to read from Password Vault
    vault_admin = get_value_from_vault("VAULT_ADMIN")
    vault_password = get_value_from_vault("VAULT_PASSWORD")
    conjur_admin_password = get_value_from_vault("CONJUR_ADMIN_PASSWORD")

    # PowerShell command script to create the PSCredential object
    ps_script = f'''
# Define the username as a plain text string
$vault_admin_username = "{vault_admin}"

# Define the password as a plain text string
$vault_admin_password = "{vault_password}"

# Convert the plain text password to a SecureString
$vault_securePassword = ConvertTo-SecureString -String $vault_admin_password -AsPlainText -Force

# Create the PSCredential object using the username and secure password
$PVWACredentials = New-Object System.Management.Automation.PSCredential ($vault_admin_username, $vault_securePassword)

# Output the credentials object to verify (for demonstration)
$PVWACredentials

# Define the username as a plain text string
$conjur_admin_username = "admin"

# Define the password as a plain text string
$conjur_admin_password = "{conjur_admin_password}"

# Convert the plain text password to a SecureString
$conjur_securePassword = ConvertTo-SecureString -String $conjur_admin_password -AsPlainText -Force

# Create the PSCredential object using the username and secure password
$conjurCredentials = New-Object System.Management.Automation.PSCredential ($conjur_admin_username, $conjur_securePassword)

# Output the credentials object to verify (for demonstration)
$conjurCredentials

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

cd {vaultsyncs_vars['Sync_Package_Directory']}

.\\V5SynchronizerInstallation.ps1 -silent -trustPVWAAndConjurCert
'''
    result = winrm_remote_shell_ps_script(hostname, ps_script)
    return result


def precheck_vault_synchronizer(hostname):
    result = "PASSED"

    if check_dotnet_framework_48(hostname) == "Installed":
        logging.info(".Net Framework 4.8 is installed.")
    else:
        logging.error(".Net Framework 4.8 is not installed.")
        result = "FAILED"

    if check_ms_visual_c_2022_x86(hostname) == "Installed":
        logging.info("Microsoft Visual C++ 2022 x86 Redistributable packages is installed.")
    else:
        logging.error("Microsoft Visual C++ 2022 x86 Redistributable packages is not installed.")
        result = "FAILED"

    if check_FIPS_enabled(hostname) == "Enabled":
        logging.info("FIPS is enabled.")
    else:
        logging.error("FIPS is not enabled.")
        result = "FAILED"

    return result


def deploy_vaultsync_model(yaml_file):
    """
    Deploys a vaultsync model based on the provided YAML file.

    Parameters:
    - yaml_file: the YAML file containing configuration information

    Returns:
    - None
    """
    # vaultsyncs_vars = get_vars('vaultsyncs', yaml_file)
    hostnames = get_vault_synchronizer_hostnames(yaml_file)
    # username = vaultsyncs_vars['ansible_user']
    # password = vaultsyncs_vars['ansible_password']

    for hostname in hostnames['vaultsyncs']:
        print_announcement_banner(f"Deploying Vault Synchronizer on {hostname}")
        logging.info("Precheck...")
        result = precheck_vault_synchronizer(hostname)
        if result == "PASSED":
            logging.info("Precheck...Passed")
            logging.info("Write Silent.ini for Vault Synchronizer...")
            result = remote_write_silent_ini_file(yaml_file, hostname)
            # print(result)
            logging.info("Install Vault Synchronizer...")
            result = remote_install_vault_synchronizer(yaml_file, hostname)
        else:
            logging.error("Precheck...Failed")
    return
