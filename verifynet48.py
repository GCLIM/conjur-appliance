import winrm
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests

# # Disable SSL warnings
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def check_dotnet_framework_48(host, username, password):
    try:
        # Create a WinRM session to the remote host using HTTPS and ignoring SSL certificate validation
        session = winrm.Session(
            f'https://{host}:5986/wsman',
            auth=(username, password),
            transport='ntlm',
            server_cert_validation='ignore'  # Ignore SSL certificate validation
        )
        
        # PowerShell command to check the .NET Framework 4.8 Release value
        ps_script = '''
        $ReleaseKey = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full" -Name Release
        if ($ReleaseKey.Release -ge 528040) {
            Write-Output "Installed"
        } else {
            Write-Output "Not Installed"
        }
        '''
        
        # Execute the command on the remote host
        result = session.run_ps(ps_script)
        
        # Check the output
        if result.status_code == 0:
            return result.std_out.decode().strip()
        else:
            return f"Error: {result.std_err.decode().strip()}"
    
    except Exception as e:
        return f"Exception: {str(e)}"

# Replace with your remote host details
host = "vaultsyn.gcloud101.com"
username = "Administrator"
password = "MySecretP@ss1"

# Check .NET Framework 4.8 installation
result = check_dotnet_framework_48(host, username, password)
print(result)
