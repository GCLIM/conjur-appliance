import subprocess

import yaml
import socket
import argparse
import os
import conjur_appliance
import conjur_appliance as appliance
import asyncio
import asyncssh
import tracemalloc
import logging
import winrm
import hvac

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Set asyncssh's logging level to WARNING to suppress lower-level messages
logging.getLogger('asyncssh').setLevel(logging.WARNING)

tracemalloc.start()
DOCKER = "podman"
SSH_PORT = 22
repository = "https://github.com/GCLIM/conjur-appliance.git"
directory = "conjur-appliance"


def print_announcement_banner(message):
    """
    Prints an announcement banner with the provided message.

    Args:
        message (str): The message to be displayed in the banner.
    """
    # Determine the length of the message
    message_length = len(message)

    # Create the top and bottom border of the banner
    border = "+" + "-" * (message_length + 2) + "+"

    # Print the banner
    print(border)
    print("| " + message + " |")
    print(border)


def get_vault_credentials():
    """Fetch VAULT_URL from environment variables."""
    vault_url = os.getenv('VAULT_URL')
    if not vault_url:
        raise ValueError("VAULT_URL environment variable not set.")
    vault_api_key = os.getenv('VAULT_API_KEY')
    if not vault_api_key:
        raise ValueError("VAULT_API_KEY environment variable not set.")
    return vault_url, vault_api_key


def get_value_from_vault(key):
    # authenticate to Vault
    vault_url, vault_api_key = get_vault_credentials()
    vault_client = hvac.Client(
        url=vault_url,
        token=vault_api_key
    )

    read_response = vault_client.secrets.kv.v2.read_secret_version(
        raise_on_deleted_version=False,
        mount_point="kv",
        path="conjurorchestrator"
    )

    value = read_response["data"]["data"][key]
    return value


# def get_admin_password():
#     """Fetch ADMIN_PASSWORD from environment variables."""
#     key = os.getenv('ADMIN_PASSWORD')
#     if not key:
#         raise ValueError("ADMIN_PASSWORD environment variable not set.")
#     return key


# async def get_ssh_private_key():
#     """Fetch the SSH private key from environment variables."""
#     key = os.getenv('SSH_PRIVATE_KEY')
#     if not key:
#         raise ValueError("SSH_PRIVATE_KEY environment variable not set.")
#     return key


# async def get_ssh_username():
#     """Fetch the SSH_USERNAME from environment variables."""
#     key = os.getenv('SSH_USERNAME')
#     if not key:
#         raise ValueError("SSH_USERNAME environment variable not set.")
#     return key

# def get_winrm_username():
#     """Fetch the WINRM_USERNAME from environment variables."""
#     key = os.getenv('WINRM_USERNAME')
#     if not key:
#         raise ValueError("WINRM_USERNAME environment variable not set.")
#     return key


# def get_winrm_password():
#     """Fetch the WINRM_PASSWORD from environment variables."""
#     key = os.getenv('WINRM_PASSWORD')
#     if not key:
#         raise ValueError("WINRM_PASSWORD environment variable not set.")
#     return key


async def remote_run_with_key(hostname, port, commands):
    """Run a command on a remote host with a private key."""
    # Read the private key
    # private_key = await get_ssh_private_key()
    # # Read the username
    # username = await get_ssh_username()
    private_key = get_value_from_vault('SSH_KEY')
    username = get_value_from_vault('SSH_USERNAME')

    # Log the masked command
    masked_command = conjur_appliance.mask_sensitive_info(commands)
    logging.info(f"Executing command: {masked_command}")

    retry_attempts = 3
    for _ in range(retry_attempts):
        try:
            # Connect to the remote server using the SSH key
            async with asyncssh.connect(hostname, port=port, username=username,
                                        client_keys=[asyncssh.import_private_key(private_key)]) as conn:
                # Run the multiline command
                result = await conn.run(commands, check=True)

                # Print the output and error
                if result.stdout:
                    logging.info(f"Output:\n{result.stdout}")

                if result.returncode == 0:
                    logging.info(f"Output:\n{result.stderr}")
                else:
                    logging.error(f"Error:\n{result.stderr}")
            break

        except (OSError, asyncssh.Error) as e:
            logging.error(f"SSH connection failed: {str(e)}")
            if hasattr(e, 'returncode'):
                logging.error(f"Exit status: {e.returncode}")
            if hasattr(e, 'cmd'):
                masked_cmd = conjur_appliance.mask_sensitive_info(e.cmd)
                logging.error(f"Command: {masked_cmd}")
            if hasattr(e, 'stdout') and e.stdout:
                logging.error(f"Standard output:\n{e.stdout}")
            if hasattr(e, 'stderr') and e.stderr:
                logging.error(f"Standard error:\n{e.stderr}")
            print(f"Attempt {_ + 1} of {retry_attempts} failed. Retrying ...")


# async def remote_run_with_key(hostname, port, commands):
#     """Run commands on a remote host with a private key."""
#     try:
#         # Read the private key
#         private_key = await get_ssh_private_key()
#         # Read the username
#         username = await get_ssh_username()

#         # Log and execute each command individually if commands are a list
#         if isinstance(commands, list):
#             async with asyncssh.connect(hostname, port=port, username=username,
#                                         client_keys=[asyncssh.import_private_key(private_key)]) as conn:
#                 for command in commands:
#                     # Log the masked command
#                     masked_command = mask_sensitive_info(command)
#                     logging.info(f"Executing command: {masked_command}")

#                     # Execute the command
#                     result = await conn.run(command, check=True)

#                     # Print the output and error
#                     if result.stdout:
#                         logging.info(f"Output:\n{result.stdout}")
#                     if result.stderr:
#                         logging.error(f"Error:\n{result.stderr}")

#         # If commands are a single string, execute it directly
#         elif isinstance(commands, str):
#             async with asyncssh.connect(hostname, port=port, username=username,
#                                         client_keys=[asyncssh.import_private_key(private_key)]) as conn:
#                 # Log the masked command
#                 masked_command = mask_sensitive_info(commands)
#                 logging.info(f"Executing command: {masked_command}")

#                 # Execute the command
#                 result = await conn.run(commands, check=True)

#                 # Print the output and error
#                 if result.stdout:
#                     logging.info(f"Output:\n{result.stdout}")
#                 if result.stderr:
#                     logging.error(f"Error:\n{result.stderr}")

#         else:
#             logging.error("Commands should be a list of strings or a single string")

# except (OSError, asyncssh.Error) as e:
#     # Log details safely, checking attribute existence
#     logging.error(f"SSH connection failed: {str(e)}")
#     if hasattr(e, 'returncode'):
#         logging.error(f"Exit status: {e.returncode}")
#     if hasattr(e, 'cmd'):
#         logging.error(f"Command: {e.cmd}")
#     if hasattr(e, 'stdout') and e.stdout:
#         logging.error(f"Standard output:\n{e.stdout}")
#     if hasattr(e, 'stderr') and e.stderr:
#         logging.error(f"Standard error:\n{e.stderr}")
#     raise  # Re-raise the exception to let the caller handle it


# Function to find attributes for a given host name
def get_host_attributes(yaml_file, host_name):
    """
    A function to retrieve attributes for a given host name from a YAML file.

    Args:
    yaml_file (str): The path to the YAML file containing the host attributes.
    host_name (str): The name of the host to retrieve attributes for.

    Returns:
    dict or str: The attributes of the specified host if found, otherwise a message or None.
    """
    # Read the YAML file
    with open(yaml_file, 'r') as file:
        yaml_dict = yaml.safe_load(file)

    # Check each section in the YAML dictionary
    for section in yaml_dict.values():

        # Check if 'hosts' key exists in the section
        if 'hosts' in section:

            # Check if the host name is in the 'hosts' dictionary
            if host_name in section['hosts']:
                return section['hosts'][host_name]

    # If the host is not found, return a message or None
    return f"Host '{host_name}' not found in the YAML data."


def get_leader_hostname_containername(yaml_file):
    """
    A function to get the leader's hostname and container name from the YAML file.

    Args:
    yaml_file (str): The path to the YAML file.

    Returns:
    tuple: The leader's hostname and container name.
    """
    # Read the YAML file
    with open(yaml_file, 'r') as file:
        yaml_dict = yaml.safe_load(file)

    # Extract the leader's hosts section
    leader_section = yaml_dict.get('leader', {}).get('hosts', {})

    # Check if the leader_section is not empty
    if not leader_section:
        return None, None

    # Assuming there's only one leader hostname, get the first (and only) item
    leader_hostname = next(iter(leader_section))
    leader_details = leader_section[leader_hostname]

    # Extract leader name
    leader_name = leader_details.get('name', None)

    return leader_hostname, leader_name


# Function to get the variables for the leader
def get_leader_vars(yaml_file):
    """
    A function to get the variables for the leader from a YAML file.

    Args:
    yaml_file (str): The path to the YAML file containing the leader variables.

    Returns:
    dict: The variables for the leader.
    """
    # Read the YAML file
    with open(yaml_file, 'r') as file:
        yaml_dict = yaml.safe_load(file)

    # Access the 'leader' section in the YAML dictionary
    leader_section = yaml_dict.get('leader', {})

    # Extract the 'vars' sub-section
    leader_vars = leader_section.get('vars', {})

    # Return the leader vars
    return leader_vars


def get_followers_vars(yaml_file):
    """
    A function to get the variables for the followers from a YAML file.

    Args:
    - yaml_file (str): The path to the YAML file containing the follower variables.

    Returns:
    - dict: The variables for the followers.
    """
    # Read the YAML file
    with open(yaml_file, 'r') as file:
        yaml_dict = yaml.safe_load(file)

    # Access the 'followers' section in the YAML dictionary
    followers_section = yaml_dict.get('followers', {})

    # Extract the 'vars' sub-section
    followers_vars = followers_section.get('vars', {})

    # Return the leader vars
    return followers_vars


def get_vars(asset_group, yaml_file):
    """
    A function to get the variables for the asset group from a YAML file.

    Args:
    - asset_group (str): The name of the asset group.
    - yam_file (str): The path to the YAML file containing the asset group variables.

    Returns:
    - dict: The variables for the asset group.
    """
    # Read the YAML file
    with open(yaml_file, 'r') as file:
        yaml_dict = yaml.safe_load(file)

    # Access the 'followers' section in the YAML dictionary
    asset_group_section = yaml_dict.get(asset_group, {})

    # Extract the 'vars' sub-section
    asset_group_vars = asset_group_section.get('vars', {})

    # Return the leader vars
    return asset_group_vars


# Function to get hostnames for leader and standbys
def get_leader_cluster_hostnames(yaml_file):
    """
    A function to extract leader and standby hostnames from a YAML file.

    Args:
    yaml_file (str): The path to the YAML file containing the hostnames.

    Returns:
    dict: A dictionary containing two keys: 'leader' and 'standbys', each with a list of hostnames.
    """
    # Read the YAML file
    with open(yaml_file, 'r') as file:
        yaml_dict = yaml.safe_load(file)

    # Initialize dictionaries to hold the hostnames
    cluster_hostnames = {
        'leader': [],
        'standbys': []
    }

    # Extract leader hostnames
    leader_section = yaml_dict.get('leader', {}).get('hosts', {})
    cluster_hostnames['leader'] = list(leader_section.keys())

    # Extract standby hostnames
    standbys_section = yaml_dict.get('standbys', {}).get('hosts', {})
    cluster_hostnames['standbys'] = list(standbys_section.keys())

    return cluster_hostnames


def get_follower_hostnames(yaml_file):
    """
    A function to get follower hostnames from a YAML file.

    Args:
    - yaml_file (str): The path to the YAML file.

    Returns:
    - dict: A dictionary containing the list of follower hostnames under the 'followers' key.
    """
    # Read the YAML file
    with open(yaml_file, 'r') as file:
        yaml_dict = yaml.safe_load(file)

    # Initialize dictionaries to hold the hostnames
    follower_hostnames = {
        'followers': []
    }

    # Extract leader hostnames
    followers_section = yaml_dict.get('followers', {}).get('hosts', {})
    follower_hostnames['followers'] = list(followers_section.keys())

    return follower_hostnames


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


def resolve_current_hostname():
    """
    Retrieves the current hostname of the host machine.

    Returns:
        str: The current hostname.
    """
    try:
        hostname = socket.gethostname()
        print(f"The hostname of the current host is: {hostname}")
        return hostname
    except socket.error as e:
        print(f"Error: {e}")
        return None


async def seed_and_unpack(leader_hostname, leader_container_name, standby_hostname, standby_container_name):
    """
    Asynchronously seeds and unpacks files between the leader and standby nodes using SSH connections.

    Parameters:
        leader_hostname (str): The hostname of the leader node.
        leader_container_name (str): The container name of the leader node.
        standby_hostname (str): The hostname of the standby node.
        standby_container_name (str): The container name of the standby node.

    Returns:
        None
    """
    try:
        # Read username
        # username = await get_ssh_username()
        username = get_value_from_vault('SSH_USERNAME')

        # Read the private keys
        # dap_private_key = await get_ssh_private_key()
        # standby_private_key = await get_ssh_private_key()
        dap_private_key = get_value_from_vault('SSH_KEY')
        standby_private_key = get_value_from_vault('SSH_KEY')

        # Connect to the first server and run the seed command
        async with asyncssh.connect(leader_hostname, port=SSH_PORT, username=username,
                                    client_keys=[asyncssh.import_private_key(dap_private_key)]) as conn1:
            seed_command = f"{DOCKER} exec {leader_container_name} evoke seed standby {standby_hostname} {leader_hostname}"
            seed_result = await conn1.run(seed_command, check=True)
            seed_output = seed_result.stdout.strip()

            # Write seed output to a temporary file
            temp_seed_file = f'/tmp/seed_output_for_{standby_container_name}.txt'
            with open(temp_seed_file, 'w') as temp_file:
                temp_file.write(seed_output)

            # Transfer the temporary file to the standby node
            async with asyncssh.connect(standby_hostname, port=SSH_PORT, username=username,
                                        client_keys=[asyncssh.import_private_key(standby_private_key)]) as conn2:
                await asyncssh.scp(temp_seed_file, (conn2, temp_seed_file))

                # Run the unpack command using the transferred file
                unpack_command = f"{DOCKER} exec -i {standby_container_name} evoke unpack seed - < {temp_seed_file}"
                await conn2.run(unpack_command, check=True)

            # Write seed output to a temporary file with blank
            seed_output = ""
            temp_seed_file = f'/tmp/seed_output_for_{standby_container_name}.txt'
            with open(temp_seed_file, 'w') as temp_file:
                temp_file.write(seed_output)

            # Transfer the blank file to the standby node
            async with asyncssh.connect(standby_hostname, port=SSH_PORT, username=username,
                                        client_keys=[asyncssh.import_private_key(standby_private_key)]) as conn2:
                await asyncssh.scp(temp_seed_file, (conn2, temp_seed_file))

        logging.info("Seed and unpack process completed successfully.")


    except asyncssh.ProcessError as e:
        logging.error(f"Command execution failed: {e}")

    except (OSError, asyncssh.Error) as e:
        logging.error(f"SSH connection failed: {e}")


def file_exists(file_path):
    """
    Check if a file exists.

    :param file_path: The path to the file.
    :return: True if the file exists, False otherwise.
    """
    if not os.path.exists(file_path):
        logging.error(f"File does not exist: {file_path}")
        return False
    else:
        logging.info(f"File exists: {file_path}")
        return True


def leader_deployment_model(yaml_file):
    """
    Deploy the leader or standby cluster based on the host attributes and leader variables.

    :param yaml_file: The YAML file containing configuration details.
    :return: None
    """
    current_hostname = resolve_current_hostname()
    leader_vars = get_leader_vars(yaml_file)

    host_attributes = get_host_attributes(yaml_file, current_hostname)
    if host_attributes is None:
        logging.error(f"No deployment information found for host '{current_hostname}'")
        exit(1)

    # check if deploying leader node
    if host_attributes['type'] == 'leader':
        logging.info(f"Deploying leader cluster for leader node ...")
        logging.info(f"Name: {host_attributes['name']}")
        logging.info(f"Type: {host_attributes['type']}")
        logging.info(f"Registry: {leader_vars['registry']}")
        appliance.deploy_model(
            name=host_attributes['name'],
            type=host_attributes['type'],
            registry=leader_vars['registry']
        )
        logging.info(f"Leader cluster name: {leader_vars['load_balancer_dns']}")
        logging.info(f"Account name: {leader_vars['account_name']}")

        cluster_hostnames = get_leader_cluster_hostnames(yaml_file)
        all_hostnames = cluster_hostnames['leader'] + cluster_hostnames['standbys']
        leader_altnames = ",".join(all_hostnames)

        logging.info(f"Leader cluster nodes: {leader_altnames}")
        admin_password = get_value_from_vault('CONJUR_ADMIN_PASSWORD')

        configure_leader_command = f"""{DOCKER} exec {host_attributes['name']} evoke configure leader --accept-eula --hostname {leader_vars['load_balancer_dns']} --leader-altnames {leader_altnames} --admin-password {admin_password} {leader_vars['account_name']}"""

        try:
            appliance.run_subprocess(configure_leader_command, shell=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Subprocess failed: {e}")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")

        # if appliance.run_subprocess(configure_leader_command, shell=True) == 0:
        #     logging.info(f"Leader cluster leader node deployment complete...Done")
        # else:
        #     logging.error(f"Leader cluster leader node deployment complete...Failed")

        # check if ca-chain exit, import CA root certificate
        if file_exists(leader_vars['ca_chain']):
            appliance.import_root_certificate(host_attributes['name'], leader_vars['ca_chain'])

            # check if master key and master cert exit, import certificates
            if file_exists(leader_vars['master_key']) and file_exists(leader_vars['master_cert']):
                appliance.import_ha_cluster_certificates(host_attributes['name'], leader_vars['master_key'],
                                                         leader_vars['master_cert'])

            # restart conjur services
            appliance.restart_conjur_services(host_attributes['name'])

    # check if deploying sync standby node
    if host_attributes['type'] == 'standby':
        logging.info(f"Deploying leader cluster for standby node ...")
        logging.info(f"Name: {host_attributes['name']}")
        logging.info(f"Type: {host_attributes['type']}")
        logging.info(f"Registry: {leader_vars['registry']}")
        appliance.deploy_model(
            name=host_attributes['name'],
            type=host_attributes['type'],
            registry=leader_vars['registry']
        )

    return


def deploy_leader_cluster_model(yaml_file):
    """
    Deploys a leader cluster model based on the provided YAML file.

    Parameters:
    - yaml_file: the YAML file containing configuration information

    Returns:
    - None
    """
    try:
        leader_vars = get_leader_vars(yaml_file)
    except Exception as e:
        logging.error(f"Failed to read leader cluster variables from {yaml_file}: {e}")
        exit(1)

    try:
        cluster_hostnames = get_leader_cluster_hostnames(yaml_file)
    except Exception as e:
        logging.error(f"Failed to read leader cluster hostnames from {yaml_file}: {e}")
        exit(1)

    leader_hostname, leader_container_name = get_leader_hostname_containername(yaml_file)

    for hostname in (cluster_hostnames['leader'] + cluster_hostnames['standbys']):
        env_str = ""
        try:
            host_attributes = get_host_attributes(yaml_file, hostname)
            if host_attributes is None:
                raise ValueError(f"No information found for hostname: {hostname}")
            if host_attributes['type'] == 'leader':
                leader_node_name = hostname
                leader_container_name = host_attributes['name']
                admin_password = get_value_from_vault('CONJUR_ADMIN_PASSWORD')
                env_vars = f'ADMIN_PASSWORD={admin_password}'
                env_str = f"env {env_vars} "
        except Exception as e:
            logging.error(f"Failed to look up hostname {hostname}: {e}")
            continue  # Skip this hostname and proceed with the next one

        commands = f"""
if [ -d "{directory}" ]; then
    git -C {directory} pull
else
    git clone {repository}
fi
cd {directory}
python3 -m pip install --user --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
{env_str} python3 conjur_orchestrator.py -o leader -i {yaml_file}
"""
        print_announcement_banner(f"Deploying leader cluster node: {hostname}")
        logging.info(f"Deploying leader cluster node: {hostname}")
        try:
            asyncio.run(remote_run_with_key(hostname, port=SSH_PORT, commands=commands))
        except Exception as e:
            logging.error(f"Failed to deploy leader cluster on hostname {hostname}: {e}")
            continue  # Skip this hostname and proceed with the next one

    # configure standby nodes
    for hostname in cluster_hostnames['standbys']:
        try:
            host_attributes = get_host_attributes(yaml_file, hostname)
            if host_attributes is None:
                raise ValueError(f"No information found for hostname: {hostname}")
        except Exception as e:
            logging.error(f"Failed to look up hostname {hostname}: {e}")
            continue  # Skip this hostname and proceed with the next one
        if host_attributes['type'] == 'standby':
            print_announcement_banner(f"Configuring standby node: {hostname} with container: {host_attributes['name']}")
            logging.info(f"Step 0: Create and unpack the standby seed files")
            # Create and unpack seed files
            print("Standby node name:", hostname)
            logging.info(f"Configuring standby node: {hostname} with container: {host_attributes['name']}")
            print("Standby node name:", hostname)
            print("Standby container name:", host_attributes['name'])
            logging.info(f"Step 1: Create and unpack the Standby seed files")
            try:
                asyncio.run(seed_and_unpack(leader_hostname, leader_container_name, hostname, host_attributes['name']))
            except Exception as e:
                logging.error(f"Failed to configure standby node {hostname}: {e}")
                continue  # Skip this hostname and proceed with the next one

            # Configure standby node using unencrypted master key
            logging.info(f"Step 2: Configure the Standby")
            configure_standby_command = f"{DOCKER} exec {host_attributes['name']} evoke configure standby"
            try:
                asyncio.run(remote_run_with_key(hostname, port=SSH_PORT, commands=configure_standby_command))
                logging.info(f"Standby node {hostname} configured.")
            except Exception as e:
                logging.error(f"Failed to configure standby node {hostname}: {e}")
                continue  # Skip this hostname and proceed with the next one

    # enable synchronous replication
    print_announcement_banner("Enabling synchronous replication")
    logging.info("Step 3: Enable synchronous replication")
    try:
        sync_start_command = f"{DOCKER} exec {leader_container_name} sh -c 'evoke replication sync start'"
        asyncio.run(remote_run_with_key(leader_hostname, port=SSH_PORT, commands=sync_start_command))
        logging.info(f"Leader cluster synchronous replication enabled successfully.")

    except Exception as e:
        logging.error(f"Failed to enable synchronous replication: {e}")


def deploy_follower_model(yaml_file):
    """
    Deploys a follower model based on the provided YAML file.

    Parameters:
    - yaml_file: the YAML file containing configuration information

    Returns:
    - None
    """
    try:
        followers_vars = get_followers_vars(yaml_file)
    except Exception as e:
        logging.error(f"Failed to read follower variables from {yaml_file}: {e}")
        exit(1)

    try:
        hostnames = get_follower_hostnames(yaml_file)
    except Exception as e:
        logging.error(f"Failed to read follower hostnames from {yaml_file}: {e}")
        return

    for hostname in hostnames['followers']:
        try:
            host_attributes = get_host_attributes(yaml_file, hostname)
            if host_attributes is None:
                raise ValueError(f"No information found for hostname: {hostname}")

        except Exception as e:
            logging.error(f"Failed to look up hostname {hostname}: {e}")
            continue  # Skip this hostname and proceed with the next one

        commands = f"""
if [ -d "{directory}" ]; then
    git -C {directory} pull
else
    git clone {repository}
fi
cd {directory}
python3 -m pip install --user --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
python3 conjur_appliance.py -m deploy -n {host_attributes['name']} -t {host_attributes['type']} -reg {followers_vars['registry']}
"""
        try:
            print_announcement_banner(f"Deploying follower: {hostname}")
            asyncio.run(remote_run_with_key(hostname, port=SSH_PORT, commands=commands))
        except Exception as e:
            logging.error(f"Failed to deploy follower on hostname {hostname}: {e}")
            continue  # Skip this hostname and proceed with the next one

        logging.info(f"Follower deployment complete for node: {hostname}")

    logging.info("Follower model deployment complete.")


def retire_leader_cluster_model(yaml_file):
    """
    Retires the leader cluster model based on the provided YAML file.

    Parameters:
    - yaml_file: the YAML file containing configuration information

    Returns:
    - None
    """
    try:
        cluster_hostnames = get_leader_cluster_hostnames(yaml_file)

        # Combine leader and standby hostnames into a single list
        all_hostnames = cluster_hostnames['leader'] + cluster_hostnames['standbys']

    except Exception as e:
        logging.error(f"Failed to read leader cluster hostnames from {yaml_file}: {e}")
        exit(1)

    for hostname in all_hostnames:
        commands = f"""
if [ -d "{directory}" ]; then
    git -C {directory} pull
else
    git clone {repository}
fi
cd {directory}
python3 -m pip install --user --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
python3 conjur_appliance.py -m retire
"""
        print_announcement_banner(f"Retiring leader cluster: {hostname}")
        asyncio.run(remote_run_with_key(hostname, port=SSH_PORT, commands=commands))

    print(f"Leader cluster retired.")


def retire_follower_model(yaml_file):
    """
    Deploys a follower model based on the provided YAML file.

    Parameters:
    - yaml_file: the YAML file containing configuration information

    Returns:
    - None
    """
    try:
        follower_hostnames = get_follower_hostnames(yaml_file)

    except Exception as e:
        logging.error(f"Failed to read follower hostnames from {yaml_file}: {e}")
        exit(1)

    for hostname in follower_hostnames['followers']:
        host_attributes = get_host_attributes(yaml_file, hostname)
        if host_attributes is None:
            exit(1)

        commands = f"""
if [ -d "{directory}" ]; then
    git -C {directory} pull
else
    git clone {repository}
fi
cd {directory}
python3 -m pip install --user --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
python3 conjur_appliance.py -m retire
"""
        print_announcement_banner(f"Retiring follower: {hostname}")
        asyncio.run(remote_run_with_key(hostname, port=SSH_PORT, commands=commands))
        print(f"Follower retired.")


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


def c(hostname):
    # PowerShell command to check for Microsoft Visual C++ 2022 x86 Redistributable packages
    ps_script = '''
    Get-ItemProperty -Path "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" |
    Where-Object { $_.DisplayName -like "Microsoft Visual C++ 2022*" } |
    Select-Object DisplayName, DisplayVersion
    '''

    # Execute the command
    result = winrm_remote_shell_ps_script(hostname, ps_script)

    # Check the result
    if result.status_code == 0:
        output = result.std_out.decode('utf-8').strip()
        if output:
            return "Installed"
        else:
            return "Not Installed"
    else:
        print(f"Failed to execute the command. Error: {result.std_err.decode('utf-8').strip()}")
        raise ValueError("Failed to execute the command.")


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
        logging.info("Installed Microsoft Visual C++ 2022 x86 Redistributable packages is installed.")
    else:
        logging.error("No Microsoft Visual C++ 2022 x86 Redistributable packages found.")
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
    vaultsyncs_vars = get_vars('vaultsyncs', yaml_file)
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


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Conjur deployment orchestrator",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=True)
    parser.add_argument("-d", "--deploy", type=str,
                        help="leader: deploy leader cluster\nfollower: deploy followers\nvaultsync: deploy vault ynchronizer")
    parser.add_argument("-o", "--orchestrator", type=str, help="leader: orchestrator leader cluster deployment")
    parser.add_argument("-r", "--retire", type=str, help="leader: retire leader cluster\nfollower: retire followers")
    parser.add_argument("-i", "--inventory", type=str, help="eg. inventories/dev.yml")
    parser.add_argument("-health", "--health", type=str, help="leader: fetch health report")
    args = parser.parse_args()

    # Check if no arguments are provided, then print help
    if not any(vars(args).values()):
        parser.print_help()

    if args.deploy in ["leader"]:
        # check if inventory exist for arg.inventory
        if not args.inventory:
            parser.print_help()
            print("Error: -i, --inventory cannot be empty.")
            exit(1)
        # check if inventory exist on the disk
        if not os.path.exists(args.inventory):
            print(f"Error: {args.inventory} does not exist.")
            exit(1)
        deploy_leader_cluster_model(args.inventory)

    if args.orchestrator in ["leader"]:
        # check if inventory exist for arg.inventory
        if not args.inventory:
            parser.print_help()
            print("Error: -i, --inventory cannot be empty.")
            exit(1)
        # check if inventory exist on the disk
        if not os.path.exists(args.inventory):
            print(f"Error: {args.inventory} does not exist.")
            exit(1)
        leader_deployment_model(args.inventory)

    if args.retire in ["leader"]:
        # check if inventory exist for arg.inventory
        if not args.inventory:
            parser.print_help()
            print("Error: -i, --inventory cannot be empty.")
            exit(1)
        # check if inventory exist on the disk
        if not os.path.exists(args.inventory):
            print(f"Error: {args.inventory} does not exist.")
            exit(1)
        retire_leader_cluster_model(args.inventory)

    if args.deploy in ["follower"]:
        # check if inventory exist for arg.inventory
        if not args.inventory:
            parser.print_help()
            print("Error: -i, --inventory cannot be empty.")
            exit(1)
        # check if inventory exist on the disk
        if not os.path.exists(args.inventory):
            print(f"Error: {args.inventory} does not exist.")
            exit(1)
        deploy_follower_model(args.inventory)

    if args.deploy in ["vaultsync"]:
        # check if inventory exist for arg.inventory
        if not args.inventory:
            parser.print_help()
            print("Error: -i, --inventory cannot be empty.")
            exit(1)
        # check if inventory exist on the disk
        if not os.path.exists(args.inventory):
            print(f"Error: {args.inventory} does not exist.")
            exit(1)
        deploy_vaultsync_model(args.inventory)

    if args.retire in ["follower"]:
        # check if inventory exist for arg.inventory
        if not args.inventory:
            parser.print_help()
            print("Error: -i, --inventory cannot be empty.")
            exit(1)
        # check if inventory exist on the disk
        if not os.path.exists(args.inventory):
            print(f"Error: {args.inventory} does not exist.")
            exit(1)
        retire_follower_model(args.inventory)

    if args.health in ["leader"]:
        # URL to fetch the health data from
        health_check_url = "http://conjur01.gcloud101.com:444/health"
        # Fetch and analyze the health data
        conjur_appliance.fetch_and_analyze_health(health_check_url)
