import subprocess

import yaml
import socket
import argparse
import os
import conjur_appliance as appliance
import asyncio
import asyncssh
import tracemalloc
import logging
import re

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


def get_admin_password():
    """Fetch ADMIN_PASSWORD from environment variables."""
    key = os.getenv('ADMIN_PASSWORD')
    if not key:
        raise ValueError("ADMIN_PASSWORD environment variable not set.")
    return key


async def get_ssh_private_key():
    """Fetch the SSH private key from environment variables."""
    key = os.getenv('SSH_PRIVATE_KEY')
    if not key:
        raise ValueError("SSH_PRIVATE_KEY environment variable not set.")
    return key


async def get_ssh_username():
    """Fetch the SSH_USERNAME from environment variables."""
    key = os.getenv('SSH_USERNAME')
    if not key:
        raise ValueError("SSH_USERNAME environment variable not set.")
    return key


def mask_sensitive_info(command):
    """
    Masks sensitive information in a command string.
    """
    # Define patterns for various sensitive information
    patterns = [
        r'(env\s+ADMIN_PASSWORD=)([^\s]+)',                         # env ADMIN_PASSWORD=value
        r'(env\s+DB_PASSWORD=)([^\s]+)',                            # env DB_PASSWORD=value
        r'(export\s+[A-Z_]+PASSWORD=)([^\s]+)',                     # export DB_PASSWORD=value
        r'(--password\s+)(\S+)',                                    # --password value
        r'(--secret\s+)(\S+)',                                      # --secret value
        r'(-pass\s+)(\S+)',                                         # -pass value
        r'(\b(?:password|passwd|secret|api_key|token)\b\s*=\s*["\']?)([^\s"\'&;]+)', # password=value or password='value'
        r'(["\'])(password|secret|api_key|token)["\']?\s*=\s*(["\'])([^\3]+)(\3)',    # "password=value" or 'password=value'
    ]

    # Replace sensitive parts with masked value
    masked_command = command
    for pattern in patterns:
        masked_command = re.sub(pattern, lambda x: f'{x.group(1)}****', masked_command, flags=re.IGNORECASE)

    return masked_command

# async def remote_run_with_key(hostname, port, commands):
#     """Run a command on a remote host with a private key."""
#     # Read the private key
#     private_key = await get_ssh_private_key()
#     # Read the username
#     username = await get_ssh_username()

#     # for command in commands:
#     #     # Log the masked command
#     #     masked_command = mask_sensitive_info(command)
#     #     logging.info(f"Executing command: {masked_command}")

#     try:
#         # Connect to the remote server using the SSH key
#         async with asyncssh.connect(hostname, port=port, username=username,
#                                     client_keys=[asyncssh.import_private_key(private_key)]) as conn:
#             # Run the multiline command
#             result = await conn.run(commands, check=True)

#             # Print the output and error
#             if result.stdout:
#                 logging.info(f"Output:\n{result.stdout}")

#             if result.stderr:
#                 logging.error(f"Error:\n{result.stderr}")

#     except (OSError, asyncssh.Error) as e:
#         logging.error(f"SSH connection failed with exit status {e.returncode}: {e.cmd}")
#         logging.error(f"Standard output:\n{e.stdout}")
#         logging.error(f"Standard error:\n{e.stderr}")
#         raise  # Re-raise the exception to let the caller handle it

async def remote_run_with_key(hostname, port, commands):
    """Run commands on a remote host with a private key."""
    try:
        # Read the private key
        private_key = await get_ssh_private_key()
        # Read the username
        username = await get_ssh_username()

        # Log and execute each command individually if commands are a list
        if isinstance(commands, list):
            async with asyncssh.connect(hostname, port=port, username=username,
                                        client_keys=[asyncssh.import_private_key(private_key)]) as conn:
                for command in commands:
                    # Log the masked command
                    masked_command = mask_sensitive_info(command)
                    logging.info(f"Executing command: {masked_command}")
                    
                    # Execute the command
                    result = await conn.run(command, check=True)

                    # Print the output and error
                    if result.stdout:
                        logging.info(f"Output:\n{result.stdout}")
                    if result.stderr:
                        logging.error(f"Error:\n{result.stderr}")

        # If commands are a single string, execute it directly
        elif isinstance(commands, str):
            async with asyncssh.connect(hostname, port=port, username=username,
                                        client_keys=[asyncssh.import_private_key(private_key)]) as conn:
                # Log the masked command
                masked_command = mask_sensitive_info(commands)
                logging.info(f"Executing command: {masked_command}")
                
                # Execute the command
                result = await conn.run(commands, check=True)

                # Print the output and error
                if result.stdout:
                    logging.info(f"Output:\n{result.stdout}")
                if result.stderr:
                    logging.error(f"Error:\n{result.stderr}")

        else:
            logging.error("Commands should be a list of strings or a single string")

    except (OSError, asyncssh.Error) as e:
        # Log details safely, checking attribute existence
        logging.error(f"SSH connection failed: {str(e)}")
        if hasattr(e, 'returncode'):
            logging.error(f"Exit status: {e.returncode}")
        if hasattr(e, 'cmd'):
            logging.error(f"Command: {e.cmd}")
        if hasattr(e, 'stdout') and e.stdout:
            logging.error(f"Standard output:\n{e.stdout}")
        if hasattr(e, 'stderr') and e.stderr:
            logging.error(f"Standard error:\n{e.stderr}")
        raise  # Re-raise the exception to let the caller handle it

        
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
        username = await get_ssh_username()

        # Read the private keys
        dap_private_key = await get_ssh_private_key()
        standby_private_key = await get_ssh_private_key()

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
        admin_password = get_admin_password()

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
                appliance.import_ha_cluster_certificates(host_attributes['name'], leader_vars['master_key'], leader_vars['master_cert'])

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
                admin_password = get_admin_password()
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
            logging.info(f"Configuring standby node: {hostname} with container: {host_attributes['name']}")
            print_announcement_banner(f"Configuring standby node: {hostname} with container: {host_attributes['name']}")
            print("Standby node name:", hostname)
            print("Standby container name:", host_attributes['name'])
            logging.info(f"Step 1: Create and unpack the Standby seed files")
            try:
                asyncio.run(seed_and_unpack(leader_hostname, leader_container_name, hostname, host_attributes['name']))

                logging.info(f"Step 2: Configure the Standby")
                # Configure standby node using unencrypted master key
                configure_standby_command = f"{DOCKER} exec {host_attributes['name']} evoke configure standby"
                if asyncio.run(remote_run_with_key(hostname, port=SSH_PORT, commands=configure_standby_command)) == 0:
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


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Conjur deployment orchestrator",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=True)
    parser.add_argument("-d", "--deploy", type=str, help="leader: deploy leader cluster\nfollower: deploy followers")
    parser.add_argument("-o", "--orchestrator", type=str, help="leader: orchestrator leader cluster deployment")
    parser.add_argument("-r", "--retire", type=str, help="leader: retire leader cluster\nfollower: retire followers")
    parser.add_argument("-i", "--inventory", type=str, help="eg. inventories/dev.yml")
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
