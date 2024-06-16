import yaml
import socket
import argparse
import os
import conjur_appliance
import asyncio
import asyncssh
import tracemalloc
import logging

tracemalloc.start()
DOCKER = "podman"
SSH_PORT = 22

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


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


async def remote_run_with_key(hostname, port, commands):
    """Run a command on a remote host with a private key."""
    # Read the private key
    private_key = await get_ssh_private_key()
    # Read the username
    username = await get_ssh_username()
    try:
        # Connect to the remote server using the SSH key
        async with asyncssh.connect(hostname, port=port, username=username,
                                    client_keys=[asyncssh.import_private_key(private_key)]) as conn:
            # Run the multiline command
            result = await conn.run(commands, check=True)

            # Collect the results
            output = result.stdout
            error = result.stderr

            # Print the output and error
            if output:
                print("Output:")
                print(output)

            if error:
                print("Error:")
                print(error)

    except (OSError, asyncssh.Error) as e:
        print(f"SSH connection failed: {e}")

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


def lookup_by_follower_hostname(yaml_file, hostname):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)

    if hostname in data:
        info = data[hostname]
        # print(f"Deployment info for host '{hostname}': {info}")
        host_info = {
            "type": "follower",
            "name": info["name"],
            "registry": ""
        }
        if "registry" in info:
            host_info["registry"] = info["registry"]
        return host_info
    else:
        print(f"No deployment information found for host '{hostname}'")
        return None


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


def read_leader_cluster_requirements(yaml_file):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)

    kind = data.get('kind')
    hostname = data.get('hostname')
    account_name = data.get('account_name')
    default_registry = data.get('default_registry')
    return kind, hostname, account_name, default_registry


def read_follower_requirements(yaml_file):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)

    kind = data.get('kind')
    hostname = data.get('hostname')
    account_name = data.get('account_name')
    default_registry = data.get('default_registry')
    return kind, hostname, account_name, default_registry


def read_follower_hostnames(yaml_file):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)

    # Extract all keys except known top-level keys
    known_keys = {'kind', 'hostname', 'account_name', 'default_registry'}
    hostnames = [key for key in data if key not in known_keys]

    return hostnames


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
        conjur_appliance.deploy_model(
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

        configure_leader_command = f"""{DOCKER} exec {host_attributes['name']} evoke configure leader --accept-eula --hostname {leader_vars['load_balancer_dns']} \
        --leader-altnames {leader_altnames} --admin-password {admin_password} {leader_vars['account_name']}"""

        if conjur_appliance.run_subprocess(configure_leader_command, shell=True).returncode == 0:
            logging.info(f"Leader cluster leader node deployment complete...Done")
        else:
            logging.error(f"Leader cluster leader node deployment complete...Failed")

    # check if deploying sync standby node
    if host_attributes['type'] == 'standby':
        logging.info(f"Deploying leader cluster for standby node ...")
        logging.info(f"Name: {host_attributes['name']}")
        logging.info(f"Type: {host_attributes['type']}")
        logging.info(f"Registry: {leader_vars['registry']}")
        conjur_appliance.deploy_model(
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
if [ -d "conjur-appliance" ]; then
    git -C conjur-appliance pull
else
    git clone https://github.com/GCLIM/conjur-appliance.git
fi
cd conjur-appliance
python3 -m pip install --user --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
{env_str} python3 conjur_orchestrator.py -o leader -i {yaml_file}
"""
        try:
            print_announcement_banner(f"Deploying leader cluster node: {hostname}")
            logging.info(f"Deploying leader cluster node: {hostname}")
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
    try:
        kind, hostname, account_name, default_registry = read_follower_requirements(yaml_file)
    except Exception as e:
        logging.error(f"Failed to read follower requirements from {yaml_file}: {e}")
        return

    if kind != 'follower':
        error_message = f"Invalid kind: {kind}, expects 'follower' for follower deployment"
        logging.error(error_message)
        return

    try:
        hostnames = read_follower_hostnames(yaml_file)
    except Exception as e:
        logging.error(f"Failed to read follower hostnames from {yaml_file}: {e}")
        return

    for node_name in hostnames:
        try:
            info = lookup_by_follower_hostname(yaml_file, node_name)
            if info is None:
                raise ValueError(f"No information found for hostname: {node_name}")

            if info['registry'] == "":
                info['registry'] = default_registry
        except Exception as e:
            logging.error(f"Failed to look up hostname {node_name}: {e}")
            continue  # Skip this hostname and proceed with the next one

        commands = f"""
if [ -d "conjur-appliance" ]; then
    git -C conjur-appliance pull
else
    git clone https://github.com/GCLIM/conjur-appliance.git
fi
cd conjur-appliance
python3 -m pip install --user --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
python3 conjur_appliance.py -m deploy -n {node_name} -t {info['type']} -reg {info['registry']}
"""
        try:
            print_announcement_banner(f"Deploying follower: {node_name}")
            asyncio.run(remote_run_with_key(node_name, port=SSH_PORT, commands=commands))
        except Exception as e:
            logging.error(f"Failed to deploy follower on hostname {node_name}: {e}")
            continue  # Skip this hostname and proceed with the next one

        logging.info(f"Follower deployment complete for node: {node_name}")

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
if [ -d "conjur-appliance" ]; then
    git -C conjur-appliance pull
else
    git clone https://github.com/GCLIM/conjur-appliance.git
fi
cd conjur-appliance
python3 -m pip install --user --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
python3 conjur_appliance.py -m retire
"""
        print_announcement_banner(f"Retiring leader cluster: {hostname}")
        asyncio.run(remote_run_with_key(hostname, port=SSH_PORT, commands=commands))

    print(f"Leader cluster retired.")


def retire_follower_model(yaml_file):
    kind, hostname, account_name, default_registry = read_leader_cluster_requirements(yaml_file)

    if kind != 'follower':
        print(f"Invalid kind: {kind}, expects 'follower' for follower retirement")
        exit(1)

    for node_name in read_follower_hostnames(yaml_file):
        info = lookup_by_follower_hostname(yaml_file, node_name)
        if info is None:
            exit(1)

        commands = f"""
if [ -d "conjur-appliance" ]; then
    git -C conjur-appliance pull
else
    git clone https://github.com/GCLIM/conjur-appliance.git
fi
cd conjur-appliance
python3 -m pip install --user --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
python3 conjur_appliance.py -m retire
"""
        print_announcement_banner(f"Retiring follower: {node_name}")
        asyncio.run(remote_run_with_key(node_name, port=SSH_PORT, commands=commands))
        print(f"Follower retired.")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Conjur deployment orchestrator",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=True)
    parser.add_argument("-d", "--deploy", type=str, help="leader: deploy leader cluster\nfollower: deploy follower")
    parser.add_argument("-o", "--orchestrator", type=str, help="leader: orchestrator leader cluster deployment")
    parser.add_argument("-r", "--retire", type=str, help="leader: retire leader cluster")
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
