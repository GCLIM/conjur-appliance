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

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


def print_announcement_banner(message):
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


def lookup_by_leader_hostname(yaml_file, hostname):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)

    if hostname in data:
        info = data[hostname]
        # print(f"Deployment info for host '{hostname}': {info}")
        host_info = {
            "type": info["type"],
            "name": info["name"],
            "registry": ""
        }
        if "registry" in info:
            host_info["registry"] = info["registry"]
        return host_info
    else:
        print(f"No deployment information found for host '{hostname}'")
        return None


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


def read_leader_cluster_hostnames(yaml_file):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)

    # Extract all keys except known top-level keys
    known_keys = {'kind', 'hostname', 'account_name', 'default_registry'}
    hostnames = [key for key in data if key not in known_keys]

    return hostnames


def read_follower_hostnames(yaml_file):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)

    # Extract all keys except known top-level keys
    known_keys = {'kind', 'hostname', 'account_name', 'default_registry'}
    hostnames = [key for key in data if key not in known_keys]

    return hostnames


def leader_deployment_model(yaml_file):
    current_hostname = resolve_current_hostname()
    kind, hostname, account_name, default_registry = read_leader_cluster_requirements(yaml_file)

    if kind != 'leader-cluster':
        print(f"Invalid kind: {kind}, expects 'leader-cluster' for leader cluster deployment")
        exit(1)

    info = lookup_by_leader_hostname(yaml_file, current_hostname)
    if info is None:
        logging.error(f"No deployment information found for host '{current_hostname}'")
        exit(1)

    if info['registry'] == "":
        info['registry'] = default_registry

    # check if deploying leader node
    if info['type'] == 'leader':
        print(f"Deploying leader cluster for leader node ...")
        print(f"Name: {info['name']}")
        print(f"Type: {info['type']}")
        print(f"Registry: {info['registry']}")
        conjur_appliance.deploy_model(
            name=info["name"],
            type=info["type"],
            registry=info["registry"]
        )
        print(f"Leader cluster name: {hostname}")
        print(f"Account name: {account_name}")
        print(f"Leader cluster nodes: {read_leader_cluster_hostnames(yaml_file)}")
        leader_altnames = ','.join(read_leader_cluster_hostnames(yaml_file))
        admin_password = get_admin_password()
        print(f"Admin password: {admin_password}")
        command = f"""
{DOCKER} exec {info['name']} evoke configure leader --accept-eula --hostname {hostname} \
--leader-altnames {leader_altnames} --admin-password {admin_password} {account_name}"""
        if conjur_appliance.run_subprocess(command, shell=True).returncode == 0:
            print(f"Leader cluster leader node deployment complete...Done")
        else:
            print(f"Leader cluster leader node deployment complete...Failed")

    # check if deploying sync standy node
    if info['type'] == 'standby':
        print(f"Deploying leader cluster for standby node ...")
        print(f"Name: {info['name']}")
        print(f"Type: {info['type']}")
        print(f"Registry: {info['registry']}")
        conjur_appliance.deploy_model(
            name=info["name"],
            type=info["type"],
            registry=info["registry"]
        )
        print(f"Leader cluster standby node deployment complete.")
    return


async def seed_and_unpack(leader_node_name, leader_container_name, standby_node_name, standby_container_name):
    try:
        # Read username
        username = await get_ssh_username()

        # Read the private keys
        dap_private_key = await get_ssh_private_key()
        standby_private_key = await get_ssh_private_key()

        # Connect to the first server and run the seed command
        async with asyncssh.connect(leader_node_name, username=username, client_keys=[dap_private_key]) as conn1:
            seed_command = f"{DOCKER} exec {leader_container_name} evoke seed standby standby_node_name leader_node_name"
            seed_result = await conn1.run(seed_command, check=True)
            seed_output = seed_result.stdout.strip()

            # Connect to the second server and run the unpack command with the seed output
            async with asyncssh.connect(standby_node_name, username=username, client_keys=[standby_private_key]) as conn2:
                unpack_command = f"{DOCKER} exec -i standby_container_name evoke unpack seed - <<EOF\n{seed_output}\nEOF"
                await conn2.run(unpack_command, check=True)

        print("Seed and unpack process completed successfully.")

    except (OSError, asyncssh.Error) as e:
        print(f"SSH connection or command execution failed: {e}")


def deploy_leader_cluster_model(yaml_file):
    try:
        kind, hostname, account_name, default_registry = read_leader_cluster_requirements(yaml_file)
    except Exception as e:
        logging.error(f"Failed to read leader cluster requirements from {yaml_file}: {e}")
        return

    if kind != 'leader-cluster':
        error_message = f"Invalid kind: {kind}, expects 'leader-cluster' for leader cluster deployment"
        logging.error(error_message)
        return

    try:
        node_names = read_leader_cluster_hostnames(yaml_file)
    except Exception as e:
        logging.error(f"Failed to read leader cluster hostnames from {yaml_file}: {e}")
        return

    leader_node_name = ""
    leader_container_name = ""
    for node_name in node_names:
        try:
            info = lookup_by_leader_hostname(yaml_file, node_name)
            if info is None:
                raise ValueError(f"No information found for hostname: {node_name}")
            if info['type'] == 'leader':
                leader_node_name = node_name
                leader_container_name = info['name']
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
python3 conjur_orchestrator.py -o leader -f env/dev/leader_cluster.yml
"""
        try:
            print_announcement_banner(f"Deploying leader cluster node: {node_name}")
            asyncio.run(remote_run_with_key(node_name, port=22, commands=commands))
        except Exception as e:
            logging.error(f"Failed to deploy leader cluster on hostname {node_name}: {e}")
            continue  # Skip this hostname and proceed with the next one

    # configure standby nodes
    for node_name in node_names:
        try:
            info = lookup_by_leader_hostname(yaml_file, node_name)
            if info is None:
                raise ValueError(f"No information found for hostname: {node_name}")
        except Exception as e:
            logging.error(f"Failed to look up hostname {node_name}: {e}")
            continue  # Skip this hostname and proceed with the next one
        if info['type'] == 'standby':
            print_announcement_banner(f"Configuring standby node: {node_name}")
            try:
                asyncio.run(seed_and_unpack(leader_node_name, leader_container_name, node_name, info['name']))
            except Exception as e:
                logging.error(f"Failed to configure standby node {node_name}: {e}")
                continue  # Skip this hostname and proceed with the next one
            print(f"Standby node {node_name} configured.")

    logging.info(f"Leader cluster deployment complete.")


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
            asyncio.run(remote_run_with_key(node_name, port=22, commands=commands))
        except Exception as e:
            logging.error(f"Failed to deploy follower on hostname {node_name}: {e}")
            continue  # Skip this hostname and proceed with the next one

        logging.info(f"Follower deployment complete for node: {node_name}")

    logging.info("Follower model deployment complete.")


def retire_leader_cluster_model(yaml_file):
    kind, hostname, account_name, default_registry = read_leader_cluster_requirements(yaml_file)

    if kind != 'leader-cluster':
        print(f"Invalid kind: {kind}, expects 'leader-cluster' for leader retirement")
        exit(1)

    for node_name in read_leader_cluster_hostnames(yaml_file):
        info = lookup_by_leader_hostname(yaml_file, node_name)
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
        print_announcement_banner(f"Retiring leader cluster: {node_name}")
        asyncio.run(remote_run_with_key(node_name, port=22, commands=commands))

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
        asyncio.run(remote_run_with_key(node_name, port=22, commands=commands))
        print(f"Follower retired.")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Conjur deployment orchestrator",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=True)
    parser.add_argument("-d", "--deploy", type=str, help="leader: deploy leader cluster\nfollower: deploy follower")
    parser.add_argument("-o", "--orchestrator", type=str, help="leader: orchestrator leader cluster deployment")
    parser.add_argument("-r", "--retire", type=str, help="leader: retire leader cluster")
    parser.add_argument("-f", "--file", type=str, help="eg. env/dev/leader-cluster.yml")
    args = parser.parse_args()

    # Check if no arguments are provided, then print help
    if not any(vars(args).values()):
        parser.print_help()

    if args.deploy in ["leader"]:
        # check if file exist for arg.file
        if not args.file:
            parser.print_help()
            print("Error: -f, --file cannot be empty.")
            exit(1)
        # check if file exist on the disk
        if not os.path.exists(args.file):
            print(f"Error: {args.file} does not exist.")
            exit(1)
        deploy_leader_cluster_model(args.file)

    if args.orchestrator in ["leader"]:
        # check if file exist for arg.file
        if not args.file:
            parser.print_help()
            print("Error: -f, --file cannot be empty.")
            exit(1)
        # check if file exist on the disk
        if not os.path.exists(args.file):
            print(f"Error: {args.file} does not exist.")
            exit(1)
        leader_deployment_model(args.file)

    if args.retire in ["leader"]:
        # check if file exist for arg.file
        if not args.file:
            parser.print_help()
            print("Error: -f, --file cannot be empty.")
            exit(1)
        # check if file exist on the disk
        if not os.path.exists(args.file):
            print(f"Error: {args.file} does not exist.")
            exit(1)
        retire_leader_cluster_model(args.file)

    if args.deploy in ["follower"]:
        # check if file exist for arg.file
        if not args.file:
            parser.print_help()
            print("Error: -f, --file cannot be empty.")
            exit(1)
        # check if file exist on the disk
        if not os.path.exists(args.file):
            print(f"Error: {args.file} does not exist.")
            exit(1)
        deploy_follower_model(args.file)

    if args.retire in ["follower"]:
        # check if file exist for arg.file
        if not args.file:
            parser.print_help()
            print("Error: -f, --file cannot be empty.")
            exit(1)
        # check if file exist on the disk
        if not os.path.exists(args.file):
            print(f"Error: {args.file} does not exist.")
            exit(1)
        retire_follower_model(args.file)
