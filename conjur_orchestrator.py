import yaml
import socket
import argparse
import os
import conjur_appliance
import asyncio
import asyncssh
import tracemalloc

tracemalloc.start()
DOCKER = "podman"


async def remote_run_with_key(hostname, port, username, key_path, commands):
    try:
        # Connect to the remote server using the SSH key
        async with asyncssh.connect(hostname, port=port, username=username, client_keys=[key_path]) as conn:
            # Run the multiline command
            result = await conn.run(commands, check=True)

            # Collect the results
            output = result.stdout
            error = result.stderr

            # Print the output and error
            print("Output:")
            print(output)
            print("Error:")
            print(error)
    except (OSError, asyncssh.Error) as e:
        print(f"SSH connection failed: {e}")


def lookup_by_hostname(yaml_file, hostname):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)

    if hostname in data:
        info = data[hostname]
        print(f"Deployment info for host '{hostname}': {info}")
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


def read_leader_cluster_hostnames(yaml_file):
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

    info = lookup_by_hostname(yaml_file, current_hostname)
    if info is None:
        exit(1)

    if info['registry'] == "":
        info['registry'] = default_registry

    #check if deploying leader node
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
        command = f"""
{DOCKER} exec {info['name']} evoke configure leader --accept-eula --hostname {hostname} \
--leader-altnames {leader_altnames} --admin-password MySecretPass1 {account_name}"""
        print(command)
        print(f"Leader cluster leader node deployment complete.")

    #check if deploying sync standy node
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


def leader_deployall_model(yaml_file):
    kind, hostname, account_name, default_registry = read_leader_cluster_requirements(yaml_file)

    if kind != 'leader-cluster':
        print(f"Invalid kind: {kind}, expects 'leader-cluster' for leader cluster deployment")
        exit(1)

    for hostname in read_leader_cluster_hostnames(yaml_file):
        info = lookup_by_hostname(yaml_file, hostname)
        if info is None:
            exit(1)

#         commands = f"""
# # Check if the directory 'conjur-appliance' exists
# if [ -d "conjur-appliance" ]; then
# # If it exists, navigate to it and pull the latest changes from the repository
#     git -C conjur-appliance pull
# else
# # If it does not exist, clone the repository from GitHub
#     git clone https://github.com/GCLIM/conjur-appliance.git
# fi
# # Change to the 'conjur-appliance' directory and run the Python script
# cd conjur-appliance && \
# python3 conjur_orchestrator.py -d leader -f env/dev/leader_cluster.yml
# """
        commands = f"""
ls -l
if [ -d "conjur-appliance" ]; then
    git -C conjur-appliance pull
else
    git clone https://github.com/GCLIM/conjur-appliance.git
fi
cd conjur-appliance
python3 -m pip install --user --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
python3 conjur_orchestrator.py -d leader -f env/dev/leader_cluster.yml
"""
        # key_path = "/home/gclim/.ssh/conjurappliance_rsa"
        key_path = "/Users/ghimchuanlim/.ssh/id_rsa"
        asyncio.run(remote_run_with_key(hostname, port=22, username="gclim",
                            key_path=key_path, commands=commands))
        print(f"Leader cluster standby node deployment complete.")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Conjur deployment orchestrator",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=True)
    parser.add_argument("-d", "--deploy", type=str, help="leader: deploy leader cluster")
    parser.add_argument("-g", "--deployall", type=str, help="deployall: deploy leader cluster")
    parser.add_argument("-f", "--file", type=str, help="eg. env/dev/leader-cluster.yml")
    args = parser.parse_args()

    # Check if no arguments are provided, then print help
    if not any(vars(args).values()):
        parser.print_help()

    if args.deploy in ["leader"]:
        #check if file exist for arg.file
        if not args.file:
            parser.print_help()
            print("Error: -f, --file cannot be empty.")
            exit(1)
        #check if file exist on the disk
        if not os.path.exists(args.file):
            print(f"Error: {args.file} does not exist.")
            exit(1)
        leader_deployment_model(args.file)

    if args.deployall in ["leader"]:
        # check if file exist for arg.file
        if not args.file:
            parser.print_help()
            print("Error: -f, --file cannot be empty.")
            exit(1)
        # check if file exist on the disk
        if not os.path.exists(args.file):
            print(f"Error: {args.file} does not exist.")
            exit(1)
        leader_deployall_model(args.file)