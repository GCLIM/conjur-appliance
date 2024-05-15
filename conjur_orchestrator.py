import yaml
import socket
import argparse
import os
import conjur_appliance

DOCKER = "podman"

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
    account_name = data.get('account-name')
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
        print(f"Type: {info['type']}")
        print(f"Name: {info['name']}")
        print(f"Registry: {info['registry']}")
        # conjur_appliance.deploy_model(
        #     name=info["name"],
        #     type=info["type"],
        #     registry=info["registry"]
        # )
        print(f"Leader cluster name: {hostname}")
        print(f"Account name: {account_name}")
        print(f"Leader cluster nodes: {read_leader_cluster_hostnames(yaml_file)}")
        leader_altnames = ','.join(read_leader_cluster_hostnames(yaml_file))
        command = f"""
{DOCKER} exec {info['name']} evoke configure leader --accept-eula --hostname {hostname} \
--leader-altnames {leader_altnames} --admin-password MySecretPass1 {account_name}"""
        print(command)
        print(f"Leader cluster deployment complete.")

    #check if deploying sync standy node
    if info['type'] == 'standby':
        print(f"Deploying leader cluster for standby node ...")
        print(f"Type: {info['type']}")
        print(f"Name: {info['name']}")
        print(f"Registry: {info['registry']}")

    return


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Conjur deployment orchestrator",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=True)
    parser.add_argument("-d", "--deploy", type=str, help="leader: deploy leader cluster")
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