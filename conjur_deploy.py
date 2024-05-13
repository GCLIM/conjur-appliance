import yaml
import socket
import conjur_appliance

def lookup_by_hostname(yaml_file, hostname):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)

    if hostname in data:
        info = data[hostname]
        print(f"Deployment info for host '{hostname}': {info}")
        return info
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

if __name__ == "__main__":
    yaml_file = "env/dev/leader-cluster.yml"
    hostname = resolve_current_hostname()
    info = lookup_by_hostname(yaml_file, hostname)
    if info:
        # print(f"Type: {info['type']}")
        # print(f"Name: {info['name']}")
        # print(f"Registry: {info['registry']}")
        conjur_appliance.deploy_model(
            name=info["name"],
            type=info["type"],
            registry=info["registry"]
        )

