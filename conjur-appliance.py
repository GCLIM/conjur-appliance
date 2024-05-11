import argparse
import json
import subprocess
from prettytable import PrettyTable

DOCKER = "docker"

DEPLOYMENT_FILE = "deployment.json"

PRECHECK_LIST = (
    ("Test permission to create directory", "mkdir dummy.dir", "rm -rf dummy.dir"),
    ("Test permission to create File", "touch dummy.file", "rm -rf dummy.file"),
    ("Test podman installation", "podman --version", "")
)

DEPLOYMENT_LIST = (
    ("Create Conjur system folders",        "mkdir -p ./cyberark/conjur/{security,config,backups,seeds,logs}"),
    ("Create Conjur config file",           "touch ./cyberark/conjur/config/conjur.yml"),
    ("Set permission to conjur directory",  "chmod o+x ./cyberark/conjur/config"),
    ("Set permission to conjur file",       "chmod o+r ./cyberark/conjur/config/conjur.yml"),
)

RETIREMENT_LIST = (
    ("Delete Conjur system folders", "rm -rf ./cyberark"),
)

#EXCLUDE
#--network slirp4netns:enable_ipv6=false,port_handler=slirp4netns \
#--security-opt seccomp=/opt/cyberark/conjur/security/seccomp.json \
#--log-driver journald \
DOCKER_PARAMETER_LEADER_STANDBY = " \
--add-host=conjur01.mon.local:172.31.27.126 \
--detach \
--publish '443:443' \
--publish '444:444' \
--publish '5432:5432' \
--publish '1999:1999' \
--cap-add AUDIT_WRITE \
--volume ./cyberark/conjur/config:/etc/conjur/config:z \
--volume ./cyberark/conjur/security:/opt/cyberark/conjur/security:z \
--volume ./cyberark/conjur/backups:/opt/conjur/backup:z \
--volume ./cyberark/conjur/logs:/var/log/conjur:z"

#EXCLUDE
#--network slirp4netns:enable_ipv6=false,port_handler=slirp4netns \
#--security-opt seccomp=/opt/cyberark/conjur/security/seccomp.json \
#--log-driver journald \
DOCKER_PARAMETER_FOLLOWER = " \
--add-host=conjur01.mon.local:172.31.27.126 \
--detach \
--publish '443:443' \
--publish '444:444' \
--cap-add AUDIT_WRITE \
--volume ./cyberark/conjur/config:/etc/conjur/config:z \
--volume ./cyberark/conjur/security:/opt/cyberark/conjur/security:z \
--volume ./cyberark/conjur/backups:/opt/conjur/backup:z \
--volume ./cyberark/conjur/logs:/var/log/conjur:z"


def deploy_model(name: str, type: str, registry: str) -> None:
    """
    Deploys a Conjur model with the given name, type, and registry.

    Args:
        name (str): The name of the container.
        type (str): The type of the container. Must be one of "leader", "standby", or "follower".
        registry (str): The registry of the docker image.

    Returns:
        None

    Raises:
        subprocess.CalledProcessError: If there is an error during the deployment process.

    Writes deployment information to a JSON file.
    """

    # Print the deployment details
    print(f"Deploying '{name}' '{type}' node with '{registry}' ...")

    # Iterate over the deployment list and execute each command
    for deploy_item, deploy_command in DEPLOYMENT_LIST:
        print(f"'{deploy_item}' ...")
        subprocess.run(deploy_command, check=True, shell=True)
        print(f"'{deploy_item}' done.")

    # Create a dictionary to store deployment information
    deployment_info = {
        "container_name": name,
        "type": type,
        "registry": registry,
        "status": ""
    }

    try:
        # Check the type of the container and set the command accordingly
        if type in ["leader", "standby"]:
            print(DOCKER_PARAMETER_LEADER_STANDBY)
            command = f"{DOCKER} run -p 8082:80 --name {name} {DOCKER_PARAMETER_LEADER_STANDBY} {registry}"
        elif type == "follower":
            print(DOCKER_PARAMETER_FOLLOWER)
            command = f"{DOCKER} run -p 8082:80 --name {name} {DOCKER_PARAMETER_FOLLOWER} {registry}"

        # Print the starting message and execute the command
        print(f"Starting '{name}'...")
        subprocess.run(command, check=True, shell=True)
        deployment_info["status"] = "Deployed"
        print(f"'{name}' is 'Deployed'.")
    except subprocess.CalledProcessError as e:
        # Print the error message and update the deployment status
        print(f"Error: {e}")
        deployment_info["status"] = "Failed"
        print(f"'{name}' deployment 'Failed'.")

    # Write the deployment information to a JSON file
    with open(DEPLOYMENT_FILE, 'w') as file:
        json.dump(deployment_info, file)
        file.write('\n')


def precheck_model():
    """
    Perform prechecks for model deployment.

    Runs a series of commands from PRECHECK_LIST, captures the status of each check,
    and returns an exit code based on the overall result.

    Returns:
        int: The exit code indicating the overall success or failure of the prechecks.
    """
    # Print precheck message
    print("Precheck ...")

    # Initialize PrettyTable for displaying results
    table = PrettyTable()
    table.field_names = ["Check List", "Status"]
    table.align["Check List"] = "l"  # Align the "Check" column to the left

    exit_code = 0  # Initialize exit code

    # Loop through PRECHECK_LIST and perform checks
    for check_name, command, cleanup_command in PRECHECK_LIST:
        try:
            subprocess.run(command, check=True, shell=True)  # Run the check command
            table.add_row([check_name, "Passed"])  # Add row for passed check
            subprocess.run(cleanup_command, check=True, shell=True)  # Cleanup after check
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            table.add_row([check_name, "Failed"])  # Add row for failed check
            exit_code = 1  # Update exit code to indicate failure
        finally:
            subprocess.run(cleanup_command, check=False, shell=True)  # Cleanup regardless of check result

    # Print the PrettyTable with results
    print(table)

    return exit_code  # Return the overall exit code


def retire_model():
    """
    Retires a model based on its deployment status.

    Retrieves deployment information, checks if the status is 'Deployed', stops and removes the container,
    updates the deployment status to 'Retired', runs retirement commands, and updates the status accordingly.
    """
    # Retrieve deployment information
    deployment_info = get_deployment_info()
    name = deployment_info.get("container_name")
    status = deployment_info.get("status")

    # Check if the deployment status is 'Deployed'
    if status == "Deployed":
        print(f"Retiring '{name}'...")

        # Stop and remove the container
        command = f"{DOCKER} stop {name} && {DOCKER} rm {name}"
        try:
            subprocess.run(command, check=True, shell=True)

            # Update the deployment status to 'Retired'
            deployment_info["status"] = "Retired"
            update_deployment_info(deployment_info)

            # Run retirement commands
            for retire_item, retire_command in RETIREMENT_LIST:
                print(f"'{retire_item}' ...")
                subprocess.run(retire_command, check=True, shell=True)
                print(f"'{retire_item}' done.")

            # Print success message
            print(f"'{name}' retired successfully.")
            return
        except subprocess.CalledProcessError as e:
            # Print error message and return
            print(f"Error: {e}")
            return
    else:
        # Print message if the deployment status is not 'Deployed'
        print(f"The deployment status for '{name}' is not 'Deployed'.")


def get_deployment_info():
    """
    Retrieves deployment information from the DEPLOYMENT_FILE.

    If the file doesn't exist, returns an empty list.

    Returns:
        list: The deployment information.

    Raises:
        FileNotFoundError: If the DEPLOYMENT_FILE doesn't exist.
    """
    try:
        with open(DEPLOYMENT_FILE, 'r') as file:
            # Load the deployment information from the file
            deployment_info = json.load(file)
    except FileNotFoundError:
        # If the DEPLOYMENT_FILE doesn't exist, return an empty list
        deployment_info = []

    return deployment_info


def update_deployment_info(deployment_info):
    """
    Update the deployment information in the deployments.json file.

    Args:
        deployment_info (dict): The updated deployment information.

    Raises:
        FileNotFoundError: If the deployments.json file does not exist.
    """
    # Open the deployments.json file in write mode
    with open(DEPLOYMENT_FILE, 'w') as file:
        # Write the updated deployment information to the file
        json.dump(deployment_info, file)


def is_container_running(container_name):
    """
    Check if a Docker container is currently running.

    Args:
        container_name (str): The name of the Docker container.

    Returns:
        bool: True if the container is running, False otherwise.
    """
    try:
        # Run the "docker inspect" command to get information about the container
        inspect_output = subprocess.check_output([f"{DOCKER}", "inspect", container_name])

        # Parse the JSON output
        container_info = json.loads(inspect_output)

        # Check if the container is running
        if container_info and container_info[0]["State"]["Status"] == "running":
            return True
    except subprocess.CalledProcessError:
        pass

    return False


def check_deployment_status():
    """
    Retrieves the deployment status and Docker running status.

    Returns:
        tuple: A tuple containing the deployment status ('Deployed', 'Retired', or 'Unknown')
               and a boolean indicating whether Docker is running.
    """
    # Retrieve deployment information
    deployment_info = get_deployment_info()

    # Check if there is no deployment information
    if not deployment_info:
        return "Unknown", False

    # Check the status of the deployment
    if deployment_info["status"] == "Deployed":
        # Print deployment details
        print(f'Name: {deployment_info["container_name"]}')
        print(f'Type: {deployment_info["type"]}')
        print(f'Registry: {deployment_info["registry"]}')

        # Return deployment status and Docker running status
        return "Deployed", is_container_running(deployment_info["container_name"])
    else:
        # Return deployment status and Docker running status
        return "Retired", False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy Conjur container image.", formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=True)
    parser.add_argument("-m", "--model", type=str,
                        help="deploy: deploy Conjur image\nprecheck: pre-check operating system\nretire: retire Conjur deployment\nstatus: check deployment status")
    parser.add_argument("-t", "--type", type=str,
                        help="leader\nstandby\nfollower")
    parser.add_argument("-n", "--name", type=str, help="container name")
    parser.add_argument("-reg", "--registry", type=str, help="Registry of the docker image")
    args = parser.parse_args()

    # Check if no arguments are provided, then print help
    if not any(vars(args).values()):
        parser.print_help()

    if args.model == "deploy":
        deployment_status, docker_running = check_deployment_status()
        if deployment_status != "Deployed":
            if not args.name:
                parser.print_help()
                print("Name cannot be empty.")
                print("Usage: -n, --name <name>")
                exit(1)
            if args.type not in ["leader", "standby", "follower"]:
                parser.print_help()
                print("Type must be 'leader', 'standby' or 'follower'.")
                print("Usage: -t, --type leader|standby|follower")
                exit(1)
            if not args.registry:
                parser.print_help()
                print("Registry cannot be empty.")
                print("Usage: -reg, --registry <registry>")
                exit(1)
            deploy_model(args.name, args.type, args.registry)
        else:
            print(f"Deployment status: Already {deployment_status}")
            print(f"Conjur appliance running: {docker_running}")

    if args.model == "precheck":
        if precheck_model() == 1:
            print("Precheck 'Failed'.")
            exit(1)
        else:
            print("Precheck 'Passed'.")
            exit(0)

    if args.model == "retire":
        retire_model()

    if args.model == "status":
        deployment_status, docker_running = check_deployment_status()
        if deployment_status == "Unknown":
            print("Deployment status: Unknown")
        else:
            print(f"Deployment status: {deployment_status}")
            print(f"Conjur appliance running: {docker_running}")
