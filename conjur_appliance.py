import argparse
import json
import subprocess
import os

DOCKER = "podman"
DEPLOYMENT_FILE = "deployment.json"
HOME = os.getenv("HOME")
CONJUR_SERVICE_NAME = "conjur.service"

DEPLOYMENT_LIST = (
    ("Create Conjur system folders", "mkdir -p $HOME/cyberark/conjur/{security,config,backups,seeds,logs}"),
    ("Create Conjur config file", "touch $HOME/cyberark/conjur/config/conjur.yml"),
    ("Set permission to conjur directory", "chmod o+x $HOME/cyberark/conjur/config"),
    ("Set permission to conjur file", "chmod o+r $HOME/cyberark/conjur/config/conjur.yml"),
    ("Create conjur.service folder", "mkdir -p $HOME/.config/systemd/user")
)

RETIREMENT_LIST = (
    ("Delete Conjur system folders", "rm -rf ./cyberark"),
    ("Delete conjur.service file", "rm $HOME/.config/systemd/user/conjur.service"),
)

#EXCLUDE
#--network slirp4netns:enable_ipv6=false,port_handler=slirp4netns \
#--security-opt seccomp=/opt/cyberark/conjur/security/seccomp.json \
#--log-driver journald \
DOCKER_PARAMETER_LEADER_STANDBY = f" \
--add-host=conjur01.mon.local:172.31.27.126 \
--detach \
--publish '443:443' \
--publish '444:444' \
--publish '5432:5432' \
--publish '1999:1999' \
--cap-add AUDIT_WRITE \
--volume {HOME}/cyberark/conjur/config:/etc/conjur/config:z \
--volume {HOME}/cyberark/conjur/security:/opt/cyberark/conjur/security:z \
--volume {HOME}/cyberark/conjur/backups:/opt/conjur/backup:z \
--volume {HOME}/cyberark/conjur/logs:/var/log/conjur:z"

#EXCLUDE
#--network slirp4netns:enable_ipv6=false,port_handler=slirp4netns \
#--security-opt seccomp=/opt/cyberark/conjur/security/seccomp.json \
#--log-driver journald \
DOCKER_PARAMETER_FOLLOWER = f" \
--add-host=conjur01.mon.local:172.31.27.126 \
--detach \
--publish '443:443' \
--publish '444:444' \
--cap-add AUDIT_WRITE \
--volume {HOME}/cyberark/conjur/config:/etc/conjur/config:z \
--volume {HOME}/cyberark/conjur/security:/opt/cyberark/conjur/security:z \
--volume {HOME}/cyberark/conjur/backups:/opt/conjur/backup:z \
--volume {HOME}/cyberark/conjur/logs:/var/log/conjur:z"


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
    deployment_status, docker_running, service_running = check_deployment_status()
    if deployment_status != "Deployed":

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

        # Save the current directory
        previous_dir = os.getcwd()

        # Setup conjur.server
        os.chdir(os.path.join(os.environ['HOME'], '.config/systemd/user/'))

        # Create or edit conjur.service file
        command_without_detach = command.replace("--detach ", "")
        with open("conjur.service", "w") as f:
            f.write(f"""[Unit]
    Description={name} container
    
    [Service]
    Restart=always
    ExecStartPre=-/usr/bin/podman stop -t 5 {name}
    ExecStartPre=-/usr/bin/podman rm {name}
    ExecStart=/usr/bin/{command_without_detach}
    
    [Install]
    WantedBy=default.target
    """)

        # Reload systemd
        subprocess.run(["systemctl", "--user", "daemon-reload"])

        # Start and enable the service
        subprocess.run(["systemctl", "--user", "start", "conjur.service"])
        subprocess.run(["systemctl", "--user", "enable", "conjur.service"])

        # Return to the previous directory
        os.chdir(previous_dir)

        # Write the deployment information to a JSON file
        with open(DEPLOYMENT_FILE, 'w') as file:
            json.dump(deployment_info, file)
            file.write('\n')

        # Enable linger for the current user
        enable_linger(os.getlogin())

    else:
        print(f"Deployment status: Already {deployment_status}")
        print(f"Conjur appliance running: {docker_running}")
        print(f"Conjur service enabled: {service_running}")

def check_sysctl_value(name, expected_value):
    try:
        # Run the sysctl command to retrieve the value of net.ipv4.ip_unprivileged_port_start
        result = subprocess.run(["sysctl", "-n", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, check=True)
        value = int(result.stdout.strip())  # Convert the output to an integer
        if value != expected_value:
            raise ValueError("Value is not equal to {}".format(expected_value))
    except subprocess.CalledProcessError as e:
        print("Error: {}".format(e))
        return 1
    except ValueError as e:
        print("Error: {}".format(e))
        return 1
    else:
        return 0


def check_sysctl_value(name, expected_value):
    try:
        result = subprocess.run(["sysctl", "-n", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, check=True)
        value = int(result.stdout.strip())
        if value != expected_value:
            raise ValueError("Value is not equal to {}".format(expected_value))
    except subprocess.CalledProcessError as e:
        print("Error: {}".format(e))
        return 1
    except ValueError as e:
        print("Error: {}".format(e))
        return 1
    else:
        return 0


def precheck_model():
    print("Precheck ...")
    exit_code = 0

    # Check IPv4 unprivileged port starts at 443
    if check_sysctl_value("net.ipv4.ip_unprivileged_port_start", 443) == 0:
        print("Check IPv4 unprivileged port starts at 443: Passed")
    else:
        print("Check IPv4 unprivileged port starts at 443: Failed")
        exit_code = 1

    # Check user maximum number of namespaces is set to 28633
    if check_sysctl_value("user.max_user_namespaces", 28633) == 0:
        print("Check user maximum number of namespaces is set to 28633: Passed")
    else:
        print("Check user maximum number of namespaces is set to 28633: Failed")
        exit_code = 1

    PRECHECK_LIST = (
        ("Test permission to create directory", "mkdir dummy.dir", "rm -rf dummy.dir"),
        ("Test permission to create File", "touch dummy.file", "rm -rf dummy.file"),
        ("Test podman installation", "podman --version", "")
    )

    for check_name, command, cleanup_command in PRECHECK_LIST:
        try:
            subprocess.run(command, check=True, shell=True)
            print(f"{check_name}: Passed")
            subprocess.run(cleanup_command, check=True, shell=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            print(f"{check_name}: Failed")
            exit_code = 1
        finally:
            subprocess.run(cleanup_command, check=False, shell=True)

    return exit_code


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

            if is_service_running(CONJUR_SERVICE_NAME):
                # Stop and disable the service
                subprocess.run(["systemctl", "--user", "stop", "conjur.service"])
                subprocess.run(["systemctl", "--user", "disable", "conjur.service"])

            # Reload systemd
            subprocess.run(["systemctl", "--user", "daemon-reload"])

            subprocess.run(command, check=True, shell=True)

            # Update the deployment status to 'Retired'
            deployment_info["status"] = "Retired"
            update_deployment_info(deployment_info)

            # Run retirement commands
            for retire_item, retire_command in RETIREMENT_LIST:
                print(f"'{retire_item}' ...")
                subprocess.run(retire_command, check=True, shell=True)
                print(f"'{retire_item}' done.")

            # Disable linger for the current user
            disable_linger(os.getlogin())

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


def is_service_running(service_name):
    try:
        # Run systemctl status <service_name> command
        subprocess.run(["systemctl", "--user", "status", service_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True  # If the command executed successfully, service is running
    except subprocess.CalledProcessError:
        return False  # If the command failed, service is not running


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
        return "Unknown", False, is_service_running(CONJUR_SERVICE_NAME)

    # Check the status of the deployment
    if deployment_info["status"] == "Deployed":
        # Print deployment details
        print(f'Name: {deployment_info["container_name"]}')
        print(f'Type: {deployment_info["type"]}')
        print(f'Registry: {deployment_info["registry"]}')

        # Return deployment status and Docker running status
        return "Deployed", is_container_running(deployment_info["container_name"]), is_service_running(CONJUR_SERVICE_NAME)
    else:
        # Return deployment status and Docker running status
        return "Retired", False, is_service_running(CONJUR_SERVICE_NAME)


def sysctld_config():
    """
    Configure sysctl parameters for Podman rootless mode.

    This function creates a configuration file (/etc/sysctl.d/conjur.conf)
    with the necessary sysctl parameters for Podman rootless mode. It also
    applies the configuration changes using the sysctl command.

    Returns:
        None
    """

    # Define the configuration file path
    SYSCTLD_FILE = "/etc/sysctl.d/conjur.conf"

    # Change the current working directory to /etc/sysctl.d/
    os.chdir("/etc/sysctl.d/")

    # Open the configuration file in write mode
    with open(SYSCTLD_FILE, "w") as f:
        # Write the sysctl parameters to the file
        f.write("""
        # Allow low port number for rootless Podman
        net.ipv4.ip_unprivileged_port_start=443
        # Increase max user namespaces (for example)
        user.max_user_namespaces=28633
        """)

    # Apply the configuration changes using the sysctl command
    subprocess.run(["sudo", "sysctl", "-p", SYSCTLD_FILE])

    # Print a message indicating that the sysctld has been configured
    print("Configured sysctld")


def enable_linger(username):
    try:
        # Run the `loginctl enable-linger` command
        result = subprocess.run(['loginctl', 'enable-linger', username], check=True)
        print(f"Successfully enabled linger for user {username}.")
    except subprocess.CalledProcessError as e:
        # Handle errors in case the command fails
        print(f"Failed to enable linger for user {username}.")
        print(f"Error: {e.stderr}")
    except Exception as e:
        # Handle unexpected errors
        print(f"An unexpected error occurred: {e}")


def disable_linger(username):
    try:
        # Run the `loginctl disable-linger` command
        result = subprocess.run(['loginctl', 'disable-linger', username], check=True)
        print(f"Successfully disabled linger for user {username}.")
    except subprocess.CalledProcessError as e:
        # Handle errors in case the command fails
        print(f"Failed to disable linger for user {username}.")
        print(f"Error: {e.stderr}")
    except Exception as e:
        # Handle unexpected errors
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy Conjur container image.",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=True)
    parser.add_argument("-m", "--model", type=str,
                        help="deploy: deploy Conjur image\nprecheck: pre-check operating system\nretire: retire Conjur deployment\nstatus: check deployment status")
    parser.add_argument("-t", "--type", type=str,
                        help="leader\nstandby\nfollower")
    parser.add_argument("-n", "--name", type=str, help="container name")
    parser.add_argument("-reg", "--registry", type=str, help="Registry of the docker image")
    parser.add_argument("-sys", "--sysctld", type=str, help="config")
    args = parser.parse_args()

    # Check if no arguments are provided, then print help
    if not any(vars(args).values()):
        parser.print_help()

    if args.model == "deploy":
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

        #Prechceck
        if precheck_model() == 1:
            print("Precheck 'Failed'.")
            exit(1)
        else:
            print("Precheck 'Passed'.")

        deploy_model(args.name, args.type, args.registry)

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
        deployment_status, docker_running, service_running = check_deployment_status()
        if deployment_status == "Unknown":
            print("Deployment status: Unknown")

        else:
            print(f"Deployment status: {deployment_status}")
        print(f"Conjur appliance running: {docker_running}")
        print(f"Conjur service enabled: {service_running}")

    if args.sysctld == "config":
        sysctld_config()
