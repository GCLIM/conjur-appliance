import argparse
import json
import subprocess
import os
from typing import Dict, Any
import logging
import re
import requests

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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
    ("Delete Conjur system folders", "rm -rf $HOME/cyberark"),
    ("Delete conjur.service file", "rm $HOME/.config/systemd/user/conjur.service"),
    ("Delete default.target.wants", "rm $HOME/.config/systemd/user/default.target.wants/conjur.service")
)

# EXCLUDE
# --security-opt seccomp=/opt/cyberark/conjur/security/seccomp.json \
DOCKER_PARAMETER_LEADER_STANDBY = f" \
--add-host=conjur01.mon.local:172.31.27.126 \
--detach \
--network slirp4netns:enable_ipv6=false,port_handler=slirp4netns \
--security-opt seccomp=unconfined \
--publish '443:443' \
--publish '444:444' \
--publish '5432:5432' \
--publish '1999:1999' \
--cap-add AUDIT_WRITE \
--log-driver journald \
--volume {HOME}/cyberark/conjur/config:/etc/conjur/config:z \
--volume {HOME}/cyberark/conjur/security:/opt/cyberark/conjur/security:z \
--volume {HOME}/cyberark/conjur/backups:/opt/conjur/backup:z \
--volume {HOME}/cyberark/conjur/logs:/var/log/conjur:z"

# EXCLUDE
# --security-opt seccomp=/opt/cyberark/conjur/security/seccomp.json \
DOCKER_PARAMETER_FOLLOWER = f" \
--add-host=conjur01.mon.local:172.31.27.126 \
--detach \
--network slirp4netns:enable_ipv6=false,port_handler=slirp4netns \
--security-opt seccomp=unconfined \
--publish '443:443' \
--publish '444:444' \
--cap-add AUDIT_WRITE \
--log-driver journald \
--volume {HOME}/cyberark/conjur/config:/etc/conjur/config:z \
--volume {HOME}/cyberark/conjur/security:/opt/cyberark/conjur/security:z \
--volume {HOME}/cyberark/conjur/backups:/opt/conjur/backup:z \
--volume {HOME}/cyberark/conjur/logs:/var/log/conjur:z"

PASSED = 0
FAILED = 1
ALREADY_DEPLOYED = 2


def enable_service(service_name):
    try:
        result = subprocess.run(
            ["systemctl", "--user", "enable", service_name],
            check=True, capture_output=True, text=True
        )
        print("Service enabled successfully.")
    except subprocess.CalledProcessError as e:
        print("Error enabling service:", e.stderr)


def start_service(service_name):
    try:
        result = subprocess.run(
            ["systemctl", "--user", "start", service_name],
            check=True, capture_output=True, text=True
        )
        print("Service started successfully.")
    except subprocess.CalledProcessError as e:
        print("Error starting service:", e.stderr)


def stop_service(service_name):
    try:
        result = subprocess.run(
            ["systemctl", "--user", "stop", service_name],
            check=True, capture_output=True, text=True
        )
        print("Service stopped successfully.")
    except subprocess.CalledProcessError as e:
        print("Error stopping service:", e.stderr)


def disable_service(service_name):
    try:
        result = subprocess.run(
            ["systemctl", "--user", "disable", service_name],
            check=True, capture_output=True, text=True
        )
        print("Service disabled successfully.")
    except subprocess.CalledProcessError as e:
        print("Error disabling service:", e.stderr)


# def run_subprocess(command, shell=False):
#     """
#     Run a subprocess command and print its output for verbosity.
#
#     Args:
#         command (list or str): The command to run.
#         shell (bool): Whether to run the command in the shell.
#
#     Returns:
#         CompletedProcess: The result of the subprocess.run call.
#     """
#     logging.info(f"Running command: {' '.join(command) if isinstance(command, list) else command}")
#     try:
#         result = subprocess.run(command, shell=shell, check=True, capture_output=True, text=True)
#     except subprocess.CalledProcessError as e:
#         logging.error(f"\nError: {e}")
#         return exit(1)
#     if result.stdout:
#         logging.info(f"\nstdout:\n{result.stdout}")
#     result.check_returncode()  # This will raise CalledProcessError if the command failed
#     return result

def mask_sensitive_info(command):
    """
    Masks sensitive information in a command string or list of command strings.
    """
    # Define patterns for various sensitive information
    patterns = [
        r'(env\s+ADMIN_PASSWORD=)([^\s]+)',  # env ADMIN_PASSWORD=value
        r'(env\s+DB_PASSWORD=)([^\s]+)',  # env DB_PASSWORD=value
        r'(\$conjur_admin_password\s+=\s+)([^\s]+)',  # $conjur_admin_password = value
        r'(\$vault_admin_password\s+=\s+)([^\s]+)',  # $vault_admin_password = value
        r'(export\s+[A-Z_]+PASSWORD=)([^\s]+)',  # export DB_PASSWORD=value
        r'(--admin-password\s+)(\S+)',  # --admin-password value
        r'(--secret\s+)(\S+)',  # --secret value
        r'(-pass\s+)(\S+)',  # -pass value
        r'(\b(?:password|passwd|secret|api_key|token)\b\s*=\s*["\']?)([^\s"\'&;]+)',
        # password=value or password='value'
        r'(["\'])(password|secret|api_key|token)["\']?\s*=\s*(["\'])([^\3]+)(\3)',
        # "password=value" or 'password=value'
    ]

    def mask_single_command(cmd):
        """
        Apply masking to a single command string.
        """
        for pattern in patterns:
            cmd = re.sub(pattern, lambda x: f'{x.group(1)}****', cmd, flags=re.IGNORECASE)
        return cmd

    if isinstance(command, str):
        # Mask a single command string
        return mask_single_command(command)

    elif isinstance(command, list):
        # Mask each command in the list
        return [mask_single_command(cmd) for cmd in command]

    else:
        raise ValueError("Unsupported command type. Expected str or list of str.")


def run_subprocess(command, shell=False):
    """
    Run a subprocess command and print its output for verbosity.

    Args:
        command (list or str): The command to run.
        shell (bool): Whether to run the command in the shell.

    Returns:
        CompletedProcess: The result of the subprocess.run call.
    """
    masked_command = mask_sensitive_info(command)
    logging.info(f"Running command: {' '.join(masked_command) if isinstance(masked_command, list) else masked_command}")
    try:
        result = subprocess.run(command, shell=shell, check=True, capture_output=True, text=True)
        if result.stdout:
            logging.info(f"Output:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error: {e}")
        if hasattr(e, 'returncode'):
            logging.error(f"Exit status: {e.returncode}")
        if hasattr(e, 'cmd'):
            logging.error(f"Command: {e.cmd}")
        if hasattr(e, 'stdout') and e.stdout:
            logging.error(f"Standard output:\n{e.stdout}")
        if hasattr(e, 'stderr') and e.stderr:
            logging.error(f"Standard error:\n{e.stderr}")
        raise  # Re-raise the exception to let the caller handle it

    return result


def get_deployment_info() -> Dict[str, Any]:
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
        return "Deployed", is_container_running(deployment_info["container_name"]), is_service_running(
            CONJUR_SERVICE_NAME)
    else:
        # Return deployment status and Docker running status
        return "Retired", False, is_service_running(CONJUR_SERVICE_NAME)


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
    """
    Check if a service is running.

    Args:
        service_name (str): The name of the service to check.

    Returns:
        bool: True if the service is running, False otherwise.
    """
    try:
        # Run systemctl status <service_name> command
        subprocess.run(["systemctl", "--user", "status", service_name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)
        return True  # If the command executed successfully, service is running
    except subprocess.CalledProcessError:
        return False  # If the command failed, service is not running


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
    """
    A function to enable linger for a specified username.

    Parameters:
        username (str): The username for which to enable linger.

    Returns:
        None
    """
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
    """
    A function to disable linger for a specified username.

    Parameters:
        username (str): The username for which to disable linger.

    Returns:
        None
    """
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


def deploy_model(name: str, type: str, registry: str) -> int:
    """
    Deploys a model with the specified name, type, and registry.

    Args:
        name (str): The name of the model.
        type (str): The type of the model (leader, standby, or follower).
        registry (str): The registry of the model.

    Returns:
        int: The exit code of the deployment process.
    """
    exit_code = 0
    deployment_status, docker_running, service_running = check_deployment_status()
    if deployment_status != "Deployed":

        # Print the deployment details
        print(f"Deploying '{name}' '{type}' node with '{registry}'...")

        # Iterate over the deployment list and execute each command
        for deploy_item, deploy_command in DEPLOYMENT_LIST:
            print(f"'{deploy_item}'...", end="")
            if run_subprocess(deploy_command, shell=True).returncode == 0:
                print("Done")
            else:
                print("Failed")
                exit_code = 1

        # Create a dictionary to store deployment information
        deployment_info = {
            "container_name": name,
            "type": type,
            "registry": registry,
            "status": ""
        }

        # Print the starting message and execute the command
        print(f"Starting '{name}'...", end="")

        # Export seccomp profile from image
        command = f"{DOCKER} run --entrypoint '/bin/cat' {registry} /usr/share/doc/conjur/examples/seccomp.json > {HOME}/cyberark/conjur/security/seccomp.json"
        if run_subprocess(command, shell=True).returncode == 0:
            print("Exported seccomp profile from image.")
        else:
            print("Exporting seccomp profile from image...Failed")
            exit_code = FAILED

        # Check the type of the container and set the command accordingly
        command = ""
        if type in ["leader", "standby"]:
            # print(DOCKER_PARAMETER_LEADER_STANDBY)
            command = f"{DOCKER} run --rm --name {name} {DOCKER_PARAMETER_LEADER_STANDBY} {registry}"
        elif type == "follower":
            # print(DOCKER_PARAMETER_FOLLOWER)
            command = f"{DOCKER} run --name {name} {DOCKER_PARAMETER_FOLLOWER} {registry}"

        if run_subprocess(command, shell=True).returncode == 0:
            deployment_info["status"] = "Deployed"
            print("Conjur appliance...Deployed")
        else:
            deployment_info["status"] = "Failed"
            print("Conjur appliance deployment...Failed")
            exit_code = FAILED

        # Save the current directory
        previous_dir = os.getcwd()

        # Setup conjur.server
        os.chdir(os.path.join(os.environ['HOME'], '.config/systemd/user/'))

        # Create or edit conjur.service file
        command_without_detach = command.replace("--detach ", "")
        with open("conjur.service", "w") as f:
            f.write(f"""
    [Unit]
    Description={name} container
    
    [Service]
    Restart=always
    ExecStartPre=-/usr/bin/podman start {name}
    ExecStop=/usr/bin/podman stop -t 5 {name}
    ExecStart=/usr/bin/podman start -a {name}

    [Install]
    WantedBy=default.target
    """)

        # Reload systemd
        if run_subprocess(["systemctl", "--user", "daemon-reload"]).returncode == 0:
            print("Daemon reloaded...Done")
        else:
            print("Daemon reloaded...Failed")
            exit_code = FAILED

        # Start service
        start_service("conjur.service")

        # Enable service
        enable_service("conjur.service")

        # Return to the previous directory
        os.chdir(previous_dir)

        # Write the deployment information to a JSON file
        with open(DEPLOYMENT_FILE, 'w') as file:
            json.dump(deployment_info, file)
            file.write('\n')

        # Enable linger for the current user
        enable_linger(os.getlogin())

    else:
        exit_code = ALREADY_DEPLOYED
        print(f"Deployment status: Already {deployment_status}")
        print(f"Conjur appliance running: {docker_running}")
        print(f"Conjur service enabled: {service_running}")

    return exit_code


def check_sysctl_value(name, expected_value):
    """
    A function to check the value of a sysctl parameter against an expected value.

    Parameters:
    name (str): The name of the sysctl parameter to check.
    expected_value (int): The expected value that the sysctl parameter should have.

    Returns:
    int: 0 if the value matches the expected value, 1 otherwise.
    """
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


def precheck_model():
    """
    A function that performs prechecks including checking the IPv4 unprivileged port starting at 443
    and the user maximum number of namespaces being set to 28633.
    It also tests permissions to create directories, files, and checks podman installation.
    Returns the exit code indicating the success or failure of the prechecks.
    """
    print("Precheck ...")
    exit_code = PASSED

    # Check IPv4 unprivileged port starts at 443
    if check_sysctl_value("net.ipv4.ip_unprivileged_port_start", 443) == 0:
        print("Check IPv4 unprivileged port starts at 443: Passed")
    else:
        print("Check IPv4 unprivileged port starts at 443: Failed")
        exit_code = FAILED

    # Check user maximum number of namespaces is set to 28633
    if check_sysctl_value("user.max_user_namespaces", 28633) == 0:
        print("Check user maximum number of namespaces is set to 28633: Passed")
    else:
        print("Check user maximum number of namespaces is set to 28633: Failed")
        exit_code = FAILED

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
            exit_code = FAILED
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
    if status in ["Deployed", "Failed"]:
        print(f"Retiring '{name}'...")

        # Stop and remove all containers
        command = f"{DOCKER} stop {name} && {DOCKER} rm $({DOCKER} ps -qa)"
        try:

            if is_service_running(CONJUR_SERVICE_NAME):
                # Stop and disable the service
                stop_service(CONJUR_SERVICE_NAME)
                disable_service(CONJUR_SERVICE_NAME)

            if is_container_running(name):
                if run_subprocess(command, shell=True).returncode == 0:
                    print("...Done")
                else:
                    print("...Failed")

            # Update the deployment status to 'Retired'
            deployment_info["status"] = "Retired"
            update_deployment_info(deployment_info)

            # Run retirement commands
            for retire_item, retire_command in RETIREMENT_LIST:
                print(f"'{retire_item}'...", end="")
                if run_subprocess(retire_command, shell=True).returncode == 0:
                    print("...Done")
                else:
                    print("...Failed")

            # Reload systemd
            if run_subprocess(["systemctl", "--user", "daemon-reload"]).returncode == 0:
                print("...Done")
            else:
                print("...Failed")

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


def import_root_certificate(name, file_path):
    """
    Import the root certificate file.

    :param file_path: The path to the file.
    :return: None
    """
    if os.path.exists(file_path):
        logging.info(f"Importing root certificate: {file_path}")

        # Create the directory if it doesn't exist
        command = f"{DOCKER} exec {name} mkdir -p /opt/cyberark/dap/certificates"
        run_subprocess(command, shell=True)

        # Copy the file
        command = f"{DOCKER} cp {file_path} {name}:/opt/cyberark/dap/certificates/ca-chain.pem"
        run_subprocess(command, shell=True)

        # Import the root certificate
        command = f"{DOCKER} exec {name} evoke ca import --no-restart --root /opt/cyberark/dap/certificates/ca-chain.pem"
        run_subprocess(command, shell=True)


def import_ha_cluster_certificates(name, master_key, master_cert):
    """
    Import the HA cluster certificates.

    :param master_key: The path to the master key file.
    :param master_cert: The path to the master certificate file.
    :return: None
    """
    if os.path.exists(master_key) and os.path.exists(master_cert):
        logging.info("Importing HA cluster certificates")

        # Copy the files
        command = f"{DOCKER} cp {master_key} {name}:/opt/cyberark/dap/certificates/master-key.pem"
        run_subprocess(command, shell=True)
        command = f"{DOCKER} cp {master_cert} {name}:/opt/cyberark/dap/certificates/master-cert.pem"
        run_subprocess(command, shell=True)

        # Import the certificates
        command = f"{DOCKER} exec {name} evoke ca import --no-restart --key /opt/cyberark/dap/certificates/master-key.pem --set /opt/cyberark/dap/certificates/master-cert.pem"
        run_subprocess(command, shell=True)


def import_follower_certificate(name, follower_key, follower_cert):
    """
    Import the follower certificate.

    :param follower_key: The path to the follower key file.
    :param follower_cert: The path to the follower certificate file.
    :return: None
    """
    if os.path.exists(follower_key) and os.path.exists(follower_cert):
        logging.info("Importing follower certificate")

        # Copy the files
        command = f"{DOCKER} cp {follower_key} {name}:/opt/cyberark/dap/certificates/follower-key.pem"
        run_subprocess(command, shell=True)
        command = f"{DOCKER} cp {follower_cert} {name}:/opt/cyberark/dap/certificates/follower-cert.pem"
        run_subprocess(command, shell=True)

        # Import the certificates
        command = f"{DOCKER} exec {name} evoke ca import --force --no-restart --key /opt/cyberark/dap/certificates/follower-key.pem --set /opt/cyberark/dap/certificates/follower-cert.pem"
        run_subprocess(command, shell=True)


def restart_conjur_services(name):
    """
    Restart the Conjur services.

    :param name: The name of the container.
    :return: None
    """
    command = f"{DOCKER} exec {name} sv restart conjur nginx pg seed"
    try:
        result = run_subprocess(command, shell=True)
        logging.info(f"Restarted Conjur services: {result}")
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            logging.warning("Received exit status 1.")
            # specific handling for exit status 1 can be done here.
        else:
            logging.warning(f"Handling general case for non-zero exit status: {e.returncode}")
            # can add further actions here like retries, alternate commands, etc.


def check_health(json_data):
    """
    Check the health status based on the given JSON data.
    """
    # Extract the overall status
    overall_status = json_data.get("ok", False)
    degraded_status = json_data.get("degraded", False)
    role = json_data.get("role", "unknown")

    # Check services status
    services_status = json_data.get("services", {})
    services_report = []
    for service, status in services_status.items():
        if service == "ok":
            continue  # Skip the overall 'ok' key in services
        services_report.append(f"Service '{service}': {'OK' if status == 'ok' else 'Status: ' + status}")

    # Check database status
    database_status = json_data.get("database", {}).get("ok", False)
    db_free_space = json_data.get("database", {}).get("free_space", {}).get("main", {}).get("kbytes", 0)

    # Check replication status
    replication_status = json_data.get("database", {}).get("replication_status", {})
    replication_report = []
    for replica in replication_status.get("pg_stat_replication", []):
        replication_report.append(
            f"Replica '{replica['application_name']}': "
            f"State={replica['state']}, "
            f"Sync State={replica['sync_state']}, "
            f"Replication Lag={replica['replication_lag_bytes']} bytes"
        )

    # Check audit status
    audit_status = json_data.get("audit", {}).get("ok", False)
    audit_processed = json_data.get("audit", {}).get("received", {}).get("processed", 0)

    # Check local authentication status
    local_auth_status = json_data.get("local_authentication", {}).get("ok", False)

    # Check selective replication status
    selective_rep_status = json_data.get("selective_replication", {}).get("ok", False)
    selective_rep_degraded = json_data.get("selective_replication", {}).get("degraded", False)

    # Prepare the health report
    health_report = {
        "overall_status": "OK" if overall_status and not degraded_status else "DEGRADED" if degraded_status else "NOT OK",
        "role": role,
        "services": services_report,
        "database": {
            "status": "OK" if database_status else "NOT OK",
            "free_space_kbytes": db_free_space,
            "replication": replication_report
        },
        "audit": {
            "status": "OK" if audit_status else "NOT OK",
            "processed_events": audit_processed
        },
        "local_authentication": "OK" if local_auth_status else "NOT OK",
        "selective_replication": {
            "status": "OK" if selective_rep_status else "NOT OK",
            "degraded": selective_rep_degraded
        }
    }

    return health_report


def print_health_report(health_report):
    """
    Print the health report in a readable format.
    """
    print("Health Check Summary:")
    print(f"Overall Status: {health_report['overall_status']}")
    print(f"Role: {health_report['role']}")
    print("\nServices Status:")
    for service_status in health_report['services']:
        print(f"  - {service_status}")
    print("\nDatabase Status:")
    print(f"  - Status: {health_report['database']['status']}")
    print(f"  - Free Space (kbytes): {health_report['database']['free_space_kbytes']}")
    print("\n  Replication Status:")
    for replica_status in health_report['database']['replication']:
        print(f"    - {replica_status}")
    print("\nAudit Status:")
    print(f"  - Status: {health_report['audit']['status']}")
    print(f"  - Processed Events: {health_report['audit']['processed_events']}")
    print("\nLocal Authentication Status:")
    print(f"  - Status: {health_report['local_authentication']}")
    print("\nSelective Replication Status:")
    print(f"  - Status: {health_report['selective_replication']['status']}")
    print(f"  - Degraded: {'Yes' if health_report['selective_replication']['degraded'] else 'No'}")

    print("\n")

def check_health(json_data):
    """
    Check the health status based on the given JSON data.
    """
    # Extract the overall status
    overall_status = json_data.get("ok", False)
    degraded_status = json_data.get("degraded", False)
    role = json_data.get("role", "unknown")

    # Check services status
    services_status = json_data.get("services", {})
    services_report = []
    for service, status in services_status.items():
        if service == "ok":
            continue  # Skip the overall 'ok' key in services
        services_report.append(f"Service '{service}': {'OK' if status == 'ok' else 'Status: ' + status}")

    # Check database status
    database_status = json_data.get("database", {}).get("ok", False)
    db_free_space = json_data.get("database", {}).get("free_space", {}).get("main", {}).get("kbytes", 0)

    # Check replication status
    replication_status = json_data.get("database", {}).get("replication_status", {})
    replication_report = []
    for replica in replication_status.get("pg_stat_replication", []):
        replication_report.append(
            f"Replica '{replica['application_name']}': "
            f"State={replica['state']}, "
            f"Sync State={replica['sync_state']}, "
            f"Replication Lag={replica['replication_lag_bytes']} bytes"
        )

    # Check audit status
    audit_status = json_data.get("audit", {}).get("ok", False)
    audit_processed = json_data.get("audit", {}).get("received", {}).get("processed", 0)

    # Check local authentication status
    local_auth_status = json_data.get("local_authentication", {}).get("ok", False)

    # Check selective replication status
    selective_rep_status = json_data.get("selective_replication", {}).get("ok", False)
    selective_rep_degraded = json_data.get("selective_replication", {}).get("degraded", False)

    # Prepare the health report
    health_report = {
        "overall_status": "OK" if overall_status and not degraded_status else "DEGRADED" if degraded_status else "NOT OK",
        "role": role,
        "services": services_report,
        "database": {
            "status": "OK" if database_status else "NOT OK",
            "free_space_kbytes": db_free_space,
            "replication": replication_report
        },
        "audit": {
            "status": "OK" if audit_status else "NOT OK",
            "processed_events": audit_processed
        },
        "local_authentication": "OK" if local_auth_status else "NOT OK",
        "selective_replication": {
            "status": "OK" if selective_rep_status else "NOT OK",
            "degraded": selective_rep_degraded
        }
    }

    return health_report


def print_health_report(health_report):
    """
    Print the health report in a readable format.
    """
    print("Health Check Summary:")
    print(f"Overall Status: {health_report['overall_status']}")
    print(f"Role: {health_report['role']}")
    print("\nServices Status:")
    for service_status in health_report['services']:
        print(f"  - {service_status}")
    print("\nDatabase Status:")
    print(f"  - Status: {health_report['database']['status']}")
    print(f"  - Free Space (kbytes): {health_report['database']['free_space_kbytes']}")
    print("\n  Replication Status:")
    for replica_status in health_report['database']['replication']:
        print(f"    - {replica_status}")
    print("\nAudit Status:")
    print(f"  - Status: {health_report['audit']['status']}")
    print(f"  - Processed Events: {health_report['audit']['processed_events']}")
    print("\nLocal Authentication Status:")
    print(f"  - Status: {health_report['local_authentication']}")
    print("\nSelective Replication Status:")
    print(f"  - Status: {health_report['selective_replication']['status']}")
    print(f"  - Degraded: {'Yes' if health_report['selective_replication']['degraded'] else 'No'}")


def fetch_and_analyze_health(url):
    """
    Fetch the health data from the given URL using curl and analyze it.
    """
    try:
        # Use curl to fetch the JSON data
        curl_command = f"curl -s {url}"
        result = run_subprocess(curl_command, shell=True)

        # Check if curl executed successfully
        if result.returncode != 0:
            print(f"Failed to fetch health data: {result.stderr}")
            return

        # Parse the JSON response
        json_data = json.loads(result.stdout)

        # Perform the health check
        health_report = check_health(json_data)

        # Print the health report
        print_health_report(health_report)

    except json.JSONDecodeError as e:
        print(f"Failed to decode JSON data: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy Conjur container image.",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=True)
    parser.add_argument("-m", "--model", type=str,
                        help="deploy: deploy Conjur image\nprecheck: pre-check operating system\nretire: retire Conjur deployment\nstatus: check deployment status\nhealth: fetch health report")
    parser.add_argument("-t", "--type", type=str,
                        help="leader\nstandby\nfollower")
    parser.add_argument("-n", "--name", type=str, help="container name")
    parser.add_argument("-reg", "--registry", type=str, help="Registry of the docker image")
    parser.add_argument("-sys", "--sysctld", type=str, help="config")
    parser.add_argument("-test", "--test", type=str, help="reserved for test function")
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

        # Prechceck
        if precheck_model() == FAILED:
            print("Prerequisite Check: 'Failed'")
            exit(1)
        else:
            print("Prerequisite Check: 'Passed'")

        deployment_status = deploy_model(args.name, args.type, args.registry)
        if deployment_status == FAILED:
            exit(1)
        else:
            exit(0)

    if args.model == "precheck":
        if precheck_model() == FAILED:
            print("Prerequisite Check: 'Failed'")
            exit(1)
        else:
            print("Prerequisite Check: 'Passed'")
            exit(0)

    if args.model == "retire":
        retire_model()

    if args.model == "status":
        deployment_status, docker_running, service_running = check_deployment_status()
        print("Deployment Status: ", end="")
        if deployment_status == "Unknown":
            print("Unknown")
        else:
            print(f"{deployment_status}")
        print(f"Conjur appliance running: {docker_running}")
        print(f"Conjur service enabled: {service_running}")

    if args.sysctld == "config":
        sysctld_config()

    if args.test == "restart":
        restart_conjur_services(name="leadernode")

    if args.model == "health":
        # URL to fetch the health data from
        health_check_url = "http://localhost:444/health"
        # Fetch and analyze the health data
        fetch_and_analyze_health(health_check_url)