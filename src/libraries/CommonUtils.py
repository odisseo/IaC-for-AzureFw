import os
import sys
import logging
import yaml
import json
import shutil
import stat
import glob
import subprocess
from colorama import Fore, Style, init
from jinja2 import Environment, FileSystemLoader

# Initialize colorama for cross-platform color support
init(autoreset=True)

class CustomFormatter(logging.Formatter):
    """Custom logging formatter to add colors to log levels."""
    FORMATS = {
        logging.DEBUG: Style.DIM + "%(asctime)s - %(levelname)s - %(message)s",
        logging.INFO: Fore.GREEN + "%(asctime)s - %(levelname)s - %(message)s",
        logging.WARNING: Fore.YELLOW + "%(asctime)s - %(levelname)s - %(message)s",
        logging.ERROR: Fore.RED + "%(asctime)s - %(levelname)s - %(message)s",
        logging.CRITICAL: Fore.RED + Style.BRIGHT + "%(asctime)s - %(levelname)s - %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, "%(asctime)s - %(levelname)s - %(message)s")
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def configure_logging():
    """Configure logging settings with color support."""
    # Reset any existing handlers
    root = logging.getLogger()
    if root.handlers:
        for handler in root.handlers:
            root.removeHandler(handler)
    
    # Add our custom handler with formatter
    handler = logging.StreamHandler()
    handler.setFormatter(CustomFormatter())
    root.addHandler(handler)
    root.setLevel(logging.INFO)

def get_base_path():
    """Get the base path for the scripts, handling both frozen and unfrozen environments."""
    if getattr(sys, "frozen", False):
        # When running as a bundled executable, use the terminal's current directory.
        return os.getcwd()
    else:
        # When running as a normal Python script from the root, use the current directory
        # But go one level up from the libraries directory if run from there
        current_file_path = os.path.abspath(__file__)
        if "libraries" in current_file_path:
            # If running from the libraries directory, go up two levels (beyond scripts/libraries)
            return os.path.dirname(os.path.dirname(os.path.dirname(current_file_path)))
        else:
            # If running from root, use current directory
            return os.getcwd()# Base paths

def load_yaml_file(file_path):
    """Load YAML data from a file with proper error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = yaml.safe_load(file)
            return data
    except (OSError, yaml.YAMLError) as e:
        logging.error(f"Error loading YAML file {file_path}: {e}", exc_info=True)
        return None

def load_json_file(file_path):
    """Load JSON data from a file with proper error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            return data
    except (OSError, json.JSONDecodeError) as e:
        logging.error(f"Error loading JSON file {file_path}: {e}", exc_info=True)
        return None

def save_file(content, file_path):
    """Save content to a file with proper error handling."""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
        return True
    except Exception as e:
        logging.error(f"Error saving file {file_path}: {e}", exc_info=True)
        return False

def on_rm_error(func, path, exc_info):
    """Error handler for removing read-only files."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception as e:
        logging.error(f"Error removing file {path}: {e}", exc_info=True)

def clean_directory(directory):
    """Clean a directory by removing all files and subdirectories."""
    if os.path.exists(directory):
        logging.info(f"Cleaning directory: {directory}")
        try:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                try:
                    if os.path.isfile(item_path):
                        os.unlink(item_path)
                        logging.debug(f"Deleted file: {item_path}")
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path, onerror=on_rm_error)
                        logging.debug(f"Deleted directory: {item_path}")
                except Exception as e:
                    logging.error(f"Error removing {item_path}: {e}", exc_info=True)
            return True
        except Exception as e:
            logging.error(f"Error cleaning directory {directory}: {e}", exc_info=True)
            return False
    else:
        os.makedirs(directory, exist_ok=True)
        logging.info(f"Created new directory: {directory}")
        return True

def render_jinja_template(template_file, output_file, **kwargs):
    """Render a Jinja2 template to an output file."""
    try:
        env = Environment(loader=FileSystemLoader(searchpath=os.path.dirname(template_file)))
        template = env.get_template(os.path.basename(template_file))
        output = template.render(**kwargs)
        
        return save_file(output, output_file)
    except Exception as e:
        logging.error(f"Error rendering template {template_file} to {output_file}: {e}", exc_info=True)
        return False

def ensure_list(value):
    """Ensure the value is a list."""
    if isinstance(value, list):
        return value
    elif value is None:
        return []
    elif isinstance(value, str):
        return [value]
    return [str(value)]

def normalize_name(name):
    """Normalize a name by replacing spaces, hyphens, and "_-_" with underscores."""
    import re
    if not name:
        return ""
    return re.sub(r'[\s\-]+|_-_', '_', name)

def remove_date_suffix(name):
    """
    Remove the date suffix from the name.
    
    Removes suffix patterns like '_YYYYMMDD' or '-YYYYMMDD_randomstring' 
    that are often added to resource names in ARM templates.
    
    Args:
        name (str): The name from which to remove the date suffix
        
    Returns:
        str: The name without the date suffix
    """
    import re
    if not name:
        return ""
    # Remove _YYYYMMDD pattern
    name = re.sub(r'_\d{8}$', '', name)
    # Remove -YYYYMMDD_randomstring pattern (like -20250613_jkn5bz) or _YYYYMMDD_randomstring pattern (like _20250613_jkn5bz)
    name = re.sub(r'[-_]\d{8}_[a-z0-9]+$', '', name)
    return name

def commit_changes_to_git(changes_description="Exported Azure Firewall policies to Bicep", with_push=True):
    """
    Commit and push changes to Git repository.
    
    This function performs the following Git operations:
    1. Adds all changes to the staging area
    2. Creates a commit with the provided description
    3. Pushes the changes to the remote repository
    
    Args:
        changes_description (str): Description of the changes made. Can include
                                   formatted datetime and commit_suffix if provided.
        with_push (bool): Whether to push changes to remote repository
    
    Returns:
        tuple: (success, git_id) where success is a boolean and git_id is the commit ID or timestamp
    """
    import subprocess
    from datetime import datetime
    
    logging.info("Starting Git operations to commit and push changes...")
    
    try:
        # Use the provided commit message as is
        commit_message = changes_description
        
        # Git add all changes
        logging.info("Adding changes to Git staging area...")
        add_result = subprocess.run(["git", "add", "*"], 
                                    capture_output=True, 
                                    text=True, 
                                    check=False)
        
        if add_result.returncode != 0:
            logging.error(f"Failed to add files to Git: {add_result.stderr}")
            return False, None
        
        # Git commit with timestamp and description
        logging.info(f"Committing changes with message: {commit_message}")
        commit_result = subprocess.run(["git", "commit", "-m", commit_message], 
                                       capture_output=True, 
                                       text=True, 
                                       check=False)
        
        # Get commit ID (short hash)
        git_id = get_commit_id_with_date()
        if not git_id:
            git_id = datetime.now().strftime("%Y%m%d_%H%M%S")  # Fallback to timestamp
        
        if commit_result.returncode != 0:
            # Check if there's nothing to commit
            if "nothing to commit" in commit_result.stdout or "nothing to commit" in commit_result.stderr:
                logging.info("No changes to commit")
                return True, git_id
            else:
                logging.error(f"Failed to commit changes: {commit_result.stderr}")
                return False, None
        
        # Git push if requested
        if with_push:
            logging.info("Pushing changes to remote repository...")
            push_result = subprocess.run(["git", "push"], 
                                        capture_output=True, 
                                        text=True, 
                                        check=False)
            
            if push_result.returncode != 0:
                logging.error(f"Failed to push changes: {push_result.stderr}")
                return False, git_id  # Return ID even if push fails
        
        logging.info(f"Successfully committed changes to Git repository with ID: {git_id}")
        return True, git_id
        
    except Exception as e:
        logging.error(f"Error during Git operations: {str(e)}", exc_info=True)
        return False, None
    
def pull_changes_from_git(branch_name=None):
    """
    Pull the latest changes from the remote Git repository to the local branch.
    
    This function performs the following Git operations:
    1. Fetches the latest changes from the remote repository
    2. Pulls changes into the current or specified branch
    
    Args:
        branch_name (str, optional): The name of the branch to pull. If None, uses the current branch.
    
    Returns:
        bool: True if all Git operations were successful, False otherwise
    """
    import subprocess
    
    logging.info("Starting Git operations to pull latest changes...")
    
    try:
        # Fetch latest changes from remote
        logging.info("Fetching latest changes from remote repository...")
        fetch_result = subprocess.run(["git", "fetch"], 
                                      capture_output=True, 
                                      text=True, 
                                      check=False)
        
        if fetch_result.returncode != 0:
            logging.error(f"Failed to fetch from remote: {fetch_result.stderr}")
            return False
        
        # Prepare pull command
        pull_cmd = ["git", "pull"]
        if branch_name:
            # If branch name is specified, add origin and branch name
            current_branch = branch_name
            pull_cmd.extend(["origin", branch_name])
            logging.info(f"Pulling changes into branch: {branch_name}")
        else:
            # Get current branch name
            branch_result = subprocess.run(["git", "branch", "--show-current"], 
                                          capture_output=True, 
                                          text=True, 
                                          check=False)
            if branch_result.returncode != 0:
                logging.error(f"Failed to get current branch: {branch_result.stderr}")
                return False
            
            current_branch = branch_result.stdout.strip()
            logging.info(f"Pulling changes into current branch: {current_branch}")
        
        # Pull changes from remote
        pull_result = subprocess.run(pull_cmd, 
                                     capture_output=True, 
                                     text=True, 
                                     check=False)
        
        if pull_result.returncode != 0:
            logging.error(f"Failed to pull changes: {pull_result.stderr}")
            return False
        
        # Check if there were changes
        if "Already up to date" in pull_result.stdout:
            logging.info("Local branch is already up to date")
        else:
            logging.info(f"Successfully pulled latest changes into {current_branch}")
        
        return True
        
    except Exception as e:
        logging.error(f"Error during Git pull operations: {str(e)}", exc_info=True)
        return False
    
def get_commit_id_with_date():
    """
    Get the current Git commit ID combined with today's date.
    
    This function:
    1. Retrieves the short Git commit hash
    2. Combines it with the current date in YYYYMMDD format
    
    Returns:
        str: Formatted string as 'YYYYMMDD-commitid' (e.g., '20250506-6b334d2')
             or None if an error occurs
    """
    import subprocess
    from datetime import datetime
    
    logging.info("Getting current Git commit ID with date...")
    
    try:
        # Get short commit hash
        commit_result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False
        )
        
        if commit_result.returncode != 0:
            logging.error(f"Failed to get Git commit ID: {commit_result.stderr}")
            return None
        
        # Get the commit ID and remove any whitespace
        commit_id = commit_result.stdout.strip()
        
        # Get current date in YYYYMMDD format
        date_str = datetime.now().strftime("%Y%m%d")
        
        # Combine date and commit ID
        result = f"{date_str}_{commit_id}"
        logging.info(f"Generated commit ID with date: {result}")
        
        return result
        
    except Exception as e:
        logging.error(f"Error getting Git commit ID: {str(e)}", exc_info=True)
        return None
    
def get_id_with_date():
    """
    Generate an ID combined with today's date using the content hash from .sync_lock.
    
    This function:
    1. Reads the content hash from the .sync_lock file and takes the first 6 characters
    2. Combines it with the current date in YYYYMMDD format
    
    Returns:
        str: Formatted string as 'YYYYMMDD_hash6chars' (e.g., '20250612_dd3747')
             or None if an error occurs
    
    Raises:
        ValueError: If .sync_lock file doesn't exist or has invalid format
    """
    import os
    from datetime import datetime
    
    logging.info("Generating ID with date from content hash...")
    
    try:
        # Get current date in YYYYMMDD format
        date_str = datetime.now().strftime("%Y%m%d")
        
        # Path to .sync_lock file at the project root
        sync_lock_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.sync_lock')
        
        # Read the content hash from .sync_lock
        if os.path.exists(sync_lock_path):
            with open(sync_lock_path, 'r') as file:
                content = file.read().strip()
                parts = content.split('|')
                if len(parts) >= 3:
                    # Extract the content hash (third element) and take first 6 chars
                    content_hash = parts[2][:6]
                    # Combine date and content hash
                    result = f"{date_str}_{content_hash}"
                    logging.info(f"Generated ID with date and content hash: {result}")
                    return result
                else:
                    error_msg = "Invalid format in .sync_lock file. Please run a policy sync operation to regenerate it."
                    logging.error(error_msg)
                    raise ValueError(error_msg)
        else:
            error_msg = ".sync_lock file not found. Please run a policy sync operation to generate it."
            logging.error(error_msg)
            raise ValueError(error_msg)
        
    except Exception as e:
        if isinstance(e, ValueError):
            # Re-raise ValueError exceptions
            raise
        
        error_msg = f"Error generating ID: {str(e)}. Please run a policy sync operation to resolve this issue."
        logging.error(error_msg, exc_info=True)
        raise ValueError(error_msg)

def get_prod_tenant_id():
    """Get tenant ID from the production firewall in the YAML configuration."""
    firewalls_dir = os.path.join(get_base_path(), '_firewalls')
    yaml_files = sorted(glob.glob(os.path.join(firewalls_dir, "*.yaml")))
    
    for yaml_file in yaml_files:
        try:
            with open(yaml_file, 'r') as f:
                firewalls = yaml.safe_load(f)
                if not firewalls:
                    continue
                
                # Find the production firewall
                for firewall in firewalls:
                    if firewall.get('regionType') == 'Prod':
                        return firewall.get('tenantId')
        except Exception as e:
            logging.warning(f"Error reading {yaml_file}: {str(e)}")
            continue
    
    return None

def ensure_azure_login():
    """
    Ensure user is logged into Azure with the correct tenant and subscription.
    This function should be called before any Azure CLI operations.
    """
    tenant_id = get_prod_tenant_id()
    if not tenant_id:
        raise ValueError("Could not find production tenant ID in firewall configuration")
    
    try:
        # First check if already logged in and using correct tenant
        check_cmd = "az account show --query tenantId -o tsv"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip() == tenant_id:
            logging.info("Already logged into the correct Azure tenant")
        else:
            # If not logged in or wrong tenant, perform login
            login_cmd = f"az login --tenant {tenant_id}"
            logging.info(f"Executing Azure login command: {login_cmd}")
            
            # Run the login command and capture all output
            result = subprocess.run(login_cmd, shell=True, capture_output=True, text=True)
            
            # Log the complete output for debugging
            if result.stdout:
                logging.info(f"Login command stdout:\n{result.stdout}")
            if result.stderr:
                logging.warning(f"Login command stderr:\n{result.stderr}")
                
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, login_cmd, result.stdout, result.stderr)
            
            logging.info("Azure login command completed")
        
        # List available subscriptions for this tenant
        list_cmd = f"az account list --query \"[?tenantId=='{tenant_id}']\" -o json"
        logging.info("Listing available subscriptions...")
        result = subprocess.run(list_cmd, shell=True, capture_output=True, text=True)
        
        if result.stdout:
            logging.info(f"Subscription list output:\n{result.stdout}")
        if result.stderr:
            logging.warning(f"Subscription list stderr:\n{result.stderr}")
        
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, list_cmd, result.stdout, result.stderr)
        
        subscriptions = json.loads(result.stdout)
        if not subscriptions:
            raise ValueError(f"No subscriptions found for tenant {tenant_id}")
        
        # Log all available subscriptions
        logging.info("Available subscriptions:")
        for sub in subscriptions:
            logging.info(f"- {sub.get('name')} ({sub.get('id')})")
        
        # Select the first available subscription
        subscription_id = subscriptions[0]['id']
        subscription_name = subscriptions[0]['name']
        
        # Set the active subscription
        set_cmd = f"az account set --subscription {subscription_id}"
        logging.info(f"Setting active subscription to: {subscription_name}")
        result = subprocess.run(set_cmd, shell=True, capture_output=True, text=True)
        
        if result.stdout:
            logging.info(f"Set subscription output:\n{result.stdout}")
        if result.stderr:
            logging.warning(f"Set subscription stderr:\n{result.stderr}")
        
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, set_cmd, result.stdout, result.stderr)
        
        logging.info(f"Successfully logged into Azure and set subscription to: {subscription_name}")
        return True
            
    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to login to Azure: {e.stderr if hasattr(e, 'stderr') else str(e)}"
        logging.error(error_msg)
        raise ValueError(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error during Azure login: {str(e)}"
        logging.error(error_msg)
        raise ValueError(error_msg)
