import os
import sys
import json
import argparse
from pathlib import Path
import logging
import glob
import yaml
from scripts.libraries.CommonUtils import load_yaml_file, get_base_path, configure_logging

##########################################################################
# Global Variables
##########################################################################

BASE_PATH = get_base_path()

# Project directory structure
class Paths:
    DEFAULT_LOCATION = 'westeurope'
    # Base directories
    ARM_DIR = os.path.join(BASE_PATH, 'arm')  # Removed '..' since we're already at root
    IPGROUPS_DIR = os.path.join(BASE_PATH, '_ipgroups')
    POLICIES_DIR = os.path.join(BASE_PATH, '_policies')
    CSV_DIR = os.path.join(BASE_PATH, '_csv')
    TEMPLATES_DIR = os.path.join(BASE_PATH, 'scripts', 'templates')  # Updated path to templates
    BICEP_DIR = os.path.join(BASE_PATH, 'bicep')
    FIREWALLS_DIR = os.path.join(BASE_PATH, '_firewalls')
    
    # Config files
    FW_LIST_JSON = os.path.join(BASE_PATH, 'scripts', 'libraries', 'FWList.js')  # Updated path
    
    # ARM template files
    IPGROUPS_JSON = os.path.join(ARM_DIR, 'ipgroups.json')
    POLICIES_JSON = os.path.join(ARM_DIR, 'policies.json')
    
    # Template files remain the same since they are now relative to TEMPLATES_DIR
    TEMPLATE_NAT = os.path.join(TEMPLATES_DIR, 'nat_rules.csv.jinja2')
    TEMPLATE_NETWORK = os.path.join(TEMPLATES_DIR, 'network_rules.csv.jinja2')
    TEMPLATE_APPLICATION = os.path.join(TEMPLATES_DIR, 'application_rules.csv.jinja2')
    TEMPLATE_CSV = os.path.join(TEMPLATES_DIR, 'policy.csv.jinja2')
    TEMPLATE_POLICY_BICEP = os.path.join(TEMPLATES_DIR, 'policy.bicep.jinja2')
    TEMPLATE_IPGROUPS_BICEP = os.path.join(TEMPLATES_DIR, 'ipgroups.bicep.jinja2')
    TEMPLATE_POLICY_YAML = os.path.join(TEMPLATES_DIR, 'policy.yaml.jinja2')
    TEMPLATE_RCG_YAML = os.path.join(TEMPLATES_DIR, 'rcg.yaml.jinja2')
    TEMPLATE_RC_YAML = os.path.join(TEMPLATES_DIR, 'rc.yaml.jinja2')

    WORKING_DIR = BASE_PATH
    
    # Ensure all directories exist
    @staticmethod
    def ensure_directories_exist():
        """Create all required directories if they don't exist."""
        directories = [
            Paths.ARM_DIR,
            Paths.IPGROUPS_DIR,
            Paths.POLICIES_DIR,
            Paths.CSV_DIR, 
            Paths.BICEP_DIR,
            Paths.FIREWALLS_DIR
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            
        return True

# Default configuration
class Config:
    # BICEP API Version
    FIREWALL_API_VERSION = "2024-05-01"
    
    # Default firewall name
    FIREWALL_NAME = os.getenv('FIREWALL_NAME', 'DEFAULT')
    
    # Log settings
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # Azure settings
    DEFAULT_LOCATION = os.getenv('AZURE_LOCATION', 'westeurope')
    DEFAULT_SUBSCRIPTION = os.getenv('AZURE_SUBSCRIPTION_ID', 'bca4dc33-1167-40aa-930c-0c0da34be971')

############################################################################
# In line parameters
############################################################################

def parse_arguments():
    """Parse command line arguments with detailed help information."""
    parser = argparse.ArgumentParser(
        description='Azure Firewall Policy Manager',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # List available environments
  python AzFwManager.py --list-environments
  
  # Export policies to Bicep using a specific firewall key
  python AzFwManager.py --environment Test --operation 4
  
  # Export policies to Bicep using an index
  python AzFwManager.py --environment 1 --operation 4
  
  # Synchronize policies between YAML and CSV
  python AzFwManager.py --operation 3
  
  # Update your local repository with latest changes
  python AzFwManager.py --operation 1
  
Operations:
  1: Update your local repository from Git
  2: Import policies from ARM templates
  3: Synchronize policies between YAML and CSV
  4: Export policies to Bicep (and optionally deploy)
''')
    
    parser.add_argument('--environment', '-e', type=str, metavar='ENV',
                      help='Specify the firewall key, index, or firewall name')
    parser.add_argument('--operation', '-o', type=int, choices=[1, 2, 3, 4], metavar='OP',
                      help='Select operation to perform')
    parser.add_argument('--list-environments', '-l', action='store_true',
                      help='List available Azure Firewall groups and exit')
    parser.add_argument('--non-interactive', '-n', action='store_true',
                      help='Run in non-interactive mode (requires --environment, --operation and --conflict-resolution)')
    parser.add_argument('--skip-git', '-s', action='store_true',
                      help='Skip Git operations when exporting policies')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Enable verbose output'),
    parser.add_argument('--conflict-resolution', '-c', type=str, choices=['policies', 'csv', 'cancel'],
                      help='Specify how to resolve conflicts in non-interactive mode: "policies" to use YAML policies as source, "csv" to use CSV files as source, or "cancel" to abort')
    
    return parser.parse_args()

def get_environment_from_cmdline(environment_name):
    """
    Get firewall key based on the provided environment name or index.
    
    Args:
        environment_name: Environment identifier (firewall key, index, or firewall name)
        
    Returns:
        str: Firewall key or None if not found
    """
    if not environment_name:
        return None
    
    # Get environment list for index lookup
    environments = get_environment_list()
    
    # Case 1: Direct match with a firewall key
    for idx, key in environments:
        if key == environment_name:
            logging.info(f"Using firewall key from command line: {key}")
            return key
    
    # Case 2: Match with an index
    try:
        env_idx = int(environment_name)
        for idx, key in environments:
            if int(idx) == env_idx:
                logging.info(f"Using firewall key from index {env_idx}: {key}")
                return key
    except ValueError:
        pass
    
    # Case 3: Match with a firewall name
    for fw_group in FIREWALL_DATA:
        key = fw_group.get("FirewallKey", "")
        firewalls = fw_group.get("Firewalls", [])
        
        for fw in firewalls:
            if fw.get("firewallName") == environment_name:
                logging.info(f"Found firewall key {key} for firewall name: {environment_name}")
                return key
    
    # No match found
    logging.warning(f"Environment '{environment_name}' not found")
    return None

def list_available_environments(interactive=False):
    """
    List all available firewall groups and their associated firewalls.
    
    Args:
        interactive: If True, prompt the user to select an environment
        
    Returns:
        If interactive is True: tuple of (idx, key) for the selected environment
        If interactive is False: None
    """
    environments = get_environment_list()
    
    print("\nAvailable firewall groups:")
    for idx, key in environments:
        firewalls = get_firewalls_by_key(key)
        firewall_names = [fw.get("firewallName", "Unknown") for fw in firewalls]
        firewall_str = ", ".join(firewall_names)
        print(f"{idx}. {key} ({len(firewalls)} firewalls: {firewall_str})")
    
    if interactive:
        while True:
            try:
                choice = input("\nSelect an environment (number): ")
                if not choice.strip():
                    return None
                
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(environments):
                    return environments[choice_idx]
                else:
                    print(f"Invalid choice. Please enter a number between 1 and {len(environments)}.")
            except ValueError:
                print("Please enter a valid number.")
    
    return None

##########################################################################
# Firewall Data 
##########################################################################

def load_firewall_data():
    """
    Load firewall data from YAML files in the _firewalls directory.
    
    The filename format should be: NUMBER.FWKEY.yaml
    For example: 1.Test.yaml, 2.MIME.yaml
    
    Returns:
        list: List of dictionaries with FirewallKey, FirewallOrder, and Firewalls
    """
    firewall_data = []
    configure_logging()
    try:
        # Make sure the firewalls directory exists
        os.makedirs(Paths.FIREWALLS_DIR, exist_ok=True)
        
        # Get all yaml files in the _firewalls directory
        yaml_files = sorted(glob.glob(os.path.join(Paths.FIREWALLS_DIR, "*.yaml")))
        
        if not yaml_files:
            logging.error("No firewall YAML files found in directory")
            return []
            
        # Process each YAML file
        for yaml_file in yaml_files:
            # Extract the key and order from the filename (e.g., "Test" and "1" from "1.Test.yaml")
            filename = os.path.basename(yaml_file)
            name_parts = filename.split('.')
            
            if len(name_parts) < 2:
                logging.warning(f"Filename {filename} doesn't match expected pattern NUMBER.KEY.yaml")
                continue
                
            try:
                fw_order = int(name_parts[0])  # Take the first part as the order
                fw_key = name_parts[1]         # Take the second part as the key
            except ValueError:
                logging.warning(f"Invalid order number in filename {filename}")
                continue
            
            fw_config = load_yaml_file(yaml_file)
            
            if not fw_config or not isinstance(fw_config, list):
                logging.warning(f"Invalid or empty configuration in {yaml_file}")
                continue
            
            # Validate each firewall configuration has required fields
            valid_firewalls = []
            for fw in fw_config:
                required_fields = ["firewallName", "subscriptionId", "ipGroupsResourceGroup", "policiesResourceGroup"]
                missing_fields = [field for field in required_fields if not fw.get(field)]
                
                if missing_fields:
                    logging.warning(f"Skipping firewall with missing fields: {', '.join(missing_fields)}")
                    continue
                    
                # Add regionName if not present
                if "regionName" not in fw:
                    fw["regionName"] = Paths.DEFAULT_LOCATION
                    
                valid_firewalls.append(fw)
            
            # Only add entry if it has valid firewalls
            if valid_firewalls:
                # Create a new entry for this firewall key
                firewall_entry = {
                    "FirewallKey": fw_key,
                    "FirewallOrder": fw_order,
                    "Firewalls": valid_firewalls
                }
                
                # Add to the firewall data list
                firewall_data.append(firewall_entry)
            else:
                logging.warning(f"No valid firewall configurations found in {yaml_file}")
        
        # Sort the list by FirewallOrder
        firewall_data.sort(key=lambda x: x["FirewallOrder"])
        
        total_entries = len(firewall_data)
        total_firewalls = sum(len(entry["Firewalls"]) for entry in firewall_data)
        logging.info(f"Loaded {total_firewalls} firewall configurations across {total_entries} environment keys")
        
        # If no data loaded, add a placeholder entry
        if not firewall_data:
            logging.warning("No valid firewall data found, adding placeholder entry")
            firewall_data.append({
                "FirewallKey": "Demo",
                "FirewallOrder": 1,
                "Firewalls": [{
                    "firewallName": Config.FIREWALL_NAME,
                    "subscriptionId": Config.DEFAULT_SUBSCRIPTION,
                    "ipGroupsResourceGroup": "rg-ipgroups",
                    "policiesResourceGroup": "rg-policies",
                    "regionName": Config.DEFAULT_LOCATION
                }]
            })
            
        return firewall_data
    except Exception as e:
        logging.error(f"Failed to load firewall data from YAML files: {str(e)}")
        # Return a placeholder entry for fallback
        return [{
            "FirewallKey": "Demo",
            "FirewallOrder": 1,
            "Firewalls": [{
                "firewallName": Config.FIREWALL_NAME,
                "subscriptionId": Config.DEFAULT_SUBSCRIPTION,
                "ipGroupsResourceGroup": "rg-ipgroups",
                "policiesResourceGroup": "rg-policies",
                "regionName": Config.DEFAULT_LOCATION
            }]
        }]

# Load firewall data at module import time
FIREWALL_DATA = load_firewall_data()
DEFAULT_FIREWALL = FIREWALL_DATA[0] if FIREWALL_DATA else None

def get_environment_list():
    """
    Get a list of available environment keys based on the firewall data.
    
    Returns:
        list: List of (index, key) tuples for each firewall key group
    """
    environments = []
    
    # If no firewall data is loaded, return empty list
    if not FIREWALL_DATA:
        logging.warning("No firewall data available")
        return environments
    
    # Add environments from firewall data
    for idx, fw_group in enumerate(FIREWALL_DATA, 1):
        key = fw_group.get("FirewallKey", "")
        
        # Skip entries with placeholder values
        if not key or "TBD" in key:
            continue
        
        # Add to environments list with index
        environments.append((str(idx), key))
    
    # Sort by FirewallOrder
    environments.sort(key=lambda x: next((fw["FirewallOrder"] for fw in FIREWALL_DATA if fw["FirewallKey"] == x[1]), 999))
    
    return environments

def get_firewalls_by_key(firewall_key):
    """
    Get all firewalls associated with a specific firewall key.
    
    Args:
        firewall_key: The firewall key to lookup
        
    Returns:
        list: List of firewall configurations for the specified key or empty list if not found
    """
    if not firewall_key or not FIREWALL_DATA:
        return []
    
    for fw_group in FIREWALL_DATA:
        if fw_group.get("FirewallKey") == firewall_key:
            return fw_group.get("Firewalls", [])
    
    return []

def get_firewall_parameters(firewall_name):
    """
    Get parameters for a specific firewall by name.
    
    Args:
        firewall_name: Name of the firewall
        
    Returns:
        dict: Dictionary with firewall parameters or None if not found
    """
    if not firewall_name or not FIREWALL_DATA:
        return None
        
    for fw_group in FIREWALL_DATA:
        firewalls = fw_group.get("Firewalls", [])
        for fw in firewalls:
            if fw.get("firewallName") == firewall_name:
                return {
                    "subscriptionid": fw.get("subscriptionId", Config.DEFAULT_SUBSCRIPTION),
                    "ipgrouprg": fw.get("ipGroupsResourceGroup", ""),
                    "policiesrg": fw.get("policiesResourceGroup", ""),
                    "firewallname": fw.get("firewallName", ""),
                    "regionName": fw.get("regionName", Config.DEFAULT_LOCATION)
                }
    
    return None

# Initialize paths when module is imported
try:
    Paths.ensure_directories_exist()
except Exception as e:
    logging.warning(f"Failed to create one or more directories: {str(e)}")