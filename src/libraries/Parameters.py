import os
import sys
import json
import argparse
from pathlib import Path
import logging
import glob
import yaml
from src.libraries.CommonUtils import load_yaml_file, get_base_path, configure_logging

##########################################################################
# Global Variables
##########################################################################

BASE_PATH = get_base_path()

# Project directory structure
class Paths:
    DEFAULT_LOCATION = 'westeurope'
    # Add BASE_PATH as a class attribute
    BASE_PATH = BASE_PATH
    # Base directories
    ARM_DIR = os.path.join(BASE_PATH, 'arm_import')  # ARM import directory
    ARM_EXPORT_DIR = os.path.join(BASE_PATH, 'arm_export')  # Directory for exported ARM templates
    POLICIES_DIR = os.path.join(BASE_PATH, '_policies')
    CSV_DIR = os.path.join(BASE_PATH, '_csv')
    TEMPLATES_DIR = os.path.join(BASE_PATH, 'src', 'templates')  # Templates under src
    BICEP_DIR = os.path.join(BASE_PATH, 'bicep')
    FIREWALLS_DIR = os.path.join(BASE_PATH, '_firewalls')
    COMPARISON_DIR = os.path.join(BASE_PATH, 'comparison')  # Directory for comparison results
    
    # ARM template files
    IPGROUPS_JSON = os.path.join(ARM_DIR, 'ipgroups.json')
    POLICIES_JSON = os.path.join(ARM_DIR, 'policies.json')
    
    # Template files remain the same since they are now relative to TEMPLATES_DIR
    TEMPLATE_NAT = os.path.join(TEMPLATES_DIR, 'nat_rules.csv.jinja2')
    TEMPLATE_NETWORK = os.path.join(TEMPLATES_DIR, 'network_rules.csv.jinja2')
    TEMPLATE_APPLICATION = os.path.join(TEMPLATES_DIR, 'application_rules.csv.jinja2')
    TEMPLATE_CSV = os.path.join(TEMPLATES_DIR, 'policy.csv.jinja2')
    TEMPLATE_POLICY_BICEP = os.path.join(TEMPLATES_DIR, 'policy.bicep.jinja2')
    TEMPLATE_POLICY_YAML = os.path.join(TEMPLATES_DIR, 'policy.yaml.jinja2')
    TEMPLATE_RCG_YAML = os.path.join(TEMPLATES_DIR, 'rcg.yaml.jinja2')
    TEMPLATE_RC_YAML = os.path.join(TEMPLATES_DIR, 'rc.yaml.jinja2')

    # Ensure all directories exist
    @staticmethod
    def ensure_directories_exist():
        """Create all required directories if they don't exist."""
        directories = [
            Paths.ARM_DIR,
            Paths.ARM_EXPORT_DIR,
            Paths.IPGROUPS_DIR,
            Paths.POLICIES_DIR,
            Paths.CSV_DIR, 
            Paths.BICEP_DIR,
            Paths.FIREWALLS_DIR,
            Paths.COMPARISON_DIR,
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
    DEFAULT_SUBSCRIPTION = os.getenv('AZURE_SUBSCRIPTION_ID', '00000000-0000-0000-0000-000000000000')
    DEFAULT_TENANT = os.getenv('AZURE_TENANT_ID', '00000000-0000-0000-0000-000000000000')

############################################################################
# In line parameters
############################################################################

def parse_arguments():
    """Parse command line arguments with detailed help information."""
    parser = argparse.ArgumentParser(
        description='''PoliFire (Azure Firewall Policies Infrastructure as Code)
        
This tool provides a complete workflow for managing Azure Firewall Policies using YAML files as the source of truth,
with conversion to/from CSV and ARM/Bicep templates for deployment to Azure. 

AFPIAC stands for "Azure Firewall Policies Infrastructure as Code" - a methodology for managing 
firewall policies through version-controlled configuration files rather than manual configuration.''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Workflow Overview:
  1. Maintain firewall policy configurations in YAML files (in _policies/ directory)
  2. Synchronize between YAML and CSV files for easier editing (operation 4)
  3. Export to Bicep/ARM templates (operation 5)
  4. Compare the exported templates with deployed resources (operation 6)
  5. Deploy updates to Azure (operation 8)
  6. Commit changes to version control (operation 7)

Examples:
  # List available environments
  python AzFwManager.py --list-environments
  
  # Export policies to Bicep using a specific firewall key
  python AzFwManager.py --environment Test --operation 5
  
  # Export policies to Bicep using an index
  python AzFwManager.py --environment 1 --operation 5
  
  # Synchronize policies between YAML and CSV
  python AzFwManager.py --operation 4
  
  # Update your local repository with latest changes
  python AzFwManager.py --operation 1
  
  # Compare ARM templates between import and export directories
  python AzFwManager.py --operation 6 --include-diff
  
  # Download latest ARM templates from Azure
  python AzFwManager.py --operation 2 --environment Test
  
  # Deploy Bicep templates to Azure
  python AzFwManager.py --operation 8 --environment Test
  
  # Commit changes to Git repository
  python AzFwManager.py --operation 7 --commit-message "Updated firewall policies"
  
Operations:
  1: Update local Git repository (pull latest changes)
  2: Download the latest ARM templates from Azure
  3: Import policies from ARM templates to YAML format
  4: Synchronize policies between YAML and CSV formats
  5: Export policies from YAML to Bicep templates
  6: Compare ARM Templates between Import and Export directories
  7: Commit all changes to Git repository
  8: Deploy new Bicep templates to Azure
''')
    
    parser.add_argument('--environment', '-e', type=str, metavar='ENV',
                        help='Specify the firewall key, index, or firewall name')
    parser.add_argument('--operation', '-o', type=int, choices=[1, 2, 3, 4, 5, 6, 7, 8], metavar='OP',
                        help='Select operation to perform')
    parser.add_argument('--list-environments', '-l', action='store_true',
                        help='List available Azure Firewall groups and exit')
    parser.add_argument('--include-diff', '-d', action='store_true', default=False,
                        help='Show sample of differences in the console output when comparing ARM templates (for operation 6)')
    parser.add_argument('--save-results', '-r', action='store_true', default=True,
                        help='Save comparison results to JSON file with clear import vs export differences (for operation 6). Default is True.')
    parser.add_argument('--non-interactive', '-n', action='store_true',
                        help='Run in non-interactive mode (requires --environment, --operation and --conflict-resolution for sync operations)')
    parser.add_argument('--skip-git', '-s', action='store_true',
                        help='Skip Git operations when exporting policies')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--conflict-resolution', '-c', type=str, choices=['policies', 'csv', 'cancel'],
                        help='Specify how to resolve conflicts in non-interactive mode: "policies" to use YAML policies as source, "csv" to use CSV files as source, or "cancel" to abort')
    parser.add_argument('--commit-message', '-m', type=str,
                        help='Custom commit message when using operation 7 (Commit all changes to Git)')
    parser.add_argument('--skip-download-prompt', '-p', action='store_true',
                        help='Skip the prompt to download latest templates when running operation 6 (Compare ARM Templates)')
    parser.add_argument('--clean-export', action='store_true', default=True,
                        help='Clean the export directory before generating new ARM templates (for operations 5 and 6). Default is True.')
    
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
                required_fields = ["firewallName", "subscriptionId", "ipGroupsResourceGroup", "policiesResourceGroup", "tenantId", "ipGroupssubscriptionId"]
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
                    "regionName": Config.DEFAULT_LOCATION,
                    "tenantId": Config.DEFAULT_TENANT
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
                "regionName": Config.DEFAULT_LOCATION,
                "tenantId": Config.DEFAULT_TENANT
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

# Initialize paths when module is imported
try:
    Paths.ensure_directories_exist()
except Exception as e:
    logging.warning(f"Failed to create one or more directories: {str(e)}")
