import os
import sys
import logging
import glob
import json
import subprocess
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from colorama import Fore, Style, init
from src.libraries.CommonUtils import get_base_path, clean_directory, load_yaml_file, load_json_file, save_file, remove_date_suffix, ensure_azure_login

# Initialize colorama for cross-platform color support
init(autoreset=True)
from src.libraries.YamlUtils import (
    yaml_create_policies_structure, 
    normalize_name, 
    extract_base_policy_name,
    compare_policy_sets,
    format_ip_group
)
from src.libraries.CsvUtils import csv_collect_policy_data, csv_render_csv
from src.libraries.Parameters import Paths, Config

def validate_import_files():
    """
    Validate that the required JSON files exist for import.
    
    Returns:
        bool: True if files exist, False otherwise
    """
    if not os.path.exists(Paths.POLICIES_JSON):
        logging.error(f"Error: policies.json must be present in the arm_import folder: {Paths.POLICIES_JSON}")
        return False
        
    return True

def import_policies(firewall_key=None):
    """
    Import Azure Firewall policies from individual ARM templates to YAML structure.
    Also generates CSV files for policy visualization.
    
    Args:
        firewall_key: Optional firewall key to override the default

    Returns:
        tuple: (success, message) where success is a boolean and message provides
               information about the operation
    """
    # Use provided firewall name or default
    fw_name = firewall_key or Config.FIREWALL_NAME
    
    # Ensure directories exist
    os.makedirs(Paths.POLICIES_DIR, exist_ok=True)
    os.makedirs(Paths.CSV_DIR, exist_ok=True)
    
    # Get list of all JSON files in the ARM directory
    arm_files = glob.glob(os.path.join(Paths.ARM_DIR, "*.json"))
    if not arm_files:
        logging.error(f"No ARM template files found in {Paths.ARM_DIR}")
        return False, "No ARM template files found"

    # Compare existing policies with new ones to be imported
    differences, existing_policies, new_policies = compare_policy_sets(arm_files)
    
    if existing_policies:
        # Show the comparison
        print("\nPolicy Comparison Summary:")
        print("=" * 50)
        
        if differences['removed']:
            print(f"\n{Fore.RED}Policies to be removed ({len(differences['removed'])}):{Style.RESET_ALL}")
            for policy in sorted(differences['removed']):
                print(f"  - {policy}")
        
        if differences['added']:
            print(f"\n{Fore.GREEN}New policies to be added ({len(differences['added'])}):{Style.RESET_ALL}")
            for policy in sorted(differences['added']):
                print(f"  + {policy}")
        
        if differences['common']:
            print(f"\n{Fore.YELLOW}Existing policies to be updated ({len(differences['common'])}):{Style.RESET_ALL}")
            for policy in sorted(differences['common']):
                print(f"  * {policy}")
        
        print("\nTotal changes:")
        print(f"  Removed: {len(differences['removed'])}")
        print(f"  Added: {len(differences['added'])}")
        print(f"  Updated: {len(differences['common'])}")
        print("=" * 50)
        
        # Ask for confirmation
        response = input("\nDo you want to proceed with these changes? (y/n): ").lower()
        if response != 'y':
            return False, "Operation cancelled by user"
    
    # Clean the policies directory before creating new structure
    logging.info("Cleaning policies directory before creating new structure...")
    if not clean_directory(Paths.POLICIES_DIR):
        logging.error("Failed to clean policies directory")
        return False, "Failed to clean policies directory"

    logging.info(f"Found {len(arm_files)} ARM template files to process")
    
    # Track overall success
    all_policies_processed = True
    policies_processed = 0
    
    # Process each ARM template file individually
    for arm_file in arm_files:
        try:
            logging.info(f"Processing ARM template: {os.path.basename(arm_file)}")
            
            # Load the ARM template
            data = load_json_file(arm_file)
            if not data:
                logging.error(f"Failed to load ARM template: {arm_file}")
                all_policies_processed = False
                continue
            
            # Find the main firewall policy resource and its associated rule collection groups
            policy_resource = None
            rule_collection_groups = []
            
            for resource in data.get('resources', []):
                if resource['type'] == 'Microsoft.Network/firewallPolicies':
                    policy_resource = resource
                elif resource['type'] == 'Microsoft.Network/firewallPolicies/ruleCollectionGroups':
                    rule_collection_groups.append(resource)
            
            if not policy_resource:
                logging.error(f"No firewall policy found in {arm_file}")
                all_policies_processed = False
                continue
              # Get the base policy name (without version suffix)
            policy_name = policy_resource['name']
            # Remove any date suffix from the policy name
            base_name = remove_date_suffix(policy_name)
            
            policy_name_normalized = normalize_name(base_name)
            
            # Create policy directory
            policy_dir = os.path.join(Paths.POLICIES_DIR, policy_name_normalized)
            os.makedirs(policy_dir, exist_ok=True)
            
            # Set up Jinja templates
            env = Environment(loader=FileSystemLoader(Paths.TEMPLATES_DIR))
            policy_template = env.get_template('policy.yaml.jinja2')
            rule_collection_group_template = env.get_template('rcg.yaml.jinja2')
            rule_collection_template = env.get_template('rc.yaml.jinja2')
            
            # Extract base policy if it exists
            base_policy = ''
            if 'basePolicy' in policy_resource.get('properties', {}):
                base_policy = extract_base_policy_name(policy_resource['properties']['basePolicy'])
            
            # Create main.yaml in policy directory
            main_yaml_path = os.path.join(policy_dir, 'main.yaml')
            main_yaml_content = policy_template.render(
                base_policy=base_policy,
                api_version=Config.FIREWALL_API_VERSION
            )
            if not save_file(main_yaml_content, main_yaml_path):
                logging.error(f"Failed to save main policy YAML for {policy_name_normalized}")
                all_policies_processed = False
                continue
            
            # Process rule collection groups
            for rcg in rule_collection_groups:
                try:                    # Extract RCG name and priority
                    rcg_name_parts = rcg['name'].split('/')  # Split policy/rcg name
                    rcg_name = rcg_name_parts[-1]  # Get the RCG name part
                    rcg_properties = rcg.get('properties', {})
                    rcg_priority = str(rcg_properties.get('priority', '1000')).zfill(5)  # Pad priority with zeros
                    
                    # Clean RCG name more robustly
                    rcg_clean_name = rcg_name
                    if '_' in rcg_name:
                        try:
                            # Split on first underscore and check if first part is a number
                            parts = rcg_name.split('_', 1)
                            if len(parts) > 1:
                                # If first part is a number (priority), take the rest
                                if parts[0].isdigit():
                                    rcg_clean_name = parts[1]
                                else:
                                    # If first part isn't a number, keep the original name
                                    # as it might be a meaningful underscore
                                    rcg_clean_name = rcg_name
                        except Exception:
                            # If any error occurs during splitting, keep original name
                            rcg_clean_name = rcg_name
                    
                    # Clean RCG name of any special characters that might cause issues
                    rcg_clean_name = normalize_name(rcg_clean_name)
                    
                    # Create RCG directory with priority prefix
                    rcg_dir = os.path.join(policy_dir, f"{rcg_priority}_{rcg_clean_name}")
                    os.makedirs(rcg_dir, exist_ok=True)
                    
                    logging.info(f"Creating RCG directory: {rcg_dir}")
                    
                    # Create main.yaml in RCG directory
                    rcg_main_yaml_path = os.path.join(rcg_dir, 'main.yaml')
                    rcg_main_yaml_content = rule_collection_group_template.render(
                        api_version=Config.FIREWALL_API_VERSION
                    )
                    if not save_file(rcg_main_yaml_content, rcg_main_yaml_path):
                        logging.error(f"Failed to save RCG main YAML for {rcg_clean_name}")
                        continue
                    
                    # Process rule collections within this RCG
                    for rc in rcg_properties.get('ruleCollections', []):
                        rc_name = rc.get('name', '')
                        # Clean RC name
                        rc_name = normalize_name(rc_name)
                        rc_priority = str(rc.get('priority', '1000')).zfill(5)  # Pad priority with zeros
                          # Format rule IP groups before rendering
                        rules = rc.get('rules', [])
                        for rule in rules:
                            # Format source IP groups
                            source_ip_groups = rule.get('sourceIpGroups', [])
                            if source_ip_groups:
                                rule['sourceIpGroups'] = [format_ip_group(group) for group in source_ip_groups]
                            
                            # Format destination IP groups
                            dest_ip_groups = rule.get('destinationIpGroups', [])
                            if dest_ip_groups:
                                rule['destinationIpGroups'] = [format_ip_group(group) for group in dest_ip_groups]
                        
                        # Create RC YAML file with priority prefix
                        rc_yaml_path = os.path.join(rcg_dir, f"{rc_priority}_{rc_name}.yaml")
                        rc_yaml_content = rule_collection_template.render(
                            name=rc_name,
                            priority=rc_priority,
                            rule_collection_type=rc.get('ruleCollectionType', ''),
                            action=rc.get('action', {}).get('type', 'Allow'),
                            rules=rules,
                            api_version=Config.FIREWALL_API_VERSION
                        )
                        if not save_file(rc_yaml_content, rc_yaml_path):
                            logging.error(f"Failed to save RC YAML for {rc_name}")
                            continue
                
                except Exception as e:
                    logging.error(f"Error processing RCG {rcg_clean_name}: {str(e)}")
                    continue
            
            policies_processed += 1
            logging.info(f"Successfully processed policy {policy_name_normalized}")
            
        except Exception as e:
            logging.error(f"Error processing ARM template {arm_file}: {str(e)}")
            all_policies_processed = False
            continue
    
    # Generate CSV files from the updated policies directory
    logging.info("Generating CSV files from processed policies...")
    resources_nat, resources_network, resources_application = csv_collect_policy_data(Paths.POLICIES_DIR)
    
    # Clean CSV directory before generating new files
    clean_directory(Paths.CSV_DIR)
    
    # NAT Rules
    if resources_nat:
        logging.info(f"Collected {len(resources_nat)} NAT resources")
        csv_output_path_nat = os.path.join(Paths.CSV_DIR, f'{fw_name}_nat.csv')
        csv_render_csv(resources_nat, csv_output_path_nat, "NatRule")
        logging.info(f"NAT rules CSV created: {csv_output_path_nat}")
    
    # Network Rules
    if resources_network:
        logging.info(f"Collected {len(resources_network)} Network resources")
        csv_output_path_network = os.path.join(Paths.CSV_DIR, f'{fw_name}_network.csv')
        csv_render_csv(resources_network, csv_output_path_network, "NetworkRule")
        logging.info(f"Network rules CSV created: {csv_output_path_network}")
    
    # Application Rules
    if resources_application:
        logging.info(f"Collected {len(resources_application)} Application resources")
        csv_output_path_application = os.path.join(Paths.CSV_DIR, f'{fw_name}_application.csv')
        csv_render_csv(resources_application, csv_output_path_application, "ApplicationRule")
        logging.info(f"Application rules CSV created: {csv_output_path_application}")
    
    if not all_policies_processed:
        return False, f"Some policies failed to process. Successfully processed {policies_processed} policies."
    
    return True, f"Successfully processed all {policies_processed} policies"

def replace_policy_name_in_json(data, old_name, new_name):
    """
    Recursively traverse JSON data and replace all occurrences of old_name with new_name.
    
    Args:
        data: The JSON data to process (can be dict, list, or primitive type)
        old_name: The policy name with suffix to replace
        new_name: The base policy name without suffix
        
    Returns:
        The updated JSON data
    """
    if isinstance(data, dict):        return {k: replace_policy_name_in_json(v, old_name, new_name) for k, v in data.items()}
    elif isinstance(data, list):
        return [replace_policy_name_in_json(item, old_name, new_name) for item in data]
    elif isinstance(data, str):
        return data.replace(old_name, new_name)
    else:
        return data

def download_latest_arm_template(environment=None):
    """
    Download the latest ARM template for the firewall policy.
    Only downloads policies from production firewalls (not DR).
    Then decompiles the ARM templates to Bicep files.
    
    Args:
        environment: The environment key to filter firewalls (e.g., 'Test', 'MIME', etc.)
    
    Returns:
        tuple: (success, message) where success is a boolean and message provides
               information about the operation
    """
    if not environment:
        return False, "No environment specified"

    logging.info("Ensuring Azure authentication before downloading templates...")
    ensure_azure_login()
    
    # Clean the ARM directory before downloading new templates
    logging.info("Cleaning ARM directory before downloading new templates...")
    clean_directory(Paths.ARM_DIR)

    # Ensure the arm_import directory exists (it might have been deleted by clean_directory)
    os.makedirs(Paths.ARM_DIR, exist_ok=True)
    
    # Get list of YAML files in _firewalls directory that start with the environment number
    firewall_files = []
    for f in glob.glob(os.path.join(Paths.FIREWALLS_DIR, "*.yaml")):
        basename = os.path.basename(f)
        # Extract the environment name from the filename (after the dot)
        file_env = basename.split('.')[1].split('.')[0]  # e.g., "1.Test.yaml" -> "Test"
        if file_env.lower() == environment.lower():
            firewall_files.append(f)
    
    if not firewall_files:
        return False, f"No firewall YAML files found for environment {environment}"
    
    latest_policies = {}
    
    # Process each firewall YAML file
    for fw_file in firewall_files:
        yaml_data = load_yaml_file(fw_file)
        if not yaml_data or not isinstance(yaml_data, list):
            continue
        
        for fw in yaml_data:
            if not all(k in fw for k in ['policiesName', 'policiesResourceGroup', 'subscriptionId']):
                continue
                          
            # Skip non-production firewalls
            if fw.get('regionType', '').lower() != 'prod':
                logging.info(f"Skipping non-production firewall in {fw_file}")
                continue
            
            logging.info(f"Processing production firewall policies from {fw_file}")

            # Process each policy in the firewall
            for policy in fw['policiesName']:
                if policy.lower() == "tbd":  # Skip TBD policies
                    continue
                
                logging.info(f"Searching for policy {policy} in resource group {fw['policiesResourceGroup']}")
                
                # List all policies in the resource group using PowerShell style
                try:
                    list_cmd = (
                        f'az resource list '
                        f'--subscription {fw["subscriptionId"]} '
                        f'--resource-group {fw["policiesResourceGroup"]} '
                        f'--resource-type "Microsoft.Network/firewallPolicies"'
                    )
                    command = ["powershell", "-Command", list_cmd]
                    
                    result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
                    all_resources = json.loads(result.stdout)
                    
                    # Filter policies that match our policy name
                    versioned_policies = []
                    for r in all_resources:
                        resource_name = r.get('name', '')
                        if not resource_name:
                            continue

                        # Check if the resource name starts with our policy name
                        if not resource_name.startswith(policy):
                            continue
                            
                        # Get the version suffix (everything after the base policy name)
                        suffix = resource_name[len(policy):].strip('_-')
                        if not suffix:
                            continue

                        # Check for date pattern in the suffix (YYYYMMDD_xxxxxx)
                        parts = suffix.split('_')
                        if len(parts) >= 2:  # Should have at least date and hash
                            date_part = parts[-2] if len(parts) > 2 else parts[0]
                            hash_part = parts[-1]
                            
                            # Verify date format (8 digits) and hash format (6 chars)
                            if (len(date_part) == 8 and date_part.isdigit() and
                                len(hash_part) == 6):
                                versioned_policies.append(r)
                                logging.info(f"Found versioned policy: {resource_name}")
                    
                    if versioned_policies:
                        # Sort by the suffix (after the last hyphen) to get the latest version
                        latest = max(versioned_policies, key=lambda x: x['name'].split('-')[-1])
                        latest_policies[policy] = {
                            'name': latest['name'],
                            'resourceGroup': fw['policiesResourceGroup'],
                            'subscriptionId': fw['subscriptionId']
                        }
                        logging.info(f"Found latest version of policy {policy}: {latest['name']}")
                    else:
                        logging.warning(f"No matching versioned policy found for {policy} in resource group {fw['policiesResourceGroup']}")
                        
                except subprocess.CalledProcessError as e:
                    logging.error(f"Error executing Azure CLI command for policy {policy}: {e.stderr}")
                    continue
                except json.JSONDecodeError as e:
                    logging.error(f"Error parsing Azure CLI output for policy {policy}: {str(e)}")
                    continue
                except Exception as e:
                    logging.error(f"Unexpected error processing policy {policy}: {str(e)}")
                    continue
    
    if not latest_policies:
        return False, f"No policies found to download for environment {environment}"
    
    success_count = 0
    # Download ARM template for each latest policy version
    for base_name, policy_info in latest_policies.items():
        try:
            # Get the policy resource ID using PowerShell style
            id_cmd = (
                f'az resource show '
                f'--subscription {policy_info["subscriptionId"]} '
                f'--resource-group {policy_info["resourceGroup"]} '
                f'--name {policy_info["name"]} '
                f'--resource-type "Microsoft.Network/firewallPolicies" '
                f'--query "id" '
                f'-o tsv'
            )
            command = ["powershell", "-Command", id_cmd]
            
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            policy_id = result.stdout.strip()
            
            if not policy_id:
                logging.error(f"Could not get resource ID for policy {policy_info['name']}")
                continue
            
            # Export the ARM template using PowerShell style and save with full versioned name
            output_file = os.path.join(Paths.ARM_DIR, f"{policy_info['name']}.json")
            export_cmd = (
                f'az group export '
                f'--resource-group {policy_info["resourceGroup"]} '
                f'--resource-ids {policy_id} '
                f'--skip-all-params '
                f'--output json'
            )
            command = ["powershell", "-Command", export_cmd]
            
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            
            # Parse the JSON output to ensure it's valid
            template_json = json.loads(result.stdout)
            
            # Replace all occurrences of the versioned policy name with the base name in the template content
            template_json = replace_policy_name_in_json(template_json, policy_info['name'], base_name)
            
            # Save the ARM template with versioned filename but updated content
            with open(output_file, 'w') as f:
                json.dump(template_json, f, indent=2)
            
            # # Decompile the ARM template to Bicep
            # bicep_output_file = output_file.replace('.json', '.bicep')
            # decompile_cmd = (
            #     f'az bicep decompile '
            #     f'--file {output_file}'
            # )
            # command = ["powershell", "-Command", decompile_cmd]
            
            # try:
            #     decompile_result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            #     logging.info(f"Successfully decompiled ARM template to Bicep: {bicep_output_file}")
            # except subprocess.CalledProcessError as e:
            #     logging.error(f"Error decompiling ARM template to Bicep: {e.stderr}")
            
            logging.info(f"Successfully downloaded and updated ARM template as {policy_info['name']}.json")
            success_count += 1
            
        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing Azure CLI command for policy {policy_info['name']}: {e.stderr}")
            continue
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing Azure CLI output for policy {policy_info['name']}: {e}")
            continue
        except Exception as e:
            logging.error(f"Unexpected error processing policy {policy_info['name']}: {e}")
            continue
    
    if success_count == 0:
        return False, f"Failed to download any ARM templates for environment {environment}"
    
    return True, f"Successfully downloaded and decompiled {success_count} ARM templates for environment {environment}"

