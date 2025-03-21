import os
import json
import re
import logging
from jinja2 import Environment, FileSystemLoader
import shutil
import stat

def configure_logging():
    """Configure logging settings."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set up Jinja environment
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_PATH, '..', 'templates')
env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

# Load templates
policy_template = env.get_template('policy.yaml.jinja2')
rule_collection_group_template = env.get_template('rcg.yaml.jinja2')
rule_collection_template = env.get_template('rc.yaml.jinja2')
ipgroups_template = env.get_template('ipgroups.yaml.jinja2')

def format_ip_group(ip_group):
    """Format the IP group by extracting the relevant part from the parameter string or full resource path."""
    # Handle the case where the IP group is in the format [parameters('...')]
    match = re.match(r"\[parameters\('([^']+)'\)\]", ip_group)
    if match:
        ip_group_name = match.group(1)
        return normalize_name(ip_group_name)
    
    # Handle the case where the IP group is a full resource path
    match = re.match(r".*/Microsoft.Network/ipGroups/([^/]+)$", ip_group)
    if match:
        ip_group_name = match.group(1)
        return normalize_name(ip_group_name)
    
    # Return the original value if no match is found
    return ip_group

def on_rm_error(func, path, exc_info):
    """Error handler for removing read-only files."""
    os.chmod(path, stat.S_IWRITE)
    func(path)

def clean_output_directory(output_dir):
    """Clean the output directory by removing its contents and recreating it."""
    if os.path.exists(output_dir):
        logging.info(f"Cleaning output directory: {output_dir}")
        shutil.rmtree(output_dir, onerror=on_rm_error)
        logging.info(f"Deleted root directory: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    logging.info(f"Created new output directory: {output_dir}")

def remove_date_suffix(name):
    """Remove the date suffix from the name."""
    return re.sub(r'_\d{8}$', '', name)

def extract_base_policy_name(base_policy):
    """Extract the policy name from the basePolicy string."""
    if isinstance(base_policy, dict):
        base_policy = base_policy.get('id', '')
    match = re.search(r"'Microsoft.Network/firewallPolicies', '([^']+)'", base_policy)
    if match:
        policy_name_with_date = match.group(1)
        return remove_date_suffix(policy_name_with_date)
    return base_policy

def load_json_file(file_path):
    """Load JSON data from a file."""
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            logging.info(f"Loaded JSON from {file_path}")
            return data
    except (OSError, json.JSONDecodeError) as e:
        logging.error(f"Error loading JSON file {file_path}: {e}", exc_info=True)
        return None

def normalize_name(name):
    """Normalize the name by replacing spaces, hyphens, and "_-_" with underscores."""
    return re.sub(r'[\s\-]+|_-_', '_', name)

def yaml_create_ipgroups_structure(json_file_path, output_dir):
    """Create the directory structure and YAML files for IP groups from the JSON data."""
    try:
        logging.info(f"Reading JSON file from: {json_file_path}")
        data = load_json_file(json_file_path)
        if not data:
            return
        
        clean_output_directory(output_dir)
        
        ip_groups = [
            {
                "name": normalize_name(resource["name"]),
                "location": resource["location"],
                "ipAddresses": resource["properties"]["ipAddresses"]
            }
            for resource in data["resources"]
            if resource["type"] == "Microsoft.Network/ipGroups"
        ]
        logging.info(f"Extracted {len(ip_groups)} IP groups from JSON data")
        
        for group in ip_groups:
            file_name = group["name"] + '.yaml'
            file_path = os.path.join(output_dir, file_name)
            yaml_content = ipgroups_template.render(location=group["location"], ip_addresses=group["ipAddresses"])
            
            with open(file_path, 'w') as file:
                file.write(yaml_content)
            logging.info(f"Generated YAML file for IP group {group['name']} at {file_path}")
        
        logging.info("IP groups YAML files generated successfully.")
    except (OSError, KeyError, TypeError) as e:
        logging.error(f"Error creating IP groups structure from JSON: {e}", exc_info=True)

def yaml_create_policies_structure(json_file_path, output_dir):
    """Create the directory structure and YAML files for policies from the JSON data."""
    try:
        logging.info(f"Reading JSON file from: {json_file_path}")
        data = load_json_file(json_file_path)
        if not data:
            return
        
        clean_output_directory(output_dir)
        
        for resource in data['resources']:
            if resource['type'] == 'Microsoft.Network/firewallPolicies':
                policy_name = remove_date_suffix(resource['name'])
                policy_name_normalized = normalize_name(policy_name)
                base_policy = resource['properties'].get('basePolicy', '')
                base_policy_name = normalize_name(extract_base_policy_name(base_policy))
                policy_dir = os.path.join(output_dir, policy_name_normalized)
                logging.info(f"Creating policy directory: {policy_dir}")
                os.makedirs(policy_dir, exist_ok=True)

                # Create main.yaml in policy directory
                main_yaml_path = os.path.join(policy_dir, 'main.yaml')
                logging.info(f"Creating main.yaml in policy directory: {main_yaml_path}")
                with open(main_yaml_path, 'w') as main_yaml_file:
                    main_yaml_file.write(policy_template.render(base_policy=base_policy_name))
                
                for rcg_resource in data['resources']:
                    if rcg_resource['type'] == 'Microsoft.Network/firewallPolicies/ruleCollectionGroups' and policy_name in rcg_resource['name']:
                        rcg_name = rcg_resource['name'].split('/')[-1].replace(')]', '').rstrip("'")
                        rcg_name_parts = rcg_name.split(", ")
                        rcg_name = rcg_name_parts[-1].replace("'", "")
                        rcg_name_normalized = normalize_name(rcg_name)
                        rcg_priority = rcg_resource['properties']['priority']
                        rcg_dir = os.path.join(policy_dir, f"{rcg_priority}_{rcg_name_normalized}")
                        logging.info(f"Creating rule collection group directory: {rcg_dir}")
                        os.makedirs(rcg_dir, exist_ok=True)
                        
                        # Create main.yaml in rule collection group directory
                        rcg_main_yaml_path = os.path.join(rcg_dir, 'main.yaml')
                        logging.info(f"Creating main.yaml in rule collection group directory: {rcg_main_yaml_path}")
                        with open(rcg_main_yaml_path, 'w') as rcg_main_yaml_file:
                            rcg_main_yaml_file.write(rule_collection_group_template.render())
                        
                        for rule_collection in rcg_resource['properties']['ruleCollections']:
                            rc_priority = rule_collection['priority']
                            rc_name = rule_collection['name']
                            rc_name_normalized = normalize_name(rc_name)
                            rc_file_path = os.path.join(rcg_dir, f"{rc_priority}_{rc_name_normalized}.yaml")
                            logging.info(f"Creating rule collection file: {rc_file_path}")
                            
                            rules = []
                            for rule in rule_collection['rules']:
                                rule_data = {
                                    'ruleType': rule['ruleType'],
                                    'name': normalize_name(rule['name']),
                                    'ipProtocols': rule['ipProtocols'],
                                    'sourceAddresses': rule['sourceAddresses'],
                                    'sourceIpGroups': [format_ip_group(ip_group) for ip_group in rule['sourceIpGroups']],
                                    'destinationAddresses': rule['destinationAddresses'],
                                    'destinationIpGroups': [format_ip_group(ip_group) for ip_group in rule['destinationIpGroups']],
                                    'destinationFqdns': rule['destinationFqdns'],
                                    'destinationPorts': rule['destinationPorts']
                                }
                                rules.append(rule_data)
                            
                            # Write rule collection to YAML file
                            with open(rc_file_path, 'w') as rc_file:
                                rc_file.write(rule_collection_template.render(
                                    rule_collection_type=rule_collection['ruleCollectionType'],
                                    action=rule_collection['action']['type'],
                                    rules=rules
                                ))
        logging.info("Policy YAML files generated successfully.")
    except (OSError, KeyError, TypeError) as e:
        logging.error(f"Error creating policies structure from JSON: {e}", exc_info=True)
