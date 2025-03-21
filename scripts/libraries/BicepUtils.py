import os
import csv
import logging
import glob
import yaml
from jinja2 import Environment, FileSystemLoader

def configure_logging():
    """Configure logging settings."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set up Jinja environment
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_PATH, '..', 'templates')
env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

# Load templates
policy_template = env.get_template('policy.bicep.jinja2')

def load_csv(file_path, delimiter=';'):
    try:
        with open(file_path, mode='r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file, delimiter=delimiter)
            data = [row for row in reader]
            logging.info(f"Loaded CSV file: {file_path}")
            return data, extract_date_suffix(os.path.basename(file_path))
    except Exception as e:
        logging.error(f"Error loading CSV file {file_path}: {e}", exc_info=True)
        return None, None

def group_data(data, policies=None):
    if not data:
        logging.warning("Warning: CSV data is empty")
        return policies if policies else {}

    logging.info(f"CSV Column Names: {data[0].keys()}")

    if policies is None:
        policies = {}

    for row in data:
        policy_name = f"{row['PolicyName']}_{row['DateSuffix']}"
        rcg_name = row['RuleCollectionGroup']
        rc_name = row['RuleCollection']

        if policy_name not in policies:
            policies[policy_name] = {
                "rcg_order": [],  # Maintains the order of the RCG
                "rcgs": {},
                "date_suffix": row['DateSuffix'],  # Adds the date suffix
                "basePolicy": row.get('ParentPolicy', '') if row.get('ParentPolicy', '') != 'None' else None,  # Adds the base policy if present
                "basePolicyLastRcg": "",
            }

        if rcg_name not in policies[policy_name]["rcgs"]:
            policies[policy_name]["rcgs"][rcg_name] = {
                "RuleCollectionGroupPriority": row['RuleCollectionGroupPriority'],
                "ruleCollections": {}
            }
            policies[policy_name]["rcg_order"].append(rcg_name)  # Save the order of the RCG

        if rc_name not in policies[policy_name]["rcgs"][rcg_name]["ruleCollections"]:
            policies[policy_name]["rcgs"][rcg_name]["ruleCollections"][rc_name] = {
                "RuleCollectionPriority": row['RuleCollectionPriority'],
                "rules": []
            }

        rule = {
            "RuleCollectionType": row['RuleCollectionType'],
            "RuleCollectionAction": row['RuleCollectionAction'],
            "RuleName": row['RuleName'],
            "RuleType": row['RuleType'],
            "IpProtocols": row['IpProtocols'],
            "SourceAddresses": row['SourceAddresses'],
            "SourceIpGroups": row['SourceIpGroups'],
            "DestinationAddresses": row['DestinationAddresses'],
            "DestinationIpGroups": row['DestinationIpGroups'],
            "DestinationFqdns": row['DestinationFqdns'],
            "DestinationPorts": row['DestinationPorts'],
            "Notes": row['Notes']
        }

        policies[policy_name]["rcgs"][rcg_name]["ruleCollections"][rc_name]["rules"].append(rule)

    # Identifica l'ultimo RCG della parent e il suo suffisso data
    for policy_name, policy_data in policies.items():
        parent_policy = policy_data["basePolicy"]
        
        if parent_policy:
            for parent_name, parent_data in policies.items():
                if parent_name.startswith(parent_policy + "_"):
                    if parent_data["rcg_order"]:
                        last_rcg = parent_data["rcg_order"][-1]
                        parent_date_suffix = parent_data["date_suffix"]
                        policies[policy_name]["basePolicyLastRcg"] = f"{parent_policy}_{parent_date_suffix}_{last_rcg}"

        logging.info(f"Policy: {policy_name}, Parent: {parent_policy}, Last RCG: {policies[policy_name]['basePolicyLastRcg']}")

    return policies

def render_template(policies, TEMPLATE_PATH, output_path, subscriptionid, ipgrouprg, policiesrg):
    try:
        # Initialize Jinja2 environment
        env = Environment(loader=FileSystemLoader(searchpath=os.path.dirname(TEMPLATE_PATH)))
        template = env.get_template(os.path.basename(TEMPLATE_PATH))
        output = template.render(policies=policies, subscriptionid=subscriptionid, ipgrouprg=ipgrouprg, policiesrg=policiesrg)
        
        with open(output_path, 'w') as file:
            file.write(output)
        logging.info(f"Generated Bicep file: {output_path}")
    except Exception as e:
        logging.error(f"Error rendering template for {output_path}: {e}", exc_info=True)

def extract_date_suffix(filename):
    return filename.split('_')[-1].split('.')[0]

def parse_yaml_file(filename):
    """Reads and parses the content of a YAML file."""
    with open(filename, 'r') as f:
        data = yaml.safe_load(f)
    return data

def generate_bicep_from_yaml(folder, template_file, output_file):
    """Generate Bicep file from YAML files using a Jinja2 template."""
    # Retrieve all YAML files (.yaml and .yml) in the given folder
    yaml_files = glob.glob(os.path.join(folder, "*.yaml"))
    yaml_files.extend(glob.glob(os.path.join(folder, "*.yml")))

    if not yaml_files:
        logging.error(f"No YAML files found in folder '{folder}'.")
        return

    # Load the Jinja2 template
    env = Environment(loader=FileSystemLoader(searchpath=os.path.dirname(template_file)))
    template = env.get_template(os.path.basename(template_file))

    # Parse YAML files and render the template
    yaml_contents = []
    for yaml_file in sorted(yaml_files):
        data = parse_yaml_file(yaml_file)
        data['filename'] = os.path.splitext(os.path.basename(yaml_file))[0]
        yaml_contents.append(data)

    bicep_content = template.render(yaml_contents=yaml_contents)

    # Write the combined Bicep content to the specified output file.
    try:
        with open(output_file, "w") as f:
            f.write(bicep_content)
        logging.info(f"Bicep file generated successfully: {output_file}")
    except Exception as e:
        logging.error(f"Failed to write the output file: {e}", exc_info=True)