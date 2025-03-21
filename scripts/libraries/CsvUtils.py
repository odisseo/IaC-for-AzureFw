import os
import yaml
import logging
from jinja2 import Environment, FileSystemLoader

def load_yaml_file(file_path):
    """Load YAML data from a file."""
    try:
        with open(file_path, 'r') as file:
            data = yaml.safe_load(file)
            logging.info(f"Loaded YAML from {file_path}")
            return data
    except (OSError, yaml.YAMLError) as e:
        logging.error(f"Error loading YAML file {file_path}: {e}", exc_info=True)
        return None

def ensure_list(value):
    """Ensure the value is a list."""
    if isinstance(value, list):
        return value
    elif isinstance(value, str):
        return [value]
    return []

def get_policy_parent(policy_path):
    """Get the parent policy from the main.yaml file."""
    main_yaml_path = os.path.join(policy_path, 'main.yaml')
    policy_data = load_yaml_file(main_yaml_path)
    if policy_data and 'properties' in policy_data and 'basePolicy' in policy_data['properties']:
        return policy_data['properties']['basePolicy']
    return ''

def csv_collect_policy_data(policies_dir):
    """Collect policy data from the policies directory."""
    resources = []
    for policy_name in os.listdir(policies_dir):
        policy_path = os.path.join(policies_dir, policy_name)
        if os.path.isdir(policy_path):
            policy_parent = get_policy_parent(policy_path)
            for rcg_folder in os.listdir(policy_path):
                rcg_path = os.path.join(policy_path, rcg_folder)
                if os.path.isdir(rcg_path):
                    rcg_priority, rcg_name = rcg_folder.split('_', 1)
                    for rc_file in os.listdir(rcg_path):
                        if rc_file.endswith('.yaml'):
                            rc_file_path = os.path.join(rcg_path, rc_file)
                            if '_' in rc_file:
                                rc_priority, rc_name = rc_file.replace('.yaml', '').split('_', 1)
                            else:
                                logging.warning(f"Skipping file with unexpected name format: {rc_file}")
                                continue
                            rc_data = load_yaml_file(rc_file_path)
                            if not rc_data:
                                continue

                            rules = []
                            for rule in rc_data.get('rules', []):
                                rules.append({
                                    'ruleType': rule.get('ruleType', ''),
                                    'name': rule.get('name', ''),
                                    'ipProtocols': ensure_list(rule.get('ipProtocols', [])),
                                    'sourceAddresses': ensure_list(rule.get('sourceAddresses', [])),
                                    'sourceIpGroups': ensure_list(rule.get('sourceIpGroups', [])),
                                    'destinationAddresses': ensure_list(rule.get('destinationAddresses', [])),
                                    'destinationIpGroups': ensure_list(rule.get('destinationIpGroups', [])),
                                    'destinationFqdns': ensure_list(rule.get('destinationFqdns', [])),
                                    'destinationPorts': ensure_list(rule.get('destinationPorts', [])),
                                    'notes': rule.get('notes', '')
                                })

                            resources.append({
                                'type': 'Microsoft.Network/firewallPolicies/ruleCollectionGroups',
                                'name': f"{policy_name}/{rcg_name}",
                                'properties': {
                                    'priority': rcg_priority,
                                    'ruleCollections': [{
                                        'name': rc_name,
                                        'priority': rc_priority,
                                        'ruleCollectionType': rc_data.get('ruleCollectionType', ''),
                                        'action': {'type': rc_data.get('action', '')} if isinstance(rc_data.get('action'), str) else rc_data.get('action', {}),
                                        'rules': rules
                                    }]
                                },
                                'policyParent': policy_parent
                            })
    return resources

def csv_render_csv(resources, template_path, output_path):
    """Render the CSV file from the collected resources."""
    try:
        # Initialize Jinja2 environment
        env = Environment(loader=FileSystemLoader(searchpath=os.path.dirname(template_path)))
        template = env.get_template(os.path.basename(template_path))
        output = template.render(resources=resources)
        
        with open(output_path, 'w') as file:
            file.write(output)
        logging.info(f"Generated CSV file: {output_path}")
    except Exception as e:
        logging.error(f"Error rendering template for {output_path}: {e}", exc_info=True)
