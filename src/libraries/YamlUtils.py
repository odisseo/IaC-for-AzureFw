import os
import re
import logging
import csv
from jinja2 import Environment, FileSystemLoader
from src.libraries.CommonUtils import (
    load_json_file, load_yaml_file, save_file, clean_directory,
    normalize_name, ensure_list, get_base_path, remove_date_suffix
)
from src.libraries.Parameters import Paths, Config

###################################################################
# IPGROUPS
###################################################################

def format_ip_group(ip_group):
    """
    Format the IP group by extracting the relevant part from the parameter string 
    or full resource path.
    
    Args:
        ip_group (str): The IP group string to format, can be:
            - A parameter reference: [parameters('NAME')]
            - A full resource path: /subscriptions/.../ipGroups/NAME
            - Just the name: NAME
            
    Returns:
        str: The clean IP group name without path or parameters wrapper
    """
    if not ip_group:
        return ""
        
    # Handle the case where the IP group is in the format [parameters('...')]
    param_match = re.match(r"\[parameters\('([^']+)'\)\]", ip_group)
    if param_match:
        ip_group_name = param_match.group(1)
        # If the parameter value itself is a resource path, extract the name
        if '/' in ip_group_name:
            return format_ip_group(ip_group_name)
        return normalize_name(ip_group_name)
    
    # Handle the case where the IP group is a full resource path
    # This will match both:
    # - /subscriptions/.../ipGroups/NAME
    # - Microsoft.Network/ipGroups/NAME
    path_match = re.search(r'(?:/ipGroups/|/Microsoft\.Network/ipGroups/)([^/\s]+)(?:\s|$|/|\'|")', ip_group)
    if path_match:
        ip_group_name = path_match.group(1)
        return normalize_name(ip_group_name)
    
    # If no special format is detected, just normalize the name
    return normalize_name(ip_group)
    
###################################################################
# JSON to YAML
###################################################################

def extract_base_policy_name(base_policy):
    """Extract the policy name from the basePolicy string."""
    if not base_policy:
        return ""
        
    if isinstance(base_policy, dict):
        base_policy = base_policy.get('id', '')
        
    match = re.search(r"'Microsoft.Network/firewallPolicies', '([^']+)'", base_policy)
    if match:
        policy_name_with_date = match.group(1)
        return remove_date_suffix(policy_name_with_date)
        
    return base_policy

def yaml_create_policies_structure(json_file_path, output_dir):
    """Create the directory structure and YAML files for policies from the JSON data."""
    logging.info(f"Creating policies YAML structure from {json_file_path}")
    
    # Load the JSON data
    data = load_json_file(json_file_path)
    if not data:
        return False
    
    # Clean the output directory
    if not clean_directory(output_dir):
        return False
    
    # Set up Jinja templates using Paths.TEMPLATES_DIR
    env = Environment(loader=FileSystemLoader(Paths.TEMPLATES_DIR))
    policy_template = env.get_template('policy.yaml.jinja2')
    rule_collection_group_template = env.get_template('rcg.yaml.jinja2')
    rule_collection_template = env.get_template('rc.yaml.jinja2')
    
    policy_count = 0
    rcg_count = 0
    rc_count = 0
    
    try:
        # Process each firewall policy
        for resource in data['resources']:
            if resource['type'] == 'Microsoft.Network/firewallPolicies':
                policy_name = remove_date_suffix(resource['name'])
                policy_name_normalized = normalize_name(policy_name)
                base_policy = resource['properties'].get('basePolicy', '')
                base_policy_name = normalize_name(extract_base_policy_name(base_policy))
                
                # Create policy directory
                policy_dir = os.path.join(output_dir, policy_name_normalized)
                os.makedirs(policy_dir, exist_ok=True)
                
                # Create main.yaml in policy directory
                main_yaml_path = os.path.join(policy_dir, 'main.yaml')
                main_yaml_content = policy_template.render(base_policy=base_policy_name, api_version=Config.FIREWALL_API_VERSION)
                if save_file(main_yaml_content, main_yaml_path):
                    policy_count += 1
                    logging.info(f"Created policy: {policy_name_normalized}")
                
                # Process rule collection groups for this policy
                for rcg_resource in data['resources']:
                    if rcg_resource['type'] == 'Microsoft.Network/firewallPolicies/ruleCollectionGroups' and policy_name in rcg_resource['name']:
                        # Extract the RCG name from the resource name
                        rcg_name = rcg_resource['name'].split('/')[-1].replace(')]', '').rstrip("'")
                        rcg_name_parts = rcg_name.split(", ")
                        rcg_name = rcg_name_parts[-1].replace("'", "")
                        rcg_name_normalized = normalize_name(rcg_name)
                        rcg_priority = rcg_resource['properties']['priority']
                        
                        # Create RCG directory
                        rcg_dir = os.path.join(policy_dir, f"{rcg_priority}_{rcg_name_normalized}")
                        os.makedirs(rcg_dir, exist_ok=True)
                        
                        # Create main.yaml in RCG directory
                        rcg_main_yaml_path = os.path.join(rcg_dir, 'main.yaml')
                        rcg_main_yaml_content = rule_collection_group_template.render(api_version=Config.FIREWALL_API_VERSION)
                        if save_file(rcg_main_yaml_content, rcg_main_yaml_path):
                            rcg_count += 1
                            logging.info(f"Created RCG: {rcg_priority}_{rcg_name_normalized}")
                        
                        # Process rule collections for this RCG
                        for rule_collection in rcg_resource['properties']['ruleCollections']:
                            rc_priority = rule_collection['priority']
                            rc_name = rule_collection['name']
                            rc_name_normalized = normalize_name(rc_name)
                            rc_file_path = os.path.join(rcg_dir, f"{rc_priority}_{rc_name_normalized}.yaml")
                            
                            # Process rules in this rule collection
                            rules = []
                            for rule in rule_collection['rules']:
                                # Create a rule data dictionary based on rule type
                                if rule['ruleType'] == 'NetworkRule':
                                    rule_data = {
                                        'ruleType': rule['ruleType'],
                                        'name': normalize_name(rule['name']),
                                        'ipProtocols': rule.get('ipProtocols', []),
                                        'sourceAddresses': rule.get('sourceAddresses', []),
                                        'sourceIpGroups': [format_ip_group(ip_group) for ip_group in rule.get('sourceIpGroups', [])],
                                        'destinationAddresses': rule.get('destinationAddresses', []),
                                        'destinationIpGroups': [format_ip_group(ip_group) for ip_group in rule.get('destinationIpGroups', [])],
                                        'destinationFqdns': rule.get('destinationFqdns', []),
                                        'destinationPorts': rule.get('destinationPorts', [])
                                    }
                                elif rule['ruleType'] == 'NatRule':
                                    rule_data = {
                                        'ruleType': rule['ruleType'],
                                        'name': normalize_name(rule['name']),
                                        'ipProtocols': rule.get('ipProtocols', []),
                                        'sourceAddresses': rule.get('sourceAddresses', []),
                                        'sourceIpGroups': [format_ip_group(ip_group) for ip_group in rule.get('sourceIpGroups', [])],
                                        'destinationAddresses': rule.get('destinationAddresses', []),
                                        'destinationPorts': rule.get('destinationPorts', []),
                                        'translatedAddress': rule.get('translatedAddress', ''),
                                        'translatedFqdn': rule.get('translatedFqdn', ''),
                                        'translatedPort': rule.get('translatedPort', '')
                                    }
                                elif rule['ruleType'] == 'ApplicationRule':
                                    # Extract protocol information for application rules
                                    protocols = []
                                    for protocol in rule.get('protocols', []):
                                        protocols.append({
                                            'protocolType': protocol.get('protocolType', ''),
                                            'port': protocol.get('port', 0)
                                        })
                                    
                                    rule_data = {
                                        'ruleType': rule['ruleType'],
                                        'name': normalize_name(rule['name']),
                                        'protocols': protocols,
                                        'terminateTLS': rule.get('terminateTLS', False),
                                        'sourceAddresses': rule.get('sourceAddresses', []),
                                        'destinationAddresses': rule.get('destinationAddresses', []),
                                        'sourceIpGroups': [format_ip_group(ip_group) for ip_group in rule.get('sourceIpGroups', [])],
                                        'destinationIpGroups': [format_ip_group(ip_group) for ip_group in rule.get('destinationIpGroups', [])],
                                        'targetFqdns': rule.get('targetFqdns', []),
                                        'targetUrls': rule.get('targetUrls', []),
                                        'fqdnTags': rule.get('fqdnTags', []),
                                        'webCategories': rule.get('webCategories', []),
                                        'httpHeadersToInsert': rule.get('httpHeadersToInsert', [])
                                    }
                                
                                rules.append(rule_data)
                            
                            # Create RC file
                            rc_content = rule_collection_template.render(
                                rule_collection_type=rule_collection['ruleCollectionType'],
                                action=rule_collection['action']['type'],
                                rules=rules,
                                api_version=Config.FIREWALL_API_VERSION
                            )
                            
                            if save_file(rc_content, rc_file_path):
                                rc_count += 1
                                logging.info(f"Created RC: {rc_priority}_{rc_name_normalized}.yaml")
        
        logging.info(f"Successfully created {policy_count} policies with {rcg_count} RCGs and {rc_count} RCs")
        return True
        
    except (KeyError, TypeError, IndexError) as e:
        logging.error(f"Error creating policies structure: {e}", exc_info=True)
        return False
    
###################################################################
# CSV to YAML
###################################################################

def process_csv_file(csv_path, rule_type, policies):
    """
    Process a CSV file and update the policies dictionary.
    
    Args:
        csv_path (str): Path to the CSV file
        rule_type (str): Type of rules ('application', 'network', 'nat')
        policies (dict): Dictionary to update with policy information
    """
    logging.info(f"Processing {rule_type} CSV file: {csv_path}")
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            # Skip the first line (header)
            reader = csv.reader(f, delimiter=';')
            header = next(reader)
            
            # Process each row
            for row in reader:
                # Create a dictionary from the CSV row
                row_data = dict(zip(header, row))
                
                # Get policy information
                policy_name = row_data.get('PolicyName', '')
                parent_policy = row_data.get('ParentPolicy', 'None')
                
                # Skip if policy name is empty
                if not policy_name:
                    continue
                
                # Initialize policy if not exists
                if policy_name not in policies:
                    policies[policy_name] = {
                        'parent_policy': parent_policy,
                        'rule_collection_groups': {}
                    }
                
                # Get rule collection group information
                rcg_name = row_data.get('RuleCollectionGroup', '')
                rcg_priority = row_data.get('RuleCollectionGroupPriority', '1000')
                
                # Initialize rule collection group if not exists
                if rcg_name not in policies[policy_name]['rule_collection_groups']:
                    policies[policy_name]['rule_collection_groups'][rcg_name] = {
                        'priority': rcg_priority,
                        'rule_collections': {}
                    }
                
                # Get rule collection information
                rc_name = row_data.get('RuleCollection', '')
                rc_priority = row_data.get('RuleCollectionPriority', '1000')
                rc_type = row_data.get('RuleCollectionType', 'FirewallPolicyFilterRuleCollection')
                rc_action = row_data.get('RuleCollectionAction', 'Allow')
                
                # Initialize rule collection if not exists
                if rc_name not in policies[policy_name]['rule_collection_groups'][rcg_name]['rule_collections']:
                    policies[policy_name]['rule_collection_groups'][rcg_name]['rule_collections'][rc_name] = {
                        'priority': rc_priority,
                        'type': rc_type,
                        'action': rc_action,
                        'rules': []
                    }
                
                # Get rule information
                rule_name = row_data.get('RuleName', '')
                rule_type_specific = row_data.get('RuleType', '')
                
                # Create rule based on type
                rule = {'name': rule_name, 'ruleType': rule_type_specific}
                
                # Add type-specific rule properties
                if rule_type_specific == 'NetworkRule':
                    rule.update({
                        'ipProtocols': row_data.get('IpProtocols', '').split(','),
                        'sourceAddresses': split_values(row_data.get('SourceAddresses', '')),
                        'sourceIpGroups': split_values(row_data.get('SourceIpGroups', '')),
                        'destinationAddresses': split_values(row_data.get('DestinationAddresses', '')),
                        'destinationIpGroups': split_values(row_data.get('DestinationIpGroups', '')),
                        'destinationFqdns': split_values(row_data.get('DestinationFqdns', '')),
                        'destinationPorts': split_values(row_data.get('DestinationPorts', ''), '$')
                    })
                elif rule_type_specific == 'NatRule':
                    rule.update({
                        'ipProtocols': row_data.get('IpProtocols', '').split(','),
                        'sourceAddresses': split_values(row_data.get('SourceAddresses', '')),
                        'sourceIpGroups': split_values(row_data.get('SourceIpGroups', '')),
                        'destinationAddresses': split_values(row_data.get('DestinationAddresses', '')),
                        'destinationPorts': split_values(row_data.get('DestinationPorts', '')),
                        'translatedAddress': row_data.get('TranslatedAddress', ''),
                        'translatedFqdn': row_data.get('TranslatedFqdn', ''),
                        'translatedPort': row_data.get('TranslatedPort', '')
                    })
                elif rule_type_specific == 'ApplicationRule':
                    # Parse protocols for application rules
                    protocol_str = row_data.get('Protocols', '')
                    protocols = []
                    for p in protocol_str.split(','):
                        if ':' in p:
                            protocol_type, port = p.split(':')
                            protocols.append({
                                'protocolType': protocol_type,
                                'port': int(port)
                            })
                    
                    rule.update({
                        'protocols': protocols,
                        'sourceAddresses': split_values(row_data.get('SourceAddresses', '')),
                        'sourceIpGroups': split_values(row_data.get('SourceIpGroups', '')),
                        'destinationAddresses': split_values(row_data.get('DestinationAddresses', '')),
                        'destinationIpGroups': split_values(row_data.get('DestinationIpGroups', '')),
                        'targetFqdns': split_values(row_data.get('TargetFqdns', '')),
                        'targetUrls': split_values(row_data.get('TargetUrls', '')),
                        'fqdnTags': split_values(row_data.get('FqdnTags', '')),
                        'webCategories': split_values(row_data.get('WebCategories', '')),
                        'terminateTLS': row_data.get('TerminateTLS', 'False').lower() == 'true',
                        'httpHeadersToInsert': parse_headers(row_data.get('HttpHeadersToInsert', ''))
                    })
                
                # Add notes if present
                if 'Notes' in row_data and row_data['Notes']:
                    rule['notes'] = row_data['Notes']
                
                # Add the rule to the collection
                policies[policy_name]['rule_collection_groups'][rcg_name]['rule_collections'][rc_name]['rules'].append(rule)
                
    except Exception as e:
        logging.error(f"Error processing CSV file {csv_path}: {e}", exc_info=True)

def create_yaml_from_policies(policies, output_dir):
    """
    Create YAML files from the policies dictionary.
    
    Args:
        policies (dict): Dictionary containing policy information
        output_dir (str): Directory to write YAML files to
    """
    # Set up Jinja environment using centralized template directory
    env = Environment(loader=FileSystemLoader(Paths.TEMPLATES_DIR))
    policy_template = env.get_template('policy.yaml.jinja2')
    rule_collection_group_template = env.get_template('rcg.yaml.jinja2')
    rule_collection_template = env.get_template('rc.yaml.jinja2')
    
    # Create policy structure and YAML files
    for policy_name, policy_data in policies.items():
        policy_dir = os.path.join(output_dir, policy_name)
        os.makedirs(policy_dir, exist_ok=True)
        
        # Create main.yaml in policy directory
        main_yaml_path = os.path.join(policy_dir, 'main.yaml')
        parent_policy = policy_data.get('parent_policy', '')
        main_yaml_content = policy_template.render(base_policy=parent_policy, api_version=Config.FIREWALL_API_VERSION)
        with open(main_yaml_path, 'w', encoding='utf-8') as f:
            f.write(main_yaml_content)
        
        # Process rule collection groups
        for rcg_name, rcg_data in policy_data.get('rule_collection_groups', {}).items():
            rcg_priority = rcg_data.get('priority', '1000')
            rcg_dir = os.path.join(policy_dir, f"{rcg_priority}_{rcg_name}")
            os.makedirs(rcg_dir, exist_ok=True)
            
            # Create main.yaml in RCG directory
            rcg_main_yaml_path = os.path.join(rcg_dir, 'main.yaml')
            rcg_main_yaml_content = rule_collection_group_template.render(api_version=Config.FIREWALL_API_VERSION)
            with open(rcg_main_yaml_path, 'w', encoding='utf-8') as f:
                f.write(rcg_main_yaml_content)
            
            # Process rule collections
            for rc_name, rc_data in rcg_data.get('rule_collections', {}).items():
                rc_priority = rc_data.get('priority', '1000')
                rc_type = rc_data.get('type', 'FirewallPolicyFilterRuleCollection')
                rc_action = rc_data.get('action', 'Allow')
                
                # Create RC YAML file
                rc_file_path = os.path.join(rcg_dir, f"{rc_priority}_{rc_name}.yaml")
                
                # Transform rules to the format expected by the template
                rules = []
                for rule in rc_data.get('rules', []):
                    rule_data = transform_rule_data(rule)
                    rules.append(rule_data)
                
                # Render rule collection template
                rc_content = rule_collection_template.render(
                    rule_collection_type=rc_type,
                    action=rc_action,
                    rules=rules, 
                    api_version=Config.FIREWALL_API_VERSION
                )
                
                with open(rc_file_path, 'w', encoding='utf-8') as f:
                    f.write(rc_content)

def split_values(value_string, delimiter=','):
    """
    Split a string of values into a list, handling empty strings.
    
    Args:
        value_string (str): String of values to split
        delimiter (str): Delimiter to split by
    
    Returns:
        list: List of values
    """
    if not value_string:
        return []
    return [v.strip() for v in value_string.split(delimiter) if v.strip()]

def parse_headers(header_string):
    """
    Parse HTTP headers from a string.
    
    Args:
        header_string (str): String of headers in format 'header1=value1,header2=value2'
    
    Returns:
        list: List of header dictionaries
    """
    if not header_string:
        return []
    
    headers = []
    for h in header_string.split(','):
        if '=' in h:
            key, value = h.split('=', 1)
            headers.append({
                'header': key.strip(),
                'value': value.strip()
            })
    
    return headers

def transform_rule_data(rule):
    """
    Transform rule data to match the format expected by the Jinja template.
    
    Args:
        rule (dict): Rule data from CSV processing
    
    Returns:
        dict: Transformed rule data
    """
    # Create a copy of the rule to avoid modifying the original
    transformed_rule = dict(rule)
    
    # Ensure all list fields are proper lists
    for field in ['ipProtocols', 'sourceAddresses', 'sourceIpGroups', 
                 'destinationAddresses', 'destinationIpGroups', 
                 'destinationFqdns', 'destinationPorts', 
                 'targetFqdns', 'targetUrls', 'fqdnTags', 
                 'webCategories', 'httpHeadersToInsert']:
        if field in transformed_rule:
            transformed_rule[field] = ensure_list(transformed_rule[field])
    
    # Format IP groups
    if 'sourceIpGroups' in transformed_rule:
        transformed_rule['sourceIpGroups'] = [
            format_ip_group(ip_group) for ip_group in transformed_rule['sourceIpGroups']
        ]
    
    if 'destinationIpGroups' in transformed_rule:
        transformed_rule['destinationIpGroups'] = [
            format_ip_group(ip_group) for ip_group in transformed_rule['destinationIpGroups']
        ]
    
    return transformed_rule

def compare_policy_sets(arm_files):
    """
    Compare existing policies in _policies directory with policies to be imported from ARM templates.
    
    Args:
        arm_files: List of ARM template files to be imported
        
    Returns:
        tuple: (differences, existing_policies, new_policies) where:
            - differences is a dictionary with 'removed', 'added', and 'common' policies
            - existing_policies is a set of current policy names
            - new_policies is a set of policy names to be imported
    """
    # Get existing policies
    existing_policies = set()
    if os.path.exists(Paths.POLICIES_DIR):
        for item in os.listdir(Paths.POLICIES_DIR):
            if os.path.isdir(os.path.join(Paths.POLICIES_DIR, item)):
                existing_policies.add(item)
      # Get policies from ARM templates
    new_policies = set()
    for arm_file in arm_files:
        try:
            data = load_json_file(arm_file)
            if not data:
                continue
                
            for resource in data.get('resources', []):
                if resource['type'] == 'Microsoft.Network/firewallPolicies':
                    policy_name = resource['name']
                    # If name has version suffix, remove it
                    policy_name = remove_date_suffix(policy_name)
                    policy_name = normalize_name(policy_name)
                    new_policies.add(policy_name)
                    break  # Found the main policy resource, no need to continue
        except Exception as e:
            logging.error(f"Error analyzing ARM template {arm_file}: {str(e)}")
            continue
    
    # Calculate differences
    differences = {
        'removed': existing_policies - new_policies,  # Policies that exist but won't be in new import
        'added': new_policies - existing_policies,    # New policies that don't exist currently
        'common': existing_policies & new_policies    # Policies that exist and will be updated
    }
    
    return differences, existing_policies, new_policies
