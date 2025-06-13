import os
import yaml
import logging
from jinja2 import Environment, FileSystemLoader
from scripts.libraries.CommonUtils import load_yaml_file, ensure_list
from scripts.libraries.Parameters import Paths, Config

def get_policy_parent(policy_path):
    """Get the parent policy from the main.yaml file."""
    main_yaml_path = os.path.join(policy_path, 'main.yaml')
    policy_data = load_yaml_file(main_yaml_path)
    if policy_data and 'properties' in policy_data and 'basePolicy' in policy_data['properties']:
        return policy_data['properties']['basePolicy']
    return ''

def csv_collect_policy_data(policies_dir):
    """
    Collect policy data from the policies directory and separate by rule type.
    Properly extract metadata from folder and file structure according to:
    - policy_name/ (PolicyName)
    - main.yaml (contains ParentPolicy)
    - priority_rcg_name/ (RuleCollectionGroupPriority_RuleCollectionGroup)
    - priority_rc_name.yaml (RuleCollectionPriority_RuleCollection)
    """
    resources_nat = []
    resources_network = []
    resources_application = []

    logging.info(f"Collecting policy data from: {policies_dir}")

    for policy_name in os.listdir(policies_dir):
        policy_path = os.path.join(policies_dir, policy_name)
        if os.path.isdir(policy_path):
            # Get the parent policy from main.yaml
            policy_parent = get_policy_parent(policy_path)
            
            for rcg_folder in os.listdir(policy_path):
                rcg_path = os.path.join(policy_path, rcg_folder)
                if os.path.isdir(rcg_path) and '_' in rcg_folder:
                    # Extract RCG priority and name from folder name
                    rcg_parts = rcg_folder.split('_', 1)
                    if len(rcg_parts) >= 2:
                        rcg_priority = rcg_parts[0]
                        rcg_name = rcg_parts[1] if len(rcg_parts) > 1 else ""
                        
                        for rc_file in os.listdir(rcg_path):
                            if rc_file.endswith('.yaml') and rc_file != 'main.yaml':
                                rc_file_path = os.path.join(rcg_path, rc_file)
                                
                                # Extract RC priority and name from file name
                                rc_priority = ""
                                rc_name = ""
                                if '_' in rc_file:
                                    rc_file_parts = rc_file.replace('.yaml', '').split('_', 1)
                                    rc_priority = rc_file_parts[0]
                                    rc_name = rc_file_parts[1] if len(rc_file_parts) > 1 else ""
                                else:
                                    logging.warning(f"Skipping file with unexpected name format: {rc_file}")
                                    continue
                                
                                rc_data = load_yaml_file(rc_file_path)
                                if not rc_data:
                                    continue

                                # Get RuleCollectionType and action from file content
                                rc_type = rc_data.get('ruleCollectionType', '')
                                rc_action = rc_data.get('action', '')
                                if isinstance(rc_action, dict):
                                    rc_action = rc_action.get('type', '')

                                # Check if rules exist and are not empty
                                rules = rc_data.get('rules', [])
                                if not rules:
                                    logging.warning(f"No rules found in {rc_file_path}")
                                    continue

                                for rule in rules:
                                    # Create common rule data with all metadata properly populated
                                    rule_data = {
                                        'type': 'Microsoft.Network/firewallPolicies/ruleCollectionGroups',
                                        'name': f"{policy_name}/{rcg_name}",
                                        'policyName': policy_name,
                                        'policyParent': policy_parent if policy_parent else 'None',
                                        'ruleCollectionGroup': rcg_name,
                                        'ruleCollectionGroupPriority': rcg_priority,
                                        'ruleCollection': rc_name,
                                        'ruleCollectionPriority': rc_priority,
                                        'ruleCollectionType': rc_type,
                                        'ruleCollectionAction': rc_action,
                                        'properties': {
                                            'priority': rcg_priority,
                                            'ruleCollections': [{
                                                'name': rc_name,
                                                'priority': rc_priority,
                                                'ruleCollectionType': rc_type,
                                                'action': {'type': rc_action}
                                            }]
                                        },
                                        'ruleType': rule.get('ruleType', ''),
                                        'name': rule.get('name', ''),
                                        'notes': rule.get('notes', '')
                                    }
                                    
                                    # Add type-specific rule properties
                                    rule_type = rule.get('ruleType', '')
                                    
                                    # Common properties for all rule types
                                    rule_data.update({
                                        'sourceAddresses': ensure_list(rule.get('sourceAddresses', [])),
                                        'sourceIpGroups': ensure_list(rule.get('sourceIpGroups', [])),
                                        'destinationAddresses': ensure_list(rule.get('destinationAddresses', [])),
                                        'destinationIpGroups': ensure_list(rule.get('destinationIpGroups', []))
                                    })
                                    
                                    if rule_type == 'NetworkRule':
                                        rule_data.update({
                                            'ipProtocols': ensure_list(rule.get('ipProtocols', [])),
                                            'destinationFqdns': ensure_list(rule.get('destinationFqdns', [])),
                                            'destinationPorts': ensure_list(rule.get('destinationPorts', []))
                                        })
                                        resources_network.append(rule_data)
                                    
                                    elif rule_type == 'NatRule':
                                        rule_data.update({
                                            'ipProtocols': ensure_list(rule.get('ipProtocols', [])),
                                            'destinationPorts': ensure_list(rule.get('destinationPorts', [])),
                                            'translatedAddress': rule.get('translatedAddress', ''),
                                            'translatedFqdn': rule.get('translatedFqdn', ''),
                                            'translatedPort': rule.get('translatedPort', '')
                                        })
                                        resources_nat.append(rule_data)
                                    
                                    elif rule_type == 'ApplicationRule':
                                        rule_data.update({
                                            'protocols': ensure_list(rule.get('protocols', [])),
                                            'targetFqdns': ensure_list(rule.get('targetFqdns', [])),
                                            'targetUrls': ensure_list(rule.get('targetUrls', [])),
                                            'fqdnTags': ensure_list(rule.get('fqdnTags', [])),
                                            'webCategories': ensure_list(rule.get('webCategories', [])),
                                            'terminateTLS': rule.get('terminateTLS', ''),
                                            'httpHeadersToInsert': ensure_list(rule.get('httpHeadersToInsert', []))
                                        })
                                        resources_application.append(rule_data)

    logging.info(f"Collected {len(resources_nat)} NAT rules, {len(resources_network)} Network rules, and {len(resources_application)} Application rules")
    return resources_nat, resources_network, resources_application

def csv_render_csv(resources, output_path, rule_type=None):
    """
    Render the CSV file from the collected resources.
    
    Args:
        resources: List of resource data
        output_path: Path to save the CSV file
        rule_type: Optional rule type for unified template (NetworkRule, NatRule, or ApplicationRule)
    """
    try:
        # Initialize Jinja2 environment using centralized template directory
        env = Environment(loader=FileSystemLoader(Paths.TEMPLATES_DIR))
        
        # Add custom filter for safe joining
        def safe_join(value):
            if value is None:
                return ''
            if isinstance(value, (list, tuple)):
                return ','.join(str(v) for v in value)
            return str(value)
        
        # Add custom filter for joining destination ports with dollar symbol
        def dollar_join(value):
            if value is None:
                return ''
            if isinstance(value, (list, tuple)):
                return '$'.join(str(v) for v in value)
            return str(value)
        
        # Add custom filter for protocol formatting in Application Rules
        def protocol_join(protocols):
            if not protocols:
                return ''
            result = []
            for p in protocols:
                if isinstance(p, dict) and 'protocolType' in p and 'port' in p:
                    result.append(f"{p['protocolType']}:{p['port']}")
            return ','.join(result)
        
        # Add custom filter for HTTP headers formatting
        def header_join(headers):
            if not headers:
                return ''
            result = []
            for h in headers:
                if isinstance(h, dict) and 'header' in h and 'value' in h:
                    result.append(f"{h['header']}={h['value']}")
            return ','.join(result)
        
        # Register filters
        env.filters['safe_join'] = safe_join
        env.filters['dollar_join'] = dollar_join
        env.filters['protocol_join'] = protocol_join
        env.filters['header_join'] = header_join

        # Use the global template path from Parameters.py
        template_filename = os.path.basename(Paths.TEMPLATE_CSV)
        template = env.get_template(template_filename)
        
        # Add rule_type to context if provided
        context = {'resources': resources}
        if rule_type:
            context['rule_type'] = rule_type
            
        output = template.render(**context)
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as file:
            file.write(output)
        logging.info(f"Generated CSV file: {output_path}")
        return True
    except Exception as e:
        logging.error(f"Error rendering template for {output_path}: {e}", exc_info=True)
        return False