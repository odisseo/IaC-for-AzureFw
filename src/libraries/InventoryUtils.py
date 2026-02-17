"""
Inventory utilities for Azure Firewall Policy Manager.

This module provides functionality for collecting and processing policy data.
"""
import csv
import glob
import json
import logging
import os
import time
import yaml
from colorama import Fore, Style, init
from jinja2 import Environment, FileSystemLoader
from src.libraries.CommonUtils import CommonConfiguration, CommonData, CommonFile
from src.libraries.Parameters import Config, Paths

# Initialize colorama for cross-platform color support
init(autoreset=True)


class Yaml:
    """YAML utilities for policy data collection and processing."""
    
    # Helper methods (private)
    @staticmethod
    def _get_policy_parent(policy_path):
        """Get the parent policy from the main.yaml file."""
        main_yaml_path = os.path.join(policy_path, 'main.yaml')
        policy_data = CommonFile.load_yaml_file(main_yaml_path)
        if policy_data and 'properties' in policy_data and 'basePolicy' in policy_data['properties']:
            return policy_data['properties']['basePolicy']
        return ''
    
    @staticmethod
    def _transform_rule_data(rule):
        """
        Transform rule data to match the format expected by the Jinja template.
        Helper method for create_yaml_from_policies.
        
        Args:
            rule (dict): Rule data from CSV processing
        
        Returns:
            dict: Transformed rule data
        """
        # Import here to avoid circular dependency
        from src.libraries.InventoryUtils import ImportExport
        
        # Create a copy of the rule to avoid modifying the original
        transformed_rule = dict(rule)
        
        # Ensure all list fields are proper lists
        for field in ['ipProtocols', 'sourceAddresses', 'sourceIpGroups', 
                     'destinationAddresses', 'destinationIpGroups', 
                     'destinationFqdns', 'destinationPorts', 
                     'targetFqdns', 'targetUrls', 'fqdnTags', 
                     'webCategories', 'httpHeadersToInsert']:
            if field in transformed_rule:
                transformed_rule[field] = CommonData.ensure_list(transformed_rule[field])
        
        # Format IP groups
        if 'sourceIpGroups' in transformed_rule:
            transformed_rule['sourceIpGroups'] = [
                ImportExport._format_ip_group(ip_group) for ip_group in transformed_rule['sourceIpGroups']
            ]
        
        if 'destinationIpGroups' in transformed_rule:
            transformed_rule['destinationIpGroups'] = [
                ImportExport._format_ip_group(ip_group) for ip_group in transformed_rule['destinationIpGroups']
            ]
        
        return transformed_rule
    
    # Public methods
    @staticmethod
    def collect_policy_data(policies_dir):
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
                policy_parent = Yaml._get_policy_parent(policy_path)
                
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
                                    
                                    rc_data = CommonFile.load_yaml_file(rc_file_path)
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
                                            'sourceAddresses': CommonData.ensure_list(rule.get('sourceAddresses', [])),
                                            'sourceIpGroups': CommonData.ensure_list(rule.get('sourceIpGroups', [])),
                                            'destinationAddresses': CommonData.ensure_list(rule.get('destinationAddresses', [])),
                                            'destinationIpGroups': CommonData.ensure_list(rule.get('destinationIpGroups', []))
                                        })
                                        
                                        if rule_type == 'NetworkRule':
                                            rule_data.update({
                                                'ipProtocols': CommonData.ensure_list(rule.get('ipProtocols', [])),
                                                'destinationFqdns': CommonData.ensure_list(rule.get('destinationFqdns', [])),
                                                'destinationPorts': CommonData.ensure_list(rule.get('destinationPorts', []))
                                            })
                                            resources_network.append(rule_data)
                                        
                                        elif rule_type == 'NatRule':
                                            rule_data.update({
                                                'ipProtocols': CommonData.ensure_list(rule.get('ipProtocols', [])),
                                                'destinationPorts': CommonData.ensure_list(rule.get('destinationPorts', [])),
                                                'translatedAddress': rule.get('translatedAddress', ''),
                                                'translatedFqdn': rule.get('translatedFqdn', ''),
                                                'translatedPort': rule.get('translatedPort', '')
                                            })
                                            resources_nat.append(rule_data)
                                        
                                        elif rule_type == 'ApplicationRule':
                                            rule_data.update({
                                                'protocols': CommonData.ensure_list(rule.get('protocols', [])),
                                                'targetFqdns': CommonData.ensure_list(rule.get('targetFqdns', [])),
                                                'targetUrls': CommonData.ensure_list(rule.get('targetUrls', [])),
                                                'fqdnTags': CommonData.ensure_list(rule.get('fqdnTags', [])),
                                                'webCategories': CommonData.ensure_list(rule.get('webCategories', [])),
                                                'terminateTLS': rule.get('terminateTLS', ''),
                                                'httpHeadersToInsert': CommonData.ensure_list(rule.get('httpHeadersToInsert', []))
                                            })
                                            resources_application.append(rule_data)

        logging.info(f"Collected {len(resources_nat)} NAT rules, {len(resources_network)} Network rules, and {len(resources_application)} Application rules")
        return resources_nat, resources_network, resources_application
    
    @staticmethod
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
                        rule_data = Yaml._transform_rule_data(rule)
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


class Csv:
    """CSV utilities for processing firewall rules from CSV files."""
    
    # Helper methods (private)
    @staticmethod
    def _split_values(value, separator=','):
        """
        Split and clean values from CSV field.
        
        Args:
            value: String value to split
            separator: Character to use as separator (default: comma)
            
        Returns:
            list: List of cleaned values
        """
        if not value:
            return []
        return [v.strip() for v in value.split(separator) if v.strip()]
    
    @staticmethod
    def _parse_headers(header_str):
        """
        Parse HTTP headers from string format.
        
        Args:
            header_str: String containing headers in format "name:value,name:value"
            
        Returns:
            list: List of dictionaries with 'name' and 'value' keys
        """
        headers = []
        if not header_str:
            return headers
        
        for header in header_str.split(','):
            if ':' in header:
                name, value = header.split(':', 1)
                headers.append({
                    'name': name.strip(),
                    'value': value.strip()
                })
        return headers
    
    # Public methods
    @staticmethod
    def process_csv_file(csv_path, rule_type, policies):
        """
        Process a CSV file containing firewall rules and populate the policies dictionary.
        
        Args:
            csv_path: Path to the CSV file
            rule_type: Type of rules in the file (network, nat, application)
            policies: Dictionary to populate with policy data
            
        Returns:
            bool: True if successful, False otherwise
        """
        logging.info(f"Processing {rule_type} rules from {csv_path}")
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as file:
                # Use semicolon delimiter for CSV format
                reader = csv.DictReader(file, delimiter=';')
                
                for row in reader:
                    # Extract policy information
                    policy_name = row.get('PolicyName', '').strip()
                    if not policy_name:
                        continue
                    
                    # Initialize policy if it doesn't exist
                    if policy_name not in policies:
                        policies[policy_name] = {
                            'parent_policy': row.get('ParentPolicy', '').strip(),
                            'rule_collection_groups': {}
                        }
                    
                    # Extract rule collection group information
                    rcg_name = row.get('RuleCollectionGroup', '').strip()
                    if not rcg_name:
                        continue
                    
                    rcg_priority = row.get('RuleCollectionGroupPriority', '1000')
                    
                    # Initialize RCG if it doesn't exist
                    if rcg_name not in policies[policy_name]['rule_collection_groups']:
                        policies[policy_name]['rule_collection_groups'][rcg_name] = {
                            'priority': rcg_priority,
                            'rule_collections': {}
                        }
                    
                    # Extract rule collection information
                    rc_name = row.get('RuleCollection', '').strip()
                    if not rc_name:
                        continue
                    
                    rc_priority = row.get('RuleCollectionPriority', '1000')
                    rc_type = row.get('RuleCollectionType', 'FirewallPolicyFilterRuleCollection')
                    rc_action = row.get('RuleCollectionAction', 'Allow').strip()
                    
                    # Initialize RC if it doesn't exist
                    if rc_name not in policies[policy_name]['rule_collection_groups'][rcg_name]['rule_collections']:
                        policies[policy_name]['rule_collection_groups'][rcg_name]['rule_collections'][rc_name] = {
                            'priority': rc_priority,
                            'type': rc_type,
                            'action': rc_action,
                            'rules': []
                        }
                    
                    # Extract rule information
                    rule_name = row.get('RuleName', '')
                    rule_type_specific = row.get('RuleType', '')
                    
                    # Create base rule
                    rule = {
                        'name': rule_name,
                        'ruleType': rule_type_specific
                    }
                    
                    # Add rule-specific fields
                    if rule_type_specific == 'NetworkRule':
                        rule.update({
                            'ipProtocols': row.get('IpProtocols', '').split(','),
                            'sourceAddresses': Csv._split_values(row.get('SourceAddresses', '')),
                            'sourceIpGroups': Csv._split_values(row.get('SourceIpGroups', '')),
                            'destinationAddresses': Csv._split_values(row.get('DestinationAddresses', '')),
                            'destinationIpGroups': Csv._split_values(row.get('DestinationIpGroups', '')),
                            'destinationFqdns': Csv._split_values(row.get('DestinationFqdns', '')),
                            'destinationPorts': Csv._split_values(row.get('DestinationPorts', ''), '$')
                        })
                    
                    elif rule_type_specific == 'NatRule':
                        rule.update({
                            'ipProtocols': row.get('IpProtocols', '').split(','),
                            'sourceAddresses': Csv._split_values(row.get('SourceAddresses', '')),
                            'sourceIpGroups': Csv._split_values(row.get('SourceIpGroups', '')),
                            'destinationAddresses': Csv._split_values(row.get('DestinationAddresses', '')),
                            'destinationPorts': Csv._split_values(row.get('DestinationPorts', ''), '$'),
                            'translatedAddress': row.get('TranslatedAddress', ''),
                            'translatedFqdn': row.get('TranslatedFqdn', ''),
                            'translatedPort': row.get('TranslatedPort', '')
                        })
                    
                    elif rule_type_specific == 'ApplicationRule':
                        # Parse protocols for application rules
                        protocol_str = row.get('Protocols', '')
                        protocols = []
                        for p in protocol_str.split(','):
                            if ':' in p:
                                protocol_type, port = p.split(':')
                                protocols.append({
                                    'protocolType': protocol_type.strip(),
                                    'port': int(port.strip())
                                })
                        
                        rule.update({
                            'protocols': protocols,
                            'sourceAddresses': Csv._split_values(row.get('SourceAddresses', '')),
                            'sourceIpGroups': Csv._split_values(row.get('SourceIpGroups', '')),
                            'destinationAddresses': Csv._split_values(row.get('DestinationAddresses', '')),
                            'destinationIpGroups': Csv._split_values(row.get('DestinationIpGroups', '')),
                            'targetFqdns': Csv._split_values(row.get('TargetFqdns', '')),
                            'targetUrls': Csv._split_values(row.get('TargetUrls', '')),
                            'fqdnTags': Csv._split_values(row.get('FqdnTags', '')),
                            'webCategories': Csv._split_values(row.get('WebCategories', '')),
                            'terminateTLS': row.get('TerminateTLS', 'False').lower() == 'true',
                            'httpHeadersToInsert': Csv._parse_headers(row.get('HttpHeadersToInsert', ''))
                        })
                    
                    # Add notes if present
                    if 'Notes' in row and row['Notes']:
                        rule['notes'] = row['Notes']
                    
                    # Add the rule to the collection
                    policies[policy_name]['rule_collection_groups'][rcg_name]['rule_collections'][rc_name]['rules'].append(rule)
                    
            logging.info(f"Successfully processed {rule_type} rules from {csv_path}")
            return True
            
        except Exception as e:
            logging.error(f"Error processing {rule_type} rules from {csv_path}: {e}", exc_info=True)
            return False


class ImportExport:
    """Import and Export utilities for Azure Firewall policies."""
    
    # Helper methods (private)
    @staticmethod
    def _format_ip_group(ip_group):
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
        import re
        
        if not ip_group:
            return ""
            
        # Handle the case where the IP group is in the format [parameters('...')]
        param_match = re.match(r"\[parameters\('([^']+)'\)\]", ip_group)
        if param_match:
            ip_group_name = param_match.group(1)
            # If the parameter value itself is a resource path, extract the name
            if '/' in ip_group_name:
                return ImportExport._format_ip_group(ip_group_name)
            return CommonData.normalize_name(ip_group_name)
        
        # Handle the case where the IP group is a full resource path
        # This will match both:
        # - /subscriptions/.../ipGroups/NAME
        # - Microsoft.Network/ipGroups/NAME
        path_match = re.search(r'(?:/ipGroups/|/Microsoft\.Network/ipGroups/)([^/\s]+)(?:\s|$|/|\'|")', ip_group)
        if path_match:
            ip_group_name = path_match.group(1)
            return CommonData.normalize_name(ip_group_name)
        
        # If no special format is detected, just normalize the name
        return CommonData.normalize_name(ip_group)
    
    @staticmethod
    def _collect_policy_data_from_yaml(policies_dir):
        """
        Collect policy data from YAML files in the policy directory structure.
        
        Args:
            policies_dir (str): Directory containing policy YAML files
            
        Returns:
            dict: Dictionary containing policy data
        """
        policies = {}
        
        # Check if the policies directory exists
        if not os.path.isdir(policies_dir):
            logging.error(f"Policies directory doesn't exist: {policies_dir}")
            return policies
        
        # Process each policy folder
        for policy_name in os.listdir(policies_dir):
            policy_path = os.path.join(policies_dir, policy_name)
            if not os.path.isdir(policy_path):
                continue
                
            # Load main policy properties
            policy_main_yaml = os.path.join(policy_path, 'main.yaml')
            if not os.path.exists(policy_main_yaml):
                logging.warning(f"Missing main.yaml file for policy {policy_name}")
                continue
                
            policy_data = CommonFile.load_yaml_file(policy_main_yaml)
            
            # Extract basePolicyName and basePolicyVersion if they exist
            base_policy_name = None
            base_policy_version = None
            if policy_data and 'properties' in policy_data:
                base_policy_name = policy_data['properties'].get('basePolicyName')
                base_policy_version = policy_data['properties'].get('basePolicyVersion')
            
            # Use policy name from YAML if available, otherwise use folder name
            policy_key = policy_data.get('name', policy_name)
            
            # Extract insights if it exists
            insights = None
            if policy_data and 'properties' in policy_data and 'insights' in policy_data['properties']:
                insights = policy_data['properties']['insights']
            
            # Extract insight if it exists (alternative key name)
            if policy_data and 'properties' in policy_data and 'insight' in policy_data['properties']:
                insights = policy_data['properties']['insight']
            
            # Extract snat if it exists
            snat = None
            if policy_data and 'properties' in policy_data and 'snat' in policy_data['properties']:
                snat = policy_data['properties']['snat']
            
            # Extract tags if they exist
            tags = None
            if policy_data and 'tags' in policy_data:
                tags = policy_data['tags']
                
            # Extract SKU if it exists
            sku = None
            if policy_data and 'properties' in policy_data and 'sku' in policy_data['properties']:
                sku = policy_data['properties']['sku']
            
            # Create policy entry with policy_key as key
            policies[policy_key] = {
                "rcg_order": [],
                "rcgs": {},
                "basePolicyName": base_policy_name,
                "basePolicyVersion": base_policy_version,
                "basePolicyLastRcg": "",
                "original_name": policy_name,  # Store original name for reference
                "insights": insights,  # Add insights data
                "snat": snat,  # Add snat data
                "tags": tags,  # Add tags data
                "sku": sku  # Add sku data
            }
            
            # Process Rule Collection Groups (RCGs)
            rcg_folders = []
            for rcg_name in os.listdir(policy_path):
                rcg_path = os.path.join(policy_path, rcg_name)
                if os.path.isdir(rcg_path) and '_' in rcg_name:
                    try:
                        rcg_priority = int(rcg_name.split('_')[0])
                        rcg_folders.append((rcg_priority, rcg_name, rcg_path))
                    except ValueError:
                        logging.warning(f"Invalid RCG folder name format: {rcg_name}")
                        continue
            
            # Sort RCGs by priority
            rcg_folders.sort()
            
            # Process each RCG
            for _, rcg_folder_name, rcg_path in rcg_folders:
                # Parse priority and name from folder name (e.g., "00260_AZURE_SERVICES_TAGS_RCG")
                from src.libraries.CommonUtils import CommonData
                rcg_priority, rcg_name = CommonData.parse_priority_name(rcg_folder_name)
                
                # Add RCG to policy - Using policy_key instead of policy_name
                # Use clean name without priority prefix for Bicep export
                policies[policy_key]["rcg_order"].append(rcg_name)
                policies[policy_key]["rcgs"][rcg_name] = {
                    "RuleCollectionGroupPriority": rcg_priority,
                    "ruleCollections": {}
                }
                
                # Process Rule Collections (RCs)
                rc_files = []
                for file_name in os.listdir(rcg_path):
                    if file_name.endswith('.yaml') and file_name != 'main_rcg.yaml' and file_name != 'main.yaml':
                        rc_path = os.path.join(rcg_path, file_name)
                        if '_' in file_name:
                            try:
                                rc_priority = int(file_name.split('_')[0])
                                rc_name = '_'.join(file_name.split('_')[1:]).replace('.yaml', '')
                                rc_files.append((rc_priority, file_name, rc_name, rc_path))
                            except ValueError:
                                logging.warning(f"Invalid RC file name format: {file_name}")
                                continue
                
                # Sort RCs by priority
                rc_files.sort()
                
                # Process each RC
                for _, _, rc_name, rc_path in rc_files:
                    rc_data = CommonFile.load_yaml_file(rc_path)
                    if not rc_data:
                        logging.warning(f"Empty or invalid rule collection file: {rc_path}")
                        continue
                    
                    # Process rules in RC - get rules early and validate
                    rules = rc_data.get('rules')
                    if rules is None:
                        logging.warning(f"Rules field is None in rule collection: {rc_name} in {rcg_name}")
                        rules = []
                    elif not isinstance(rules, list):
                        logging.warning(f"Rules field is not a list in rule collection: {rc_name} in {rcg_name}")
                        rules = []
                    
                    # Skip empty rule collections to prevent template errors
                    if not rules:
                        logging.warning(f"Skipping empty rule collection: {rc_name} in {rcg_name}")
                        continue
                    
                    rc_priority = rc_path.split(os.sep)[-1].split('_')[0]
                    rc_type = rc_data.get('ruleCollectionType', '')
                    rc_action = rc_data.get('action', {})
                    
                    # Normalize action format
                    if isinstance(rc_action, str):
                        rc_action = {'type': rc_action}
                    
                    # Add RC to RCG - Using policy_key instead of policy_name
                    policies[policy_key]["rcgs"][rcg_name]["ruleCollections"][rc_name] = {
                        "RuleCollectionPriority": rc_priority,
                        "rules": []
                    }
                    
                    # Process each rule in the collection
                    for rule in rules:
                        if not isinstance(rule, dict):
                            logging.warning(f"Invalid rule format in {rc_name}, skipping: {rule}")
                            continue
                            
                        rule_type = rule.get('ruleType', '')
                        if not rule_type:
                            logging.warning(f"Rule missing ruleType in {rc_name}, skipping")
                            continue
                        
                        # Base rule data common for all rule types
                        rule_data = {
                            "RuleCollectionType": rc_type,
                            "RuleCollectionAction": rc_action.get('type', ''),
                            "RuleName": rule.get('name', ''),
                            "RuleType": rule_type,
                            "IpProtocols": ','.join(CommonData.ensure_list(rule.get('ipProtocols', []))),
                            "SourceAddresses": ','.join(CommonData.ensure_list(rule.get('sourceAddresses', []))),
                            "SourceIpGroups": ','.join(CommonData.ensure_list(rule.get('sourceIpGroups', []))),
                            "DestinationAddresses": ','.join(CommonData.ensure_list(rule.get('destinationAddresses', []))),
                            "DestinationIpGroups": ','.join(CommonData.ensure_list(rule.get('destinationIpGroups', []))),
                        }
                        
                        # Handle specific rule type properties
                        if rule_type == "NetworkRule":
                            rule_data.update({
                                "DestinationFqdns": ','.join(CommonData.ensure_list(rule.get('destinationFqdns', []))),
                                "DestinationPorts": ','.join(CommonData.ensure_list(rule.get('destinationPorts', []))),
                            })
                        elif rule_type == "NatRule":
                            rule_data.update({
                                "DestinationPorts": ','.join(CommonData.ensure_list(rule.get('destinationPorts', []))),
                                "TranslatedAddress": rule.get('translatedAddress', ''),
                                "TranslatedFqdn": rule.get('translatedFqdn', ''),
                                "TranslatedPort": rule.get('translatedPort', ''),
                            })
                        elif rule_type == "ApplicationRule":
                            # Process protocols for ApplicationRule
                            protocols = []
                            for protocol in CommonData.ensure_list(rule.get('protocols', [])):
                                if isinstance(protocol, dict) and 'protocolType' in protocol:
                                    # Handle protocol objects with protocolType and port
                                    protocol_type = protocol.get('protocolType', '')
                                    port = protocol.get('port', 443)
                                    protocols.append(f"{protocol_type}:{port}")
                                elif isinstance(protocol, str):
                                    # Handle simple protocol strings
                                    protocols.append(f"{protocol}:443")
                            
                            rule_data.update({
                                "Protocols": ','.join(protocols),
                                "TargetFqdns": ','.join(CommonData.ensure_list(rule.get('targetFqdns', []))),
                                "TargetUrls": ','.join(CommonData.ensure_list(rule.get('targetUrls', []))),
                                "FqdnTags": ','.join(CommonData.ensure_list(rule.get('fqdnTags', []))),
                                "WebCategories": ','.join(CommonData.ensure_list(rule.get('webCategories', []))),
                                "TerminateTLS": str(rule.get('terminateTLS', False)).lower(),
                            })
                            
                            # Process HTTP headers
                            http_headers = []
                            for header in CommonData.ensure_list(rule.get('httpHeadersToInsert', [])):
                                if isinstance(header, dict) and 'header' in header and 'value' in header:
                                    http_headers.append(f"{header['header']}={header['value']}")
                            
                            rule_data["HttpHeadersToInsert"] = ','.join(http_headers)
                        
                        # Using policy_key instead of policy_name
                        policies[policy_key]["rcgs"][rcg_name]["ruleCollections"][rc_name]["rules"].append(rule_data)
        
        return policies
    
    @staticmethod
    def _get_dr_ip(environment_name, prod_ip, dr_name):
        """
        Find the corresponding DR IP address for a given production IP address.
        
        Args:
            environment_name: The environment name for the group of firewalls
            prod_ip: The IP address of the production firewall
            dr_name: The name of the DR firewall to target (required)
            
        Returns:
            str: The corresponding DR IP address if found, "Null" if not found
        """
        logging.info(f"Looking for DR IP for prod IP: {prod_ip} in DR firewall: {dr_name}")
        
        # Get all firewalls for this environment
        firewalls_data, error_msg = CommonConfiguration.get_environment(
            environment_name=environment_name,
            load_yaml=True
        )
        
        if not firewalls_data:
            logging.error(f"No firewalls found for environment: {environment_name}")
            return "Null"
        
        # Find the production and target DR firewall
        prod_firewall = None
        target_dr_firewall = None
        
        for fw in firewalls_data:
            region_type = fw.get("regionType", "").upper()
            fw_name = fw.get("firewallName", "")
            
            if region_type == "PROD":
                prod_firewall = fw
                logging.info(f"Found Production firewall: {fw_name}")
            elif region_type == "DR" and fw_name == dr_name:
                target_dr_firewall = fw
                logging.info(f"Found target DR firewall: {fw_name}")
        
        if not prod_firewall:
            logging.error(f"No PROD firewall found in environment: {environment_name}")
            return "Null"
        
        if not target_dr_firewall:
            logging.error(f"DR firewall '{dr_name}' not found in environment: {environment_name}")
            return "Null"
        
        # Find the index of the prod_ip in the production firewall
        # fwPip format: {0: [name, ip], 1: [name, ip], ...}
        prod_pips = prod_firewall.get("fwPip", {})
        pip_index = None
        
        for index, pip_data in prod_pips.items():
            # pip_data is a list: [name, ip]
            if isinstance(pip_data, list) and len(pip_data) >= 2 and pip_data[1] == prod_ip:
                pip_index = index
                logging.info(f"Found prod IP {prod_ip} at index {pip_index}")
                break
        
        if pip_index is None:
            logging.warning(f"Production IP {prod_ip} not found in PROD firewall")
            return "Null"
        
        # Look up the same index in the target DR firewall
        dr_pips = target_dr_firewall.get("fwPip", {})
        dr_pip_data = dr_pips.get(pip_index)
        
        if dr_pip_data and isinstance(dr_pip_data, list) and len(dr_pip_data) >= 2:
            dr_ip = dr_pip_data[1]
            if dr_ip and dr_ip != "Null":
                logging.info(f"Found DR IP for index {pip_index} in '{dr_name}': {dr_ip}")
                return dr_ip
        
        logging.warning(f"No DR IP found for index {pip_index} in DR firewall '{dr_name}'")
        return "Null"
    
    @staticmethod
    def _edit_dr_destination_addresses(policies, environment_name, dr_firewall_name):
        """
        Edit destination addresses in NAT rules for DR firewalls.
        For each NAT rule, look up the corresponding DR IP for each destination address.
        If any destination address maps to "Null", remove the rule.
        Otherwise, update the destination addresses to their DR equivalents.
        
        Args:
            policies: Dictionary of policy data
            environment_name: Environment name to use for DR IP lookups
            dr_firewall_name: Name of the DR firewall to use for IP lookups
            
        Returns:
            dict: Updated policies dictionary with modified destination addresses
        """
        logging.info(f"Processing NatRules for DR firewall '{dr_firewall_name}' in environment '{environment_name}'")
        logging.info(f"Found {len(policies)} policies to process")
        
        for policy_key, policy_data in policies.items():
            logging.info(f"Processing policy: {policy_key}")
            
            if "rcgs" not in policy_data:
                logging.warning(f"No rule collection groups found in policy {policy_key}")
                continue
            
            for rcg_name, rcg_data in policy_data["rcgs"].items():
                if "ruleCollections" not in rcg_data:
                    logging.warning(f"No rule collections found in RCG {rcg_name}")
                    continue
                
                empty_rcs = []
                
                for rc_name, rc_data in rcg_data["ruleCollections"].items():
                    # Determine if this is a NAT rule collection
                    rc_type = next((v for k, v in rc_data.items() if k.lower() == "rulecollectiontype"), None)
                    
                    if not rc_type and ("NAT" in rc_name.upper() or "DNAT" in rc_name.upper()):
                        rc_type = "FirewallPolicyNatRuleCollection"
                        logging.info(f"Inferred NAT rule collection type from name: {rc_name}")
                    
                    is_nat_collection = rc_type and ("FirewallPolicyNatRuleCollection" == rc_type or "NAT" in rc_type.upper())
                    
                    if not is_nat_collection or "rules" not in rc_data:
                        continue
                    
                    rules_to_remove = []
                    
                    for i, rule in enumerate(rc_data["rules"]):
                        rule_type = next((v for k, v in rule.items() if k.lower() == "ruletype"), None)
                        rule_name = next((v for k, v in rule.items() if k.lower() == "rulename"), "Unnamed")
                        dest_addr_key = next((k for k in rule.keys() if k.lower() == "destinationaddresses"), None)
                        
                        if rule_type and rule_type.lower() == "natrule" and dest_addr_key:
                            logging.info(f"Processing NatRule: {rule_name} for DR firewall")
                            
                            dest_addresses_str = rule.get(dest_addr_key, "")
                            
                            # Handle both comma-separated string and list formats
                            if isinstance(dest_addresses_str, str):
                                dest_addresses = [addr.strip() for addr in dest_addresses_str.split(',') if addr.strip()]
                            else:
                                dest_addresses = dest_addresses_str
                            
                            logging.info(f"Original destination addresses: {dest_addresses}")
                            
                            updated_dest_addresses = []
                            remove_rule = False
                            
                            for dest_addr in dest_addresses:
                                dr_ip = ImportExport._get_dr_ip(environment_name, dest_addr, dr_firewall_name)
                                
                                if dr_ip == "Null":
                                    logging.info(f"DR IP for {dest_addr} is Null - rule '{rule_name}' will be removed")
                                    remove_rule = True
                                    break
                                else:
                                    logging.info(f"Found DR IP mapping: {dest_addr} -> {dr_ip}")
                                    updated_dest_addresses.append(dr_ip)
                            
                            if remove_rule:
                                if i not in rules_to_remove:
                                    rules_to_remove.append(i)
                            elif updated_dest_addresses:
                                filtered_addresses = [addr for addr in updated_dest_addresses if addr is not None]
                                
                                if not filtered_addresses:
                                    logging.info(f"All destination addresses for rule {rule_name} are None - rule will be removed")
                                    if i not in rules_to_remove:
                                        rules_to_remove.append(i)
                                else:
                                    logging.info(f"Updating destination addresses for rule {rule_name}: {dest_addresses} -> {filtered_addresses}")
                                    if isinstance(dest_addresses_str, str):
                                        rule[dest_addr_key] = ','.join(filtered_addresses)
                                    else:
                                        rule[dest_addr_key] = filtered_addresses
                    
                    # Remove rules with Null DR IPs (in reverse order)
                    for rule_index in sorted(rules_to_remove, reverse=True):
                        rule_name = next((v for k, v in rc_data["rules"][rule_index].items() if k.lower() == "rulename"), "Unnamed")
                        logging.info(f"Removing NatRule '{rule_name}' because it has Null DR IPs")
                        del rc_data["rules"][rule_index]
                    
                    # Mark empty rule collections for removal
                    if not rc_data["rules"]:
                        logging.info(f"Rule collection '{rc_name}' in group '{rcg_name}' is now empty and will be removed.")
                        empty_rcs.append(rc_name)
                
                # Remove empty rule collections
                for rc_name in empty_rcs:
                    del rcg_data["ruleCollections"][rc_name]
                
                # Mark empty rule collection groups for removal
                if not rcg_data["ruleCollections"]:
                    logging.info(f"Rule collection group '{rcg_name}' in policy '{policy_key}' is now empty and will be removed.")
                    policy_data["rcgs"][rcg_name] = None
            
            # Remove empty RCGs
            empty_rcgs = [rcg for rcg, val in policy_data["rcgs"].items() if val is None]
            for rcg in empty_rcgs:
                logging.info(f"Removing empty rule collection group '{rcg}' from policy '{policy_key}'")
                del policy_data["rcgs"][rcg]
            
            # Update rcg_order to only include RCGs that still exist
            if "rcg_order" in policy_data:
                logging.info(f"Original rcg_order: {policy_data['rcg_order']}")
                policy_data["rcg_order"] = [rcg for rcg in policy_data["rcg_order"] if rcg in policy_data["rcgs"]]
                logging.info(f"Updated rcg_order: {policy_data['rcg_order']}")
        
        return policies
    
    @staticmethod
    def _validate_rule_types(policies):
        """
        Validate rule types in the policies data to ensure all required fields are present.
        
        Args:
            policies: Dictionary of policy data
        
        Returns:
            bool: True if validation passes, False otherwise
        """
        validation_passed = True
        
        for policy_key, policy_data in policies.items():
            for rcg_name, rcg_data in policy_data["rcgs"].items():
                for rc_name, rc_data in rcg_data["ruleCollections"].items():
                    for rule in rc_data["rules"]:
                        rule_type = rule.get("RuleType")
                        rule_name = rule.get('RuleName', 'Unknown')
                        
                        # Validation rules based on rule type
                        if rule_type == "NetworkRule":
                            if not rule.get("IpProtocols"):
                                logging.warning(f"NetworkRule '{rule_name}' missing IpProtocols in {policy_key}/{rcg_name}/{rc_name}")
                                validation_passed = False
                        elif rule_type == "NatRule":
                            if not rule.get("IpProtocols"):
                                logging.warning(f"NatRule '{rule_name}' missing IpProtocols in {policy_key}/{rcg_name}/{rc_name}")
                                validation_passed = False
                        elif rule_type == "ApplicationRule":
                            if not rule.get("Protocols") and rule_name:
                                logging.warning(f"ApplicationRule '{rule_name}' missing Protocols in {policy_key}/{rcg_name}/{rc_name}")
                                validation_passed = False
                        else:
                            logging.warning(f"Unknown rule type '{rule_type}' for rule '{rule_name}' in {policy_key}/{rcg_name}/{rc_name}")
                            validation_passed = False
        
        if not validation_passed:
            logging.error("Validation failed for rule types. Check warnings above.")
        
        return validation_passed
    
    # Public methods
    @staticmethod
    def _generate_bicep(policy_data_with_suffix, output_name, firewall_config):
        """
        Generate a single Bicep file for a policy.
        
        Args:
            policy_data_with_suffix: Policy data dict with policy_name_with_suffix field
            output_name: Name for the output Bicep file (without .bicep extension)
            firewall_config: Firewall configuration dictionary
            
        Returns:
            str: Path to generated Bicep file if successful, None otherwise
        """
        bicep_file_name = f"{output_name}.bicep"
        output_path = os.path.join(Paths.BICEP_DIR, bicep_file_name)
        
        # Construct basePolicy from firewall config and policy's basePolicyVersion
        base_policy_version = policy_data_with_suffix.get('basePolicyVersion')
        
        if base_policy_version:
            # Get basePolicyName, subscription, RG from firewall config
            base_policy_name = firewall_config.get('basePolicyName', '')
            base_policy_subscription = firewall_config.get('basePolicySubscription', '')
            base_policy_rg = firewall_config.get('basePolicyRG', '')
            
            if base_policy_name and base_policy_subscription and base_policy_rg:
                # Construct full name: parent + _ + 20260116_82d81b0 = parent_20260116_82d81b0
                base_policy_full_name = f"{base_policy_name}_{base_policy_version}"
                
                # Construct full ID
                base_policy_id = f"/subscriptions/{base_policy_subscription}/resourceGroups/{base_policy_rg}/providers/Microsoft.Network/firewallPolicies/{base_policy_full_name}"
                
                policy_data_with_suffix["basePolicy"] = {'id': base_policy_id}
                logging.info(f"BasePolicy ID: {base_policy_id}")
            else:
                policy_data_with_suffix["basePolicy"] = None
                logging.warning(f"BasePolicy version exists but firewall config incomplete - skipping basePolicy")
        else:
            # No basePolicy for this policy
            policy_data_with_suffix["basePolicy"] = None
        
        # Render the template for the current policy
        if CommonFile.render_jinja_template(
            Paths.TEMPLATE_POLICY_BICEP,
            output_path,
            policy_data=policy_data_with_suffix,
            subscriptionid=firewall_config.get("policiesSubscriptionId", ""),
            ipgrouprg=firewall_config.get("ipGroupsResourceGroup", ""),
            ipgroupssubscriptionid=firewall_config.get("ipGroupssubscriptionId", 
                                                        firewall_config.get("policiesSubscriptionId", "")),
            policiesrg=firewall_config.get("policiesResourceGroup", ""),
            regionName=firewall_config.get("regionName", Config.DEFAULT_LOCATION),
            api_version=Config.FIREWALL_API_VERSION
        ):
            logging.info(f"Generated Bicep file: {bicep_file_name}")
            return output_path
        else:
            logging.error(f"Failed to generate Bicep file: {bicep_file_name}")
            return None

    @staticmethod
    def export_policies(environment_name, version):
        """
        Export Azure Firewall policies from YAML structure to Bicep templates.
        
        For each policy index in the PROD firewall's policiesName list:
        1. Generate a Bicep file for the PROD policy
        2. Generate Bicep files for each DR firewall's corresponding policy (same index)
        
        Args:
            environment_name: Name of the environment to export policies for
            version: Version suffix for policy names (e.g., "20260116_82d81b0")
            
        Returns:
            tuple: (success, generated_files) where success is a boolean and 
                   generated_files is a dict with 'policies' key
        """
        # Ensure directories exist
        os.makedirs(Paths.POLICIES_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(Paths.TEMPLATE_POLICY_BICEP), exist_ok=True)
        os.makedirs(Paths.BICEP_DIR, exist_ok=True)
        
        generated_files = {'policies': []}
        
        # Get all firewalls for this environment
        firewalls_data, error_msg = CommonConfiguration.get_environment(
            environment_name=environment_name,
            load_yaml=True
        )
        
        if not firewalls_data:
            logging.error(f"No firewalls found for environment: {environment_name}")
            return False, generated_files
        
        # Separate PROD and DR firewalls
        prod_firewall = None
        dr_firewalls = []
        
        for fw in firewalls_data:
            region_type = fw.get("regionType", "").upper()
            if region_type == "PROD":
                prod_firewall = fw
            else:
                dr_firewalls.append(fw)
        
        if not prod_firewall:
            logging.error(f"No PROD firewall found in environment: {environment_name}")
            return False, generated_files
        
        # Get PROD policies names (can be list or dict with integer keys)
        prod_policies_names_raw = prod_firewall.get("policiesName", [])
        if not prod_policies_names_raw:
            logging.error("PROD firewall has no policiesName defined")
            return False, generated_files
        
        # Convert to list if it's a dict with integer keys
        if isinstance(prod_policies_names_raw, dict):
            # Sort by key and extract values
            prod_policies_names = [prod_policies_names_raw[k] for k in sorted(prod_policies_names_raw.keys())]
        else:
            prod_policies_names = prod_policies_names_raw
        
        logging.info(f"Found {len(prod_policies_names)} PROD policies and {len(dr_firewalls)} DR firewalls")
        
        # Collect all policy data from YAML (without suffix)
        policies = ImportExport._collect_policy_data_from_yaml(Paths.POLICIES_DIR)
        if not policies:
            logging.error("No policies found in policies directory")
            return False, generated_files
        
        # Validate rule types
        if not ImportExport._validate_rule_types(policies):
            logging.warning("Rule type validation failed, but continuing with export")
        
        success = True
        
        # Process each policy index
        for index, prod_policy_name in enumerate(prod_policies_names):
            # Check if PROD policy exists in the collected policies
            if prod_policy_name not in policies:
                logging.warning(f"PROD policy '{prod_policy_name}' not found in policies directory, skipping")
                continue
            
            # Get the PROD policy data
            prod_policy_data = policies[prod_policy_name].copy()
            
            # Create policy_name_with_suffix for PROD
            policy_name_with_suffix = f"{prod_policy_name}_{version}"
            prod_policy_data["policy_name_with_suffix"] = policy_name_with_suffix
            
            logging.info(f"Processing PROD policy: {prod_policy_name} (index {index})")
            
            # Generate PROD Bicep file
            output_path = ImportExport._generate_bicep(
                prod_policy_data, 
                prod_policy_name,  # Bicep filename without suffix
                prod_firewall
            )
            if output_path:
                generated_files['policies'].append(output_path)
            else:
                success = False
            
            # Process DR firewalls for the same policy index
            for dr_fw in dr_firewalls:
                dr_policies_names_raw = dr_fw.get("policiesName", [])
                dr_fw_name = dr_fw.get("firewallName", "Unknown")
                
                # Convert to list if it's a dict with integer keys
                if isinstance(dr_policies_names_raw, dict):
                    dr_policies_names = [dr_policies_names_raw[k] for k in sorted(dr_policies_names_raw.keys())]
                else:
                    dr_policies_names = dr_policies_names_raw
                
                # Check if this DR firewall has a policy at the same index
                if index >= len(dr_policies_names):
                    logging.warning(f"DR firewall '{dr_fw_name}' has no policy at index {index}, skipping")
                    continue
                
                dr_policy_name = dr_policies_names[index]
                
                # Create DR policy data by copying PROD rules but using DR policy name
                dr_policy_data = prod_policy_data.copy()
                
                # Update policy name with suffix for DR
                dr_policy_name_with_suffix = f"{dr_policy_name}_{version}"
                dr_policy_data["policy_name_with_suffix"] = dr_policy_name_with_suffix
                
                # Edit DR NAT rules destination addresses
                dr_policy_data_wrapped = {dr_policy_name: dr_policy_data}
                dr_policy_data_wrapped = ImportExport._edit_dr_destination_addresses(
                    dr_policy_data_wrapped, 
                    environment_name, 
                    dr_fw_name
                )
                dr_policy_data = dr_policy_data_wrapped[dr_policy_name]
                
                logging.info(f"Processing DR policy: {dr_policy_name} for firewall '{dr_fw_name}' (index {index})")
                
                # Generate DR Bicep file
                output_path = ImportExport._generate_bicep(
                    dr_policy_data,
                    dr_policy_name,  # Bicep filename without suffix
                    dr_fw
                )
                if output_path:
                    generated_files['policies'].append(output_path)
                else:
                    success = False
        
        logging.info(f"Export summary: Generated {len(generated_files['policies'])} Bicep files")
        return success, generated_files
    
    @staticmethod
    def import_policies(firewall_key=None):
        """
        Import Azure Firewall policies from individual ARM templates to YAML structure.
        
        Args:
            firewall_key: Optional firewall key to override the default

        Returns:
            tuple: (success, message) where success is a boolean and message provides
                   information about the operation
        """
        # Initialization and preparation
        fw_name = firewall_key or Config.FIREWALL_NAME
        os.makedirs(Paths.POLICIES_DIR, exist_ok=True)
        os.makedirs(Paths.CSV_DIR, exist_ok=True)
        
        # Find all ARM JSON templates
        arm_files = glob.glob(os.path.join(Paths.ARM_DIR, "*.json"))
        if not arm_files:
            logging.error(f"No ARM template files found in {Paths.ARM_DIR}")
            return False, "No ARM template files found"
        
        # Clean the policies directory
        logging.info("Cleaning policies directory before creating new structure...")
        if not CommonFile.clean_directory(Paths.POLICIES_DIR):
            logging.error("Failed to clean policies directory")
            return False, "Failed to clean policies directory"

        logging.info(f"Found {len(arm_files)} ARM template files to process")
        
        # Initialize tracking
        all_policies_processed = True
        policies_processed = 0
        processed_policies = {}
        
        # Set up Jinja templates once
        env = Environment(loader=FileSystemLoader(Paths.TEMPLATES_DIR))
        policy_template = env.get_template('policy.yaml.jinja2')
        rcg_template = env.get_template('rcg.yaml.jinja2')
        rc_template = env.get_template('rc.yaml.jinja2')
        
        # Process each ARM template file
        for arm_file in arm_files:
            try:
                logging.info(f"Processing ARM template: {os.path.basename(arm_file)}")
                
                # Load and parse the JSON template
                data = CommonFile.load_json_file(arm_file)
                if not data:
                    logging.error(f"Failed to load ARM template: {arm_file}")
                    all_policies_processed = False
                    continue
                
                # Extract policy resource and rule collection groups
                policy_resource = None
                rule_collection_groups = []
                
                for resource in data.get('resources', []):
                    resource_type = resource['type']
                    if resource_type == 'Microsoft.Network/firewallPolicies':
                        policy_resource = resource
                    elif resource_type == 'Microsoft.Network/firewallPolicies/ruleCollectionGroups':
                        rule_collection_groups.append(resource)
                
                if not policy_resource:
                    logging.error(f"No firewall policy found in {arm_file}")
                    all_policies_processed = False
                    continue
                
                # Extract and normalize policy name
                policy_name = policy_resource['name']
                base_name, _ = CommonData.separate_name_suffix(policy_name)
                policy_name_normalized = CommonData.normalize_name(base_name)
                
                # Handle duplicate policies
                if policy_name_normalized in processed_policies:
                    existing_file = processed_policies[policy_name_normalized]
                    logging.warning(f"Duplicate policy found: {policy_name} in {arm_file}")
                    print(f"\n{Fore.YELLOW}Duplicate policy '{policy_name}' found in {arm_file}{Style.RESET_ALL}")
                    print(f"A policy with this normalized name already exists from: {existing_file}")
                    print(f"\n{Fore.CYAN}How do you want to handle this duplicate?{Style.RESET_ALL}")
                    print("1. Replace existing with new version")
                    print("2. Keep existing version (ignore new)")
                    print("3. Process both (will create separate rule collection groups)")
                    
                    choice = ""
                    while choice not in ["1", "2", "3"]:
                        choice = input("Enter your choice (1, 2, or 3): ").strip()
                    
                    if choice == "1":
                        logging.info(f"Replacing policy {policy_name} with new version from {arm_file}")
                        policy_dir = os.path.join(Paths.POLICIES_DIR, policy_name_normalized)
                        if os.path.exists(policy_dir):
                            if not CommonFile.clean_directory(policy_dir):
                                logging.error(f"Failed to clean policy directory for replacement: {policy_dir}")
                                all_policies_processed = False
                                continue
                    elif choice == "2":
                        logging.info(f"Keeping existing policy {policy_name}, ignoring version from {arm_file}")
                        continue
                    else:
                        logging.info(f"Processing both policy versions for {policy_name}")
                
                # Track this policy as processed
                processed_policies[policy_name_normalized] = arm_file
                
                # Create policy directory
                policy_dir = os.path.join(Paths.POLICIES_DIR, policy_name_normalized)
                os.makedirs(policy_dir, exist_ok=True)
                
                # Extract policy properties
                policy_props = policy_resource.get('properties', {})
                base_policy_data = policy_props.get('basePolicy', None)
                
                # Extract basePolicyName and basePolicyVersion from basePolicy ID
                base_policy_name = ''
                base_policy_version = ''
                
                if base_policy_data and isinstance(base_policy_data, dict):
                    base_policy_id = base_policy_data.get('id', '')
                    if base_policy_id:
                        # Extract policy full name: parent_20260116_82d81b0
                        base_policy_full_name = base_policy_id.split('/')[-1]
                        
                        # Split into name and version
                        # parent_20260116_82d81b0 -> name: parent, version: 20260116_82d81b0
                        import re
                        match = re.match(r'^(.+?)_(\d{8}_[a-f0-9]+)$', base_policy_full_name)
                        if match:
                            base_policy_name = match.group(1)
                            base_policy_version = match.group(2)
                            logging.info(f"Extracted basePolicy: name={base_policy_name}, version={base_policy_version}")
                        else:
                            # No version suffix, use full name
                            base_policy_name = base_policy_full_name
                            logging.warning(f"BasePolicy has no version suffix: {base_policy_full_name}")
                
                insights = policy_props.get('insights')
                snat = policy_props.get('snat')
                tags = policy_resource.get('tags')
                
                # Create main.yaml in policy directory
                main_yaml_path = os.path.join(policy_dir, 'main.yaml')
                main_yaml_content = policy_template.render(
                    base_policy_name=base_policy_name,
                    base_policy_version=base_policy_version,
                    api_version=Config.FIREWALL_API_VERSION,
                    insights=insights,
                    snat=snat,
                    tags=tags
                )
                if not CommonFile.save_file(main_yaml_content, main_yaml_path):
                    logging.error(f"Failed to save main policy YAML for {policy_name_normalized}")
                    all_policies_processed = False
                    continue
                
                # Process rule collection groups
                for rcg in rule_collection_groups:
                    try:
                        # Extract RCG name and priority
                        rcg_name = rcg['name'].split('/')[-1]
                        rcg_props = rcg.get('properties', {})
                        rcg_priority = str(rcg_props.get('priority', '1000')).zfill(5)
                        
                        # Clean RCG name
                        rcg_clean_name = rcg_name
                        if '_' in rcg_name:
                            parts = rcg_name.split('_', 1)
                            if len(parts) > 1 and parts[0].isdigit():
                                rcg_clean_name = parts[1]
                        
                        rcg_clean_name = CommonData.normalize_name(rcg_clean_name)
                        
                        # Create RCG directory
                        rcg_dir = os.path.join(policy_dir, f"{rcg_priority}_{rcg_clean_name}")
                        os.makedirs(rcg_dir, exist_ok=True)
                        logging.info(f"Creating RCG directory: {rcg_dir}")
                        
                        # Create main.yaml in RCG directory
                        rcg_main_yaml_path = os.path.join(rcg_dir, 'main.yaml')
                        rcg_main_yaml_content = rcg_template.render(api_version=Config.FIREWALL_API_VERSION)
                        if not CommonFile.save_file(rcg_main_yaml_content, rcg_main_yaml_path):
                            logging.error(f"Failed to save RCG main YAML for {rcg_clean_name}")
                            continue
                        
                        # Process rule collections
                        for rc in rcg_props.get('ruleCollections', []):
                            rc_name = CommonData.normalize_name(rc.get('name', ''))
                            rc_priority = str(rc.get('priority', '1000')).zfill(5)
                            
                            # Format IP groups in rules
                            rules = rc.get('rules', [])
                            for rule in rules:
                                # Format source IP groups
                                if 'sourceIpGroups' in rule:
                                    rule['sourceIpGroups'] = [ImportExport._format_ip_group(group) for group in rule['sourceIpGroups']]
                                
                                # Format destination IP groups
                                if 'destinationIpGroups' in rule:
                                    rule['destinationIpGroups'] = [ImportExport._format_ip_group(group) for group in rule['destinationIpGroups']]
                            
                            # Create RC YAML file
                            rc_yaml_path = os.path.join(rcg_dir, f"{rc_priority}_{rc_name}.yaml")
                            rc_yaml_content = rc_template.render(
                                name=rc_name,
                                priority=rc_priority,
                                rule_collection_type=rc.get('ruleCollectionType', ''),
                                action=rc.get('action', {}).get('type', 'Allow'),
                                rules=rules,
                                api_version=Config.FIREWALL_API_VERSION
                            )
                            if not CommonFile.save_file(rc_yaml_content, rc_yaml_path):
                                logging.error(f"Failed to save RC YAML for {rc_name}")
                                continue
                    
                    except Exception as e:
                        logging.error(f"Error processing RCG {rcg_clean_name}: {str(e)}")
                        continue
                
                # Track successful policy processing
                policies_processed += 1
                logging.info(f"Successfully processed policy {policy_name_normalized}")
                
            except Exception as e:
                logging.error(f"Error processing ARM template {arm_file}: {str(e)}")
                all_policies_processed = False
                continue
        
        # Return result
        if policies_processed == 0:
            return False, f"No policies were processed for firewall key: {fw_name}"
        elif not all_policies_processed:
            return False, f"Some policies failed to process. Successfully processed {policies_processed} policies."
        else:
            return True, f"Successfully processed all {policies_processed} policies"
    
    @staticmethod
    def sync_policies(folder1_path=None, folder2_path=None, args=None):
        """
        Execute the workflow for synchronizing policies between two folders.
        
        This function:
        1. Checks if folders exist and calculates their hashes
        2. Compares with stored hashes in .lock file
        3. Synchronizes folders based on hash comparisons
        4. Updates the .lock file with new hash values
        
        Args:
            folder1_path (str): Path to the first folder (defaults to Paths.POLICIES_DIR)
            folder2_path (str): Path to the second folder (defaults to Paths.CSV_DIR)
            args: Command line arguments with conflict resolution options
        
        Returns:
            bool: True if sync was successful, False otherwise
        """
        # Use default folder paths from Paths if not provided
        if folder1_path is None:
            folder1_path = Paths.POLICIES_DIR
        if folder2_path is None:
            folder2_path = Paths.CSV_DIR
        
        # Extract folder names from paths for lock file entries
        folder1_name = os.path.basename(folder1_path)
        folder2_name = os.path.basename(folder2_path)
            
        logging.info(f"Starting policy synchronization between {folder1_name} and {folder2_name}...")
        
        lock_file_path = Paths.LOCK_FILE
        
        # Check if folders exist and have content
        folder1_exists = os.path.isdir(folder1_path) and any(os.scandir(folder1_path))
        folder2_exists = os.path.isdir(folder2_path) and any(os.scandir(folder2_path))
        
        # Calculate hashes for existing folders
        hash1 = CommonFile.calculate_folder_hash(folder1_path) if folder1_exists else None
        date1 = time.time() if folder1_exists else None
        hash2 = CommonFile.calculate_folder_hash(folder2_path) if folder2_exists else None
        date2 = time.time() if folder2_exists else None
        
        # Load lock file data
        lock_data = []
        if os.path.exists(lock_file_path):
            try:
                with open(lock_file_path, 'r', encoding='utf-8') as file:
                    lock_data = yaml.safe_load(file) or []
                    if not isinstance(lock_data, list):
                        lock_data = []
            except Exception as e:
                logging.warning(f"Error reading .lock file, creating new: {e}")
                lock_data = []
        
        # Extract lock data for each folder
        lock_entry1 = next((entry for entry in lock_data if entry.get('name') == folder1_name), None)
        lock_entry2 = next((entry for entry in lock_data if entry.get('name') == folder2_name), None)
        
        lock_hash1 = lock_entry1.get('hash') if lock_entry1 else None
        lock_date1 = lock_entry1.get('date') if lock_entry1 else None
        lock_hash2 = lock_entry2.get('hash') if lock_entry2 else None
        lock_date2 = lock_entry2.get('date') if lock_entry2 else None
        
        # Process based on folder existence and hash comparisons
        
        # Case 1: NO folder 1, NO folder 2
        if not folder1_exists and not folder2_exists:
            logging.info("Both folders are empty or don't exist. Cleaning the .lock file.")
            # Create empty directories if they don't exist
            os.makedirs(folder1_path, exist_ok=True)
            os.makedirs(folder2_path, exist_ok=True)
            # Clean the lock file (create empty)
            with open(lock_file_path, 'w', encoding='utf-8') as file:
                yaml.dump([], file)
            return True
        
        # Case 2: YES folder 1, NO folder 2
        elif folder1_exists and not folder2_exists:
            logging.info("Folder 1 (yaml) exists but folder 2 (csv) is empty. Syncing folder 2 with folder 1.")
            # Create folder 2 and sync it with folder 1
            os.makedirs(folder2_path, exist_ok=True)
            
            try:
                # Clean the csv directory
                CommonFile.clean_directory(folder2_path)
                
                # Create CSV destination files
                csv_network_path = os.path.join(folder2_path, "csv_network.csv")
                csv_nat_path = os.path.join(folder2_path, "csv_nat.csv")
                csv_application_path = os.path.join(folder2_path, "csv_application.csv")
                
                # Collect policy data from the policies directory
                nat_rules, network_rules, application_rules = Yaml.collect_policy_data(folder1_path)
                
                # Generate CSV files
                if nat_rules:
                    CommonFile.render_jinja_template(Paths.TEMPLATE_CSV, csv_nat_path, resources=nat_rules, rule_type="NatRule")
                    logging.info(f"Generated NAT rules CSV: {csv_nat_path}")

                if network_rules:
                    CommonFile.render_jinja_template(Paths.TEMPLATE_CSV, csv_network_path, resources=network_rules, rule_type="NetworkRule")
                    logging.info(f"Generated Network rules CSV: {csv_network_path}")

                if application_rules:
                    CommonFile.render_jinja_template(Paths.TEMPLATE_CSV, csv_application_path, resources=application_rules, rule_type="ApplicationRule")
                    logging.info(f"Generated Application rules CSV: {csv_application_path}")
                
                # Calculate new hash for folder 2
                hash2 = CommonFile.calculate_folder_hash(folder2_path)
                date2 = date1  # Use the same date as folder 1
                
                # Update lock file for both folders
                CommonFile.update_lock_file(folder1_path, date1)
                CommonFile.update_lock_file(folder2_path, date2)
                
                logging.info("Successfully exported policies to CSV and updated lock file")
                return True
                    
            except Exception as e:
                logging.error(f"Error exporting policies to CSV: {e}", exc_info=True)
                return False
        
        # Case 3: NO folder 1, YES folder 2
        elif not folder1_exists and folder2_exists:
            logging.info("Folder 2 (csv) exists but folder 1 (yaml) is empty. Syncing folder 1 with folder 2.")
            # Create folder 1 and sync it with folder 2
            os.makedirs(folder1_path, exist_ok=True)
            
            try:
                # Clean the yaml directory
                CommonFile.clean_directory(folder1_path)
                
                # Dictionary to track policy info
                policies = {}
                
                # Process all CSV files in the directory
                csv_files = [f for f in os.listdir(folder2_path) if f.endswith('.csv')]
                for csv_file in csv_files:
                    csv_path = os.path.join(folder2_path, csv_file)
                    
                    # Determine rule type from filename
                    rule_type = None
                    if "network" in csv_file.lower():
                        rule_type = "network"
                    elif "nat" in csv_file.lower():
                        rule_type = "nat"
                    elif "application" in csv_file.lower():
                        rule_type = "application"
                    
                    if rule_type:
                        # Process CSV file to ensure correct structure
                        Csv.process_csv_file(csv_path, rule_type, policies)
                    else:
                        logging.warning(f"Could not determine rule type for CSV file: {csv_file}")
                
                # Create policy structure and YAML files
                Yaml.create_yaml_from_policies(policies, folder1_path)
                
                # Calculate new hash for folder 1
                hash1 = CommonFile.calculate_folder_hash(folder1_path)
                date1 = date2  # Use the same date as folder 2
                
                # Update lock file for both folders
                CommonFile.update_lock_file(folder1_path, date1)
                CommonFile.update_lock_file(folder2_path, date2)
                
                logging.info("Successfully exported CSV to YAML and updated lock file")
                return True
                
            except Exception as e:
                logging.error(f"Error exporting CSV to YAML: {e}", exc_info=True)
                return False
        
        # Case 4: YES folder 1, YES folder 2
        else:
            # Case 4a: hash1 != lock_hash1 and hash2 != lock_hash2
            if (hash1 != lock_hash1 and hash2 != lock_hash2):
                logging.warning("Both folders have been modified. There is a conflict.")
                
                # Use the passed args parameter for conflict resolution
                if args and hasattr(args, 'non_interactive') and args.non_interactive and hasattr(args, 'conflict_resolution') and args.conflict_resolution:
                    logging.info(f"Using non-interactive conflict resolution: {args.conflict_resolution}")
                    if args.conflict_resolution.lower() == "policies":
                        sync_direction = "policies_to_csv"
                    elif args.conflict_resolution.lower() == "csv":
                        sync_direction = "csv_to_policies"
                    else:  # "cancel" or any other value
                        logging.info("Sync operation cancelled by conflict resolution parameter")
                        return False
                else:
                    # Interactive conflict resolution
                    print("\nWARNING: Both yaml and csv directories have been modified.")
                    print("Please manually resolve conflicts by deciding which version to keep.")
                    print("Options:")
                    print("1. Use policy files as source of truth")
                    print("2. Use CSV files as source of truth")
                    print("3. Cancel sync operation")
                    
                    choice = input("\nEnter your choice (1-3): ")
                    if choice == "1":
                        sync_direction = "policies_to_csv"
                    elif choice == "2":
                        sync_direction = "csv_to_policies"
                    else:
                        logging.info("Sync operation cancelled by user")
                        return False
            
            # Case 4b: lock_date1 != lock_date2
            elif lock_date1 != lock_date2:
                logging.warning("Lock dates are different. There is a conflict.")
                
                # Interactive conflict resolution (same as above)
                print("\nWARNING: Lock dates for yaml and csv directories are different.")
                print("Please manually resolve conflicts by deciding which version to keep.")
                print("Options:")
                print("1. Use policy files as source of truth")
                print("2. Use CSV files as source of truth")
                print("3. Cancel sync operation")
                
                choice = input("\nEnter your choice (1-3): ")
                if choice == "1":
                    sync_direction = "policies_to_csv"
                elif choice == "2":
                    sync_direction = "csv_to_policies"
                else:
                    logging.info("Sync operation cancelled by user")
                    return False
            
            # Case 4c: hash1 != lock_hash1 and hash2 == lock_hash2
            elif hash1 != lock_hash1 and hash2 == lock_hash2:
                logging.info("Policies folder has been modified. Syncing CSV folder with policies.")
                sync_direction = "policies_to_csv"
            
            # Case 4d: hash1 == lock_hash1 and hash2 != lock_hash2
            elif hash1 == lock_hash1 and hash2 != lock_hash2:
                logging.info("CSV folder has been modified. Syncing policies folder with CSV.")
                sync_direction = "csv_to_policies"
            
            # Case 4e: No changes in either folder
            else:
                logging.info("Both folders are unchanged. No synchronization needed.")
                return True
            
            # Execute the synchronization based on the determined direction
            if sync_direction == "policies_to_csv":
                try:
                    # Clean the csv directory
                    CommonFile.clean_directory(folder2_path)
                    
                    # Create CSV destination files
                    csv_network_path = os.path.join(folder2_path, "csv_network.csv")
                    csv_nat_path = os.path.join(folder2_path, "csv_nat.csv")
                    csv_application_path = os.path.join(folder2_path, "csv_application.csv")
                    
                    # Collect policy data from the policies directory
                    nat_rules, network_rules, application_rules = Yaml.collect_policy_data(folder1_path)
                    
                    # Generate CSV files
                    if nat_rules:
                        CommonFile.render_jinja_template(Paths.TEMPLATE_CSV, csv_nat_path, resources=nat_rules, rule_type="NatRule")
                        logging.info(f"Generated NAT rules CSV: {csv_nat_path}")

                    if network_rules:
                        CommonFile.render_jinja_template(Paths.TEMPLATE_CSV, csv_network_path, resources=network_rules, rule_type="NetworkRule")
                        logging.info(f"Generated Network rules CSV: {csv_network_path}")

                    if application_rules:
                        CommonFile.render_jinja_template(Paths.TEMPLATE_CSV, csv_application_path, resources=application_rules, rule_type="ApplicationRule")
                        logging.info(f"Generated Application rules CSV: {csv_application_path}")
                    
                    # Calculate new hash for folder 2
                    hash2 = CommonFile.calculate_folder_hash(folder2_path)
                    current_time = time.time()
                    
                    # Update lock file for both folders with the same timestamp
                    CommonFile.update_lock_file(folder1_path, current_time)
                    CommonFile.update_lock_file(folder2_path, current_time)
                    
                    logging.info("Successfully exported policies to CSV and updated lock file")
                    return True
                        
                except Exception as e:
                    logging.error(f"Error exporting policies to CSV: {e}", exc_info=True)
                    return False
                    
            elif sync_direction == "csv_to_policies":
                try:
                    # Clean the _policies directory
                    CommonFile.clean_directory(folder1_path)
                    
                    # Dictionary to track policy info
                    policies = {}
                    
                    # Process all CSV files in the directory
                    csv_files = [f for f in os.listdir(folder2_path) if f.endswith('.csv')]
                    for csv_file in csv_files:
                        csv_path = os.path.join(folder2_path, csv_file)
                        
                        # Determine rule type from filename
                        rule_type = None
                        if "network" in csv_file.lower():
                            rule_type = "network"
                        elif "nat" in csv_file.lower():
                            rule_type = "nat"
                        elif "application" in csv_file.lower():
                            rule_type = "application"
                        
                        if rule_type:
                            # Process CSV file to ensure correct structure
                            Csv.process_csv_file(csv_path, rule_type, policies)
                        else:
                            logging.warning(f"Could not determine rule type for CSV file: {csv_file}")
                    
                    # Create policy structure and YAML files
                    Yaml.create_yaml_from_policies(policies, folder1_path)
                    
                    # Calculate new hash for folder 1
                    hash1 = CommonFile.calculate_folder_hash(folder1_path)
                    current_time = time.time()
                    
                    # Update lock file for both folders with the same timestamp
                    CommonFile.update_lock_file(folder1_path, current_time)
                    CommonFile.update_lock_file(folder2_path, current_time)
                    
                    logging.info("Successfully exported CSV to YAML and updated lock file")
                    return True
                    
                except Exception as e:
                    logging.error(f"Error exporting CSV to YAML: {e}", exc_info=True)
                    return False
        
        # If we reach here, something unexpected happened
        logging.warning("Unexpected state in sync workflow")
        return False
