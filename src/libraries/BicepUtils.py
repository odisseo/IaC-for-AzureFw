import os
import re
import json
import logging
from datetime import datetime
from src.libraries.CommonUtils import (
    load_yaml_file, render_jinja_template, 
    load_json_file,
    ensure_list,
    remove_date_suffix
)

policy_generation_count = {}

def collect_policy_data_from_yaml(policies_dir, commit_suffix=None):
    """
    Collect policy data from YAML files in the policy directory structure.
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
        policy_main_yaml = os.path.join(policy_path, 'main_policy.yaml')
        if not os.path.exists(policy_main_yaml):
            policy_main_yaml = os.path.join(policy_path, 'main.yaml')  # Try alternative name
            if not os.path.exists(policy_main_yaml):
                logging.warning(f"Missing main policy file for policy {policy_name}")
                continue
            
        policy_data = load_yaml_file(policy_main_yaml)
        base_policy = None
        
        # Extract base policy if it exists
        if policy_data and 'properties' in policy_data and 'basePolicy' in policy_data['properties']:
            base_policy_data = policy_data['properties']['basePolicy']
            if base_policy_data and isinstance(base_policy_data, dict) and 'id' in base_policy_data:
                base_policy = base_policy_data['id'].split('/')[-1]
            else:
                logging.warning(f"BasePolicy exists but does not have an 'id' field in policy {policy_name}")
        
        # Modify policy name with firewall name if provided
        modified_policy_name = policy_data.get('name', policy_name)  # Use name from YAML if available
        
        # Create the policy key with commit_suffix
        if commit_suffix:
            policy_key = f"{modified_policy_name}_{commit_suffix}"
        else:
            policy_key = modified_policy_name
        
        # Create policy entry with combined name including commit suffix
        policies[policy_key] = {
            "rcg_order": [],
            "rcgs": {},
            "date_suffix": "",
            "basePolicy": base_policy,
            "basePolicyLastRcg": "",
            "original_name": policy_name  # Store original name for reference
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
        for _, rcg_name, rcg_path in rcg_folders:
            rcg_priority = rcg_name.split('_')[0]
            
            # Add RCG to policy - Using policy_key instead of policy_name
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
                rc_data = load_yaml_file(rc_path)
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
                        "IpProtocols": ','.join(ensure_list(rule.get('ipProtocols', []))),
                        "SourceAddresses": ','.join(ensure_list(rule.get('sourceAddresses', []))),
                        "SourceIpGroups": ','.join(ensure_list(rule.get('sourceIpGroups', []))),
                        "DestinationAddresses": ','.join(ensure_list(rule.get('destinationAddresses', []))),
                        "DestinationIpGroups": ','.join(ensure_list(rule.get('destinationIpGroups', []))),
                    }
                    
                    # Handle specific rule type properties
                    if rule_type == "NetworkRule":
                        rule_data.update({
                            "DestinationFqdns": ','.join(ensure_list(rule.get('destinationFqdns', []))),
                            "DestinationPorts": ','.join(ensure_list(rule.get('destinationPorts', []))),
                        })
                    elif rule_type == "NatRule":
                        rule_data.update({
                            "DestinationPorts": ','.join(ensure_list(rule.get('destinationPorts', []))),
                            "TranslatedAddress": rule.get('translatedAddress', ''),
                            "TranslatedFqdn": rule.get('translatedFqdn', ''),
                            "TranslatedPort": rule.get('translatedPort', ''),
                        })
                    elif rule_type == "ApplicationRule":
                        # Process protocols for ApplicationRule
                        protocols = []
                        for protocol in ensure_list(rule.get('protocols', [])):
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
                            "TargetFqdns": ','.join(ensure_list(rule.get('targetFqdns', []))),
                            "TargetUrls": ','.join(ensure_list(rule.get('targetUrls', []))),
                            "FqdnTags": ','.join(ensure_list(rule.get('fqdnTags', []))),
                            "WebCategories": ','.join(ensure_list(rule.get('webCategories', []))),
                            "TerminateTLS": str(rule.get('terminateTLS', False)).lower(),
                        })
                        
                        # Process HTTP headers
                        http_headers = []
                        for header in ensure_list(rule.get('httpHeadersToInsert', [])):
                            if isinstance(header, dict) and 'header' in header and 'value' in header:
                                http_headers.append(f"{header['header']}={header['value']}")
                        
                        rule_data["HttpHeadersToInsert"] = ','.join(http_headers)
                    
                    # Using policy_key instead of policy_name
                    policies[policy_key]["rcgs"][rcg_name]["ruleCollections"][rc_name]["rules"].append(rule_data)
    
    # Link parent policies and find the last RCG of parents
    for policy_key, policy_data in policies.items():
        parent_policy = policy_data["basePolicy"]
        original_name = policy_data.get("original_name", policy_key)
        
        if parent_policy:
            # Find parent policies in the current set using original name
            for parent_key, parent_data in policies.items():
                parent_original = parent_data.get("original_name", parent_key)
                if parent_original == parent_policy:
                    if parent_data["rcg_order"]:
                        last_rcg = parent_data["rcg_order"][-1]
                        policies[policy_key]["basePolicyLastRcg"] = f"{parent_policy}_{last_rcg}"
    
    return policies

