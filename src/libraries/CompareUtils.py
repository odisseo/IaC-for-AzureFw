"""
Comparison utilities for Azure Firewall Policy Manager.

This module provides the functionality for comparing local YAML policies with Azure-deployed policies.
Uses identity-based matching with priority-prefix parsing.
"""

import os
import re
import json
import logging
import yaml
from datetime import datetime
from deepdiff import DeepDiff
from jinja2 import Environment, FileSystemLoader
from src.libraries.CommonUtils import CommonFile, CommonData
from src.libraries.Parameters import Paths

##########################################################################
# Rule Normalization Helper
##########################################################################

def normalize_rule(rule):
    """
    Normalize a rule to a canonical format for comparison.
    This ensures both ARM and YAML rules have the same structure.
    
    - Converts None to [] for array fields
    - Sorts array values for consistent comparison
    - Extracts only meaningful fields
    """
    # Define array fields that should be [] not None, containing strings
    string_array_fields = [
        'ipProtocols', 'sourceAddresses', 'sourceIpGroups', 
        'destinationAddresses', 'destinationIpGroups', 'destinationFqdns',
        'destinationPorts', 'targetFqdns', 'targetUrls',
        'fqdnTags', 'webCategories'
    ]
    
    # Array fields containing dicts (can't be sorted by value directly)
    dict_array_fields = ['protocols', 'httpHeadersToInsert']
    
    def normalize_value(value):
        """Normalize None/null to empty list."""
        if value is None:
            return []
        return value
    
    normalized = {
        'name': rule.get('name', ''),
        'ruleType': rule.get('ruleType', '')
    }
    
    # Copy all fields, normalizing arrays
    for key, value in rule.items():
        if key in ['name', 'ruleType']:
            continue
        if key in string_array_fields:
            val = normalize_value(value)
            normalized[key] = sorted(val) if val else []
        elif key in dict_array_fields:
            val = normalize_value(value)
            # Sort dicts by their string representation for consistent comparison
            normalized[key] = sorted(val, key=lambda x: json.dumps(x, sort_keys=True)) if val else []
        else:
            # Normalize None to appropriate defaults
            if value is None:
                normalized[key] = False if key in ['terminateTLS'] else value
            else:
                normalized[key] = value
    
    return normalized


def compare_rules(azure_rule, local_rule):
    """
    Compare two normalized rules field by field.
    
    Returns:
        list: List of differences found, empty if rules are identical
    """
    differences = []
    all_keys = set(azure_rule.keys()) | set(local_rule.keys())
    
    for key in sorted(all_keys):
        azure_val = azure_rule.get(key)
        local_val = local_rule.get(key)
        
        # Normalize None to [] for comparison
        if azure_val is None:
            azure_val = []
        if local_val is None:
            local_val = []
        
        # Sort arrays for comparison
        if isinstance(azure_val, list) and isinstance(local_val, list):
            try:
                azure_sorted = sorted(azure_val, key=lambda x: json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x))
                local_sorted = sorted(local_val, key=lambda x: json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x))
                if azure_sorted != local_sorted:
                    differences.append({
                        'field': key,
                        'azure_value': azure_val,
                        'local_value': local_val
                    })
            except:
                if azure_val != local_val:
                    differences.append({
                        'field': key,
                        'azure_value': azure_val,
                        'local_value': local_val
                    })
        elif azure_val != local_val:
            differences.append({
                'field': key,
                'azure_value': azure_val,
                'local_value': local_val
            })
    
    return differences


##########################################################################
# ComparePolicy Class
##########################################################################

class ComparePolicy:
    """Policy comparison utilities class."""

    @staticmethod
    def normalize_arm_template(arm_file_path):
        """
        Normalize ARM template JSON to standard policy structure.
        
        Reads ARM JSON, extracts policy and rule collection groups,
        and returns normalized structure with priority parsing.
        
        Args:
            arm_file_path (str): Path to ARM JSON file
            
        Returns:
            dict: Normalized policy structure or None on error
        """
        try:
            with open(arm_file_path, 'r', encoding='utf-8') as f:
                arm_data = json.load(f)
            
            resources = arm_data.get('resources', [])
            if not resources:
                logging.warning(f"No resources found in ARM template: {arm_file_path}")
                return None
            
            # Find the policy resource
            policy = None
            for resource in resources:
                if resource.get('type') == 'Microsoft.Network/firewallPolicies':
                    policy = resource
                    break
            
            if not policy:
                logging.error(f"No firewall policy found in ARM template: {arm_file_path}")
                return None
            
            # Extract policy properties
            policy_name = policy.get('name', '')
            policy_props = policy.get('properties', {})
            
            # Find all rule collection groups
            rcg_resources = []
            for resource in resources:
                if resource.get('type') == 'Microsoft.Network/firewallPolicies/ruleCollectionGroups':
                    rcg_resources.append(resource)
            
            # Normalize rule collection groups
            normalized_rcgs = []
            for rcg in rcg_resources:
                # Parse RCG name (format: "PolicyName/RCGName" or just "RCGName")
                rcg_full_name = rcg.get('name', '')
                if '/' in rcg_full_name:
                    rcg_prefixed_name = rcg_full_name.split('/')[-1]
                else:
                    rcg_prefixed_name = rcg_full_name
                
                # Strip priority prefix to get actual name for comparison
                rcg_priority_from_name, rcg_name = CommonData.parse_priority_name(rcg_prefixed_name)
                
                rcg_props = rcg.get('properties', {})
                rcg_priority = rcg_props.get('priority', rcg_priority_from_name)
                
                # Normalize rule collections
                normalized_rcs = []
                for rc in rcg_props.get('ruleCollections', []):
                    rc_prefixed_name = rc.get('name', '')
                    
                    # Strip priority prefix to get actual name for comparison
                    rc_priority_from_name, rc_name = CommonData.parse_priority_name(rc_prefixed_name)
                    
                    rc_priority = rc.get('priority', rc_priority_from_name)
                    rc_type = rc.get('ruleCollectionType', '')
                    
                    # Normalize rules using canonical format
                    normalized_rules = []
                    for rule in rc.get('rules', []):
                        normalized_rules.append(normalize_rule(rule))
                    
                    normalized_rcs.append({
                        'name': rc_name,
                        'priority': rc_priority,
                        'ruleCollectionType': rc_type,
                        'rules': normalized_rules
                    })
                
                normalized_rcgs.append({
                    'name': rcg_name,
                    'priority': rcg_priority,
                    'ruleCollections': normalized_rcs
                })
            
            # Return normalized structure
            return {
                'name': policy_name,
                'properties': policy_props,
                'ruleCollectionGroups': normalized_rcgs
            }
            
        except Exception as e:
            logging.error(f"Error normalizing ARM template {arm_file_path}: {e}", exc_info=True)
            return None

    @staticmethod
    def load_policy_from_yaml(policy_dir):
        """
        Load policy from YAML directory structure and normalize.
        
        Reads:
          policies/yaml/POLICY_NAME/
            ├── main.yaml
            ├── 15000_RCG_NAME/
            │   ├── main.yaml
            │   ├── 200_RC_NAME.yaml
        
        Args:
            policy_dir (str): Path to policy YAML directory
            
        Returns:
            dict: Normalized policy structure or None on error
        """
        try:
            if not os.path.exists(policy_dir):
                logging.error(f"Policy directory not found: {policy_dir}")
                return None
            
            # Load main policy file
            main_policy_file = os.path.join(policy_dir, 'main.yaml')
            if not os.path.exists(main_policy_file):
                logging.error(f"Main policy file not found: {main_policy_file}")
                return None
            
            with open(main_policy_file, 'r', encoding='utf-8') as f:
                policy_data = yaml.safe_load(f)
            
            policy_name = policy_data.get('name', os.path.basename(policy_dir))
            policy_props = policy_data.get('properties', {})
            
            # Find all RCG directories
            normalized_rcgs = []
            for item in os.listdir(policy_dir):
                item_path = os.path.join(policy_dir, item)
                if not os.path.isdir(item_path):
                    continue
                
                # Parse priority from folder name
                rcg_priority, rcg_name = CommonData.parse_priority_name(item)
                
                # Load RCG main.yaml
                rcg_main_file = os.path.join(item_path, 'main.yaml')
                if not os.path.exists(rcg_main_file):
                    logging.warning(f"RCG main.yaml not found: {rcg_main_file}")
                    continue
                
                with open(rcg_main_file, 'r', encoding='utf-8') as f:
                    rcg_data = yaml.safe_load(f)
                
                # Override priority if specified in YAML
                if 'priority' in rcg_data:
                    rcg_priority = rcg_data['priority']
                
                # Load all RC files
                normalized_rcs = []
                for rc_file in os.listdir(item_path):
                    if not rc_file.endswith('.yaml') or rc_file == 'main.yaml':
                        continue
                    
                    rc_file_path = os.path.join(item_path, rc_file)
                    rc_priority, rc_name = CommonData.parse_priority_name(os.path.splitext(rc_file)[0])
                    
                    with open(rc_file_path, 'r', encoding='utf-8') as f:
                        rc_data = yaml.safe_load(f)
                    
                    # Override priority if specified in YAML
                    if 'priority' in rc_data:
                        rc_priority = rc_data['priority']
                    
                    # Normalize rules using canonical format
                    normalized_rules = []
                    for rule in rc_data.get('rules', []):
                        normalized_rules.append(normalize_rule(rule))
                    
                    normalized_rcs.append({
                        'name': rc_name,
                        'priority': rc_priority,
                        'ruleCollectionType': rc_data.get('ruleCollectionType', ''),
                        'rules': normalized_rules
                    })
                
                normalized_rcgs.append({
                    'name': rcg_name,
                    'priority': rcg_priority,
                    'ruleCollections': normalized_rcs
                })
            
            return {
                'name': policy_name,
                'properties': policy_props,
                'ruleCollectionGroups': normalized_rcgs
            }
            
        except Exception as e:
            logging.error(f"Error loading policy from YAML {policy_dir}: {e}", exc_info=True)
            return None

    @staticmethod
    def compare_policies(local_policy, azure_policy):
        """
        Compare local vs Azure policies with identity-based matching.
        
        Matching strategy:
        - RCGs matched by actual_name (not priority-prefixed name)
        - RCs matched by actual_name within RCG
        - Rules matched by name within RC
        
        Args:
            local_policy (dict): Normalized local policy structure
            azure_policy (dict): Normalized Azure policy structure
            
        Returns:
            dict: Comparison results with added/deleted/modified items
        """
        if not local_policy or not azure_policy:
            return None
        
        result = {
            'policy_name': local_policy.get('name', 'Unknown'),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {'added': 0, 'modified': 0, 'deleted': 0},
            'rcg_added': [],
            'rcg_deleted': [],
            'rcg_modified': []
        }
        
        # Build RCG lookup dicts by actual name
        local_rcgs = {rcg['name']: rcg for rcg in local_policy.get('ruleCollectionGroups', [])}
        azure_rcgs = {rcg['name']: rcg for rcg in azure_policy.get('ruleCollectionGroups', [])}
        
        # Find added RCGs (in local but not in Azure - will be added when deployed)
        for rcg_name, rcg in local_rcgs.items():
            if rcg_name not in azure_rcgs:
                result['rcg_added'].append({
                    'name': rcg_name,
                    'priority': rcg.get('priority'),
                    'ruleCollections': len(rcg.get('ruleCollections', []))
                })
                result['summary']['added'] += 1
        
        # Find deleted RCGs (in Azure but not in local - will be deleted when deployed)
        for rcg_name, rcg in azure_rcgs.items():
            if rcg_name not in local_rcgs:
                result['rcg_deleted'].append({
                    'name': rcg_name,
                    'priority': rcg.get('priority'),
                    'ruleCollections': len(rcg.get('ruleCollections', []))
                })
                result['summary']['deleted'] += 1
        
        # Find modified RCGs (in both)
        for rcg_name in set(local_rcgs.keys()) & set(azure_rcgs.keys()):
            local_rcg = local_rcgs[rcg_name]
            azure_rcg = azure_rcgs[rcg_name]
            
            rcg_diff = {
                'name': rcg_name,
                'priority_changed': None,
                'rc_added': [],
                'rc_deleted': [],
                'rc_modified': []
            }
            
            # Check priority change
            local_priority = local_rcg.get('priority')
            azure_priority = azure_rcg.get('priority')
            if local_priority != azure_priority:
                rcg_diff['priority_changed'] = {
                    'from': azure_priority,
                    'to': local_priority
                }
            
            # Compare rule collections
            local_rcs = {rc['name']: rc for rc in local_rcg.get('ruleCollections', [])}
            azure_rcs = {rc['name']: rc for rc in azure_rcg.get('ruleCollections', [])}
            
            # Added RCs (in local but not in Azure)
            for rc_name in set(local_rcs.keys()) - set(azure_rcs.keys()):
                rc = local_rcs[rc_name]
                rcg_diff['rc_added'].append({
                    'name': rc_name,
                    'priority': rc.get('priority'),
                    'rules': len(rc.get('rules', []))
                })
            
            # Deleted RCs (in Azure but not in local)
            for rc_name in set(azure_rcs.keys()) - set(local_rcs.keys()):
                rc = azure_rcs[rc_name]
                rcg_diff['rc_deleted'].append({
                    'name': rc_name,
                    'priority': rc.get('priority'),
                    'rules': len(rc.get('rules', []))
                })
            
            # Modified RCs
            for rc_name in set(local_rcs.keys()) & set(azure_rcs.keys()):
                local_rc = local_rcs[rc_name]
                azure_rc = azure_rcs[rc_name]
                
                rc_diff = {
                    'name': rc_name,
                    'priority': local_rc.get('priority'),
                    'rule_changes': [],
                    'rules_added': [],
                    'rules_deleted': []
                }
                
                # Check priority change
                if local_rc.get('priority') != azure_rc.get('priority'):
                    rc_diff['priority_changed'] = {
                        'from': azure_rc.get('priority'),
                        'to': local_rc.get('priority')
                    }
                
                # Compare rules by name
                local_rules = {r['name']: r for r in local_rc.get('rules', [])}
                azure_rules = {r['name']: r for r in azure_rc.get('rules', [])}
                
                # Rules added (in local but not in Azure)
                for rule_name in set(local_rules.keys()) - set(azure_rules.keys()):
                    rc_diff['rules_added'].append(rule_name)
                
                # Rules deleted (in Azure but not in local)
                for rule_name in set(azure_rules.keys()) - set(local_rules.keys()):
                    rc_diff['rules_deleted'].append(rule_name)
                
                # Modified rules - compare field by field
                for rule_name in set(local_rules.keys()) & set(azure_rules.keys()):
                    local_rule = local_rules[rule_name]
                    azure_rule = azure_rules[rule_name]
                    
                    # Use field-by-field comparison
                    differences = compare_rules(azure_rule, local_rule)
                    
                    if differences:
                        for diff in differences:
                            rc_diff['rule_changes'].append({
                                'change_type': 'Modified',
                                'rule_name': rule_name,
                                'field': diff['field'],
                                'before': str(diff['azure_value']),
                                'after': str(diff['local_value'])
                            })
                
                # Only add to modified list if there are actual changes
                has_changes = (
                    rc_diff.get('priority_changed') or 
                    rc_diff['rule_changes'] or 
                    rc_diff['rules_added'] or 
                    rc_diff['rules_deleted']
                )
                if has_changes:
                    rcg_diff['rc_modified'].append(rc_diff)
            
            # Only add to modified if there are actual changes
            if (rcg_diff['priority_changed'] or rcg_diff['rc_added'] or 
                rcg_diff['rc_deleted'] or rcg_diff['rc_modified']):
                result['rcg_modified'].append(rcg_diff)
                result['summary']['modified'] += 1
        
        return result

    @staticmethod
    def generate_comparison_report(comparison_result, output_file):
        """
        Generate Markdown comparison report from comparison results.
        
        Args:
            comparison_result (dict): Result from compare_policies()
            output_file (str): Path to output MD file
            
        Returns:
            bool: True if successful
        """
        try:
            # Load Jinja template
            template_dir = Paths.TEMPLATES_DIR
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template('comparison.md.jinja2')
            
            # Render template
            content = template.render(**comparison_result)
            
            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logging.info(f"Comparison report saved to: {output_file}")
            return True
            
        except Exception as e:
            logging.error(f"Error generating comparison report: {e}", exc_info=True)
            return False


