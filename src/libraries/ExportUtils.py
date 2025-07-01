import os
import logging
from src.libraries.CommonUtils import get_id_with_date, clean_directory, render_jinja_template, remove_date_suffix
from src.libraries.BicepUtils import (
    collect_policy_data_from_yaml
)
from src.libraries.Parameters import Paths, Config

def validate_rule_types(policies):
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
                    
                    # Check for required fields based on rule type
                    if rule_type == "NetworkRule":
                        if not rule.get("IpProtocols"):
                            logging.warning(f"NetworkRule '{rule.get('RuleName')}' missing IpProtocols in {policy_key}/{rcg_name}/{rc_name}")
                            validation_passed = False
                            
                    elif rule_type == "NatRule":
                        if not rule.get("IpProtocols"):
                            logging.warning(f"NatRule '{rule.get('RuleName')}' missing IpProtocols in {policy_key}/{rcg_name}/{rc_name}")
                            validation_passed = False
                        
                    elif rule_type == "ApplicationRule":
                        if not rule.get("Protocols") and rule.get("RuleName") != "":
                            logging.warning(f"ApplicationRule '{rule.get('RuleName')}' missing Protocols in {policy_key}/{rcg_name}/{rc_name}")
                            validation_passed = False
                    
                    else:
                        logging.warning(f"Unknown rule type '{rule_type}' for rule '{rule.get('RuleName')}' in {policy_key}/{rcg_name}/{rc_name}")
                        validation_passed = False
    
    if not validation_passed:
        logging.error("Validation failed for rule types. Check warnings above.")
    
    return validation_passed

def export_policies(subscriptionid, ipgrouprg, policiesrg, firewallname, version=None, regionName=None, ipgroupssubscriptionid=None):
    """
    Export Azure Firewall policies from YAML structure to Bicep templates.
    
    Args:
        subscriptionid: Azure subscription ID
        ipgrouprg: Resource group for IP groups
        policiesrg: Resource group for policies
        firewallname: Name of the firewall
        version: Not used in new structure
        regionName: Azure region where the resources will be deployed
        ipgroupssubscriptionid: Subscription ID for IP groups (if different from policies)
        
    Returns:
        tuple: (success, generated_files) where success is a boolean and 
               generated_files is a dict with 'policies' key
    """
    # Ensure directories exist
    os.makedirs(Paths.POLICIES_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(Paths.TEMPLATE_POLICY_BICEP), exist_ok=True)
    os.makedirs(Paths.BICEP_DIR, exist_ok=True)
    
    generated_files = {
        'policies': []
    }
    
    # Get commit ID with date for policy name suffix
    commit_suffix = version
    
    logging.info(f"Using commit suffix for policy names: {commit_suffix}")
    
    # If regionName is not provided, use the default
    if not regionName:
        regionName = Config.DEFAULT_LOCATION
        logging.info(f"No region specified, using default: {regionName}")
    else:
        logging.info(f"Using region: {regionName}")
    
    # If ipgroupssubscriptionid is not provided, this will cause an error
    if not ipgroupssubscriptionid:
        logging.error("No IP groups subscription ID specified. This is a required parameter.")
        return False, generated_files
    else:
        logging.info(f"Using IP groups subscription ID: {ipgroupssubscriptionid}")
        
    # If ipgrouprg is not provided, this will cause an error
    if not ipgrouprg:
        logging.error("No IP groups resource group specified. This is a required parameter.")
        return False, generated_files
    else:
        logging.info(f"Using IP groups resource group: {ipgrouprg}")
    
    # Use the collect_policy_data_from_yaml function to process policies directly
    logging.info(f"Collecting policy data from YAML files in {Paths.POLICIES_DIR}...")
    
    policies = collect_policy_data_from_yaml(Paths.POLICIES_DIR, commit_suffix)
    
    if not policies:
        logging.error("No policies found in policies directory")
        return False, generated_files
    
    # Validate rule types and required fields
    if not validate_rule_types(policies):
        logging.warning("Rule type validation failed, but continuing with export")
    
    # Generate Bicep files for each policy
    logging.info(f"Generating Bicep files for {len(policies)} policies...")
    success = True
    policy_count = 0
    
    for policy_key, policy_data in policies.items():

        region_prefix = policy_key[:7]  # Extract the first 6 characters for region prefix
        
        # Check regionName to adjust original_name
        if "westeurope" in regionName and "EN" in region_prefix:
            policy_key = policy_key.replace("EN", "EW", 1)  # Replace only the first occurrence
        elif "northeurope" in regionName and "EW" in region_prefix:
            policy_key = policy_key.replace("EW", "EN", 1)  # Replace only the first occurrence
        elif "eastus" in regionName and "UW" in region_prefix:
            policy_key = policy_key.replace("UW", "UE", 1)  # Replace only the first occurrence
        elif "westus" in regionName and "UE" in region_prefix:
            policy_key = policy_key.replace("UE", "UW", 1)  # Replace only the first occurrence
        else:
            logging.info(f"No region match found for {regionName}, using original name.")
            
        # Extract original policy name without commit suffix to use for Bicep filename
        policy_bicep = remove_date_suffix(policy_key)

        # Use the policy name WITHOUT suffix for the Bicep file name
        bicep_file_name = f"{policy_bicep}.bicep"
        output_path = os.path.join(Paths.BICEP_DIR, bicep_file_name)
        
        # Render the template for the current policy
        if render_jinja_template(
            Paths.TEMPLATE_POLICY_BICEP,
            output_path,
            policies={policy_key: policy_data},
            subscriptionid=subscriptionid,
            ipgrouprg=ipgrouprg,
            ipgroupssubscriptionid=ipgroupssubscriptionid,
            policiesrg=policiesrg,
            regionName=regionName,
            api_version=Config.FIREWALL_API_VERSION
        ):
            generated_files['policies'].append(output_path)
            policy_count += 1
            logging.info(f"Generated Bicep file for policy: {bicep_file_name}")
        else:
            logging.error(f"Failed to generate Bicep file for policy: {policy_key}")
            success = False
    
    # Log summary of generated files
    logging.info(f"Export summary: Generated {len(generated_files['policies'])} Bicep files")
    
    return success, generated_files
