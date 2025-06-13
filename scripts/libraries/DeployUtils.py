import os
import logging
import time
import glob
from scripts.libraries.BicepUtils import deploy_policies, deploy_ipgroups
from scripts.libraries.Parameters import Paths

def deploy_resources(bicep_files, subscriptionid, ipgrouprg, policiesrg):
    """
    Deploy the specified Bicep resources to Azure.
    
    Args:
        bicep_files: Dictionary with 'policies' and 'ipgroups' keys containing file paths
        subscriptionid: Azure subscription ID
        ipgrouprg: Resource group for IP groups
        policiesrg: Resource group for policies
        
    Returns:
        bool: True if deployment was successful, False otherwise
    """
    ipgroup_files = bicep_files.get('ipgroups', [])
    policy_files = bicep_files.get('policies', [])
    
    if not ipgroup_files and not policy_files:
        logging.error("No files to deploy")
        return False
    
    deployment_success = True
    
    # Deploy IP Groups first
    if ipgroup_files:
        logging.info(f"Deploying {len(ipgroup_files)} IP group files...")
        ipgroups_success = deploy_ipgroups(ipgroup_files, subscriptionid, ipgrouprg)
        deployment_success = deployment_success and ipgroups_success
        
        if ipgroups_success:
            logging.info("IP groups deployment initiated successfully")
        else:
            logging.warning("IP groups deployment had issues")
        
        # # Wait for IP groups to be deployed
        # logging.info("Waiting 30 seconds for IP groups deployment to complete...")
        # time.sleep(30)
    
    # Deploy Bicep files for policies
    if policy_files:
        logging.info(f"Deploying {len(policy_files)} policy files...")
        policies_success = deploy_policies(policy_files, subscriptionid, policiesrg)
        deployment_success = deployment_success and policies_success
        
        if policies_success:
            logging.info("Policies deployment completed successfully")
        else:
            logging.warning("Policies deployment had issues")
    
    return deployment_success

def find_bicep_files():
    """
    Find all Bicep files in the bicep directory.
    
    Returns:
        dict: Dictionary with 'policies' and 'ipgroups' keys containing file paths
    """
    bicep_files = {
        'policies': [],
        'ipgroups': []
    }
    
    # Ensure bicep directory exists
    if not os.path.isdir(Paths.BICEP_DIR):
        logging.error(f"Bicep directory does not exist: {Paths.BICEP_DIR}")
        return bicep_files
    
    # Find all bicep files
    all_bicep_files = glob.glob(os.path.join(Paths.BICEP_DIR, "*.bicep"))
    
    # Separate IP groups and policies
    for file_path in all_bicep_files:
        file_name = os.path.basename(file_path)
        if "ipgroups" in file_name.lower():
            bicep_files['ipgroups'].append(file_path)
        else:
            bicep_files['policies'].append(file_path)
    
    return bicep_files

def select_bicep_files(bicep_files):
    """
    Allow user to select which Bicep files to deploy.
    
    Args:
        bicep_files: Dictionary with 'policies' and 'ipgroups' keys containing file paths
        
    Returns:
        dict: Dictionary with 'policies' and 'ipgroups' keys containing selected file paths
    """
    selected_files = {
        'policies': [],
        'ipgroups': []
    }
    
    # Process IP Groups
    if bicep_files['ipgroups']:
        print("\nAvailable IP Group files:")
        for i, file_path in enumerate(bicep_files['ipgroups']):
            print(f"{i+1}. {os.path.basename(file_path)}")
        
        deploy_all_ipgroups = input("\nDeploy all IP Group files? (y/n): ").lower() == 'y'
        
        if deploy_all_ipgroups:
            selected_files['ipgroups'] = bicep_files['ipgroups']
        else:
            selections = input("Enter the numbers of IP Group files to deploy (comma-separated, or 'none'): ")
            if selections.lower() != 'none':
                for selection in selections.split(','):
                    try:
                        index = int(selection.strip()) - 1
                        if 0 <= index < len(bicep_files['ipgroups']):
                            selected_files['ipgroups'].append(bicep_files['ipgroups'][index])
                    except ValueError:
                        pass
    else:
        logging.warning("No IP Group Bicep files found")
    
    # Process Policies
    if bicep_files['policies']:
        print("\nAvailable Policy files:")
        for i, file_path in enumerate(bicep_files['policies']):
            print(f"{i+1}. {os.path.basename(file_path)}")
        
        deploy_all_policies = input("\nDeploy all Policy files? (y/n): ").lower() == 'y'
        
        if deploy_all_policies:
            selected_files['policies'] = bicep_files['policies']
        else:
            selections = input("Enter the numbers of Policy files to deploy (comma-separated, or 'none'): ")
            if selections.lower() != 'none':
                for selection in selections.split(','):
                    try:
                        index = int(selection.strip()) - 1
                        if 0 <= index < len(bicep_files['policies']):
                            selected_files['policies'].append(bicep_files['policies'][index])
                    except ValueError:
                        pass
    else:
        logging.warning("No Policy Bicep files found")
    
    return selected_files