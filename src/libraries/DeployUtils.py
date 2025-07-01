import os
import logging
import time
import glob
import subprocess  # Add this import for subprocess.run
from src.libraries.Parameters import Paths
from src.libraries.CommonUtils import load_yaml_file, get_base_path, ensure_azure_login

def find_bicep_files(bicep_dir=Paths.BICEP_DIR):
    """
    Find all Bicep files in the bicep directory.
    
    Args:
        bicep_dir: Directory to search for Bicep files
        
    Returns:
        dict: Dictionary with 'policies' key containing file paths
    """
    bicep_files = {
        'policies': []
    }
    
    # Ensure bicep directory exists
    if not os.path.isdir(bicep_dir):
        logging.error(f"Bicep directory does not exist: {bicep_dir}")
        return bicep_files
    
    # Find all bicep files
    all_bicep_files = glob.glob(os.path.join(bicep_dir, "*.bicep"))
    
    # Include only policy files (exclude ipgroups)
    for file_path in all_bicep_files:
        file_name = os.path.basename(file_path)
        if "ipgroups" not in file_name.lower():
            bicep_files['policies'].append(file_path)
            logging.debug(f"Found policy Bicep file: {file_name}")
    
    return bicep_files

def select_bicep_files(bicep_files):
    """
    Allow user to select which Bicep files to deploy.
    
    Args:
        bicep_files: Dictionary with 'policies' key containing file paths
        
    Returns:
        dict: Dictionary with 'policies' key containing selected file paths
    """
    selected_files = {
        'policies': []
    }
    
    # Process Policies
    if bicep_files['policies']:
        print("\nAvailable Policy files:")
        for i, file_path in enumerate(bicep_files['policies']):
            print(f"{i+1}. {os.path.basename(file_path)}")
        
        deploy_all_policies = input("\nDeploy all Policy files? (y/n): ").lower() == 'y'
        
        if deploy_all_policies:
            selected_files['policies'] = bicep_files['policies']
            logging.info(f"Selected all {len(bicep_files['policies'])} policy files for deployment")
        else:
            # Allow selecting specific files
            selections = input("\nEnter the numbers of the Policy files to deploy (comma-separated): ")
            selection_indices = [int(s.strip()) - 1 for s in selections.split(',') if s.strip().isdigit()]
            
            for idx in selection_indices:
                if 0 <= idx < len(bicep_files['policies']):
                    selected_files['policies'].append(bicep_files['policies'][idx])
                    logging.info(f"Selected policy file: {os.path.basename(bicep_files['policies'][idx])}")
                else:
                    logging.warning(f"Invalid selection index: {idx+1}")
    else:
        logging.warning("No Policy Bicep files found")
    
    return selected_files

def deploy_bicep(bicep_file, subscriptionid, resource_group, tenant_id=None):
    """
    Deploy a Bicep file to Azure.
    
    Args:
        file: Path to the Bicep file
        subscriptionid: Azure subscription ID
        resource_group: Resource group to deploy to
        tenant_id: Azure tenant ID (optional)
        
    Returns:
        bool: True if deployment was successful, False otherwise
    """
    logging.info("Ensuring Azure authentication before deployment...")
    ensure_azure_login()
    
    if not os.path.exists(bicep_file):
        logging.error(f"Bicep file does not exist: {bicep_file}")
        return False

    try:
        # # First, perform Azure login with tenant if provided
        # if tenant_id:
        #     logging.info(f"Logging into Azure with tenant: {tenant_id}")
        #     login_cmd = f'az login --tenant {tenant_id}'
        #     login_command = ["powershell", "-Command", login_cmd]
            
        #     # Run the login command
        #     login_result = subprocess.run(login_command, shell=True, capture_output=True, text=True)
        #     if login_result.returncode != 0:
        #         logging.error(f"Failed to login to Azure: {login_result.stderr}")
        #         return False
            
        #     logging.info("Successfully logged into Azure")
        
        # Set the subscription context
        set_subscription_cmd = f'az account set --subscription {subscriptionid}'
        set_subscription_command = ["powershell", "-Command", set_subscription_cmd]
        
        # Run the set subscription command
        sub_result = subprocess.run(set_subscription_command, shell=True, capture_output=True, text=True)
        if sub_result.returncode != 0:
            logging.error(f"Failed to set subscription context: {sub_result.stderr}")
            return False
        
        # Build the deployment command
        cmd = (
            f'az deployment group create -g {resource_group} -o none '
            f'--subscription {subscriptionid} --template-file "{bicep_file}"'
        )
        
        # Pass the complete command to PowerShell
        command = ["powershell", "-Command", cmd]
        
        # Run the deployment command
        deploy_result = subprocess.run(command, shell=True, check=True)
        
        logging.info(f"Successfully deployed: {bicep_file}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to deploy {bicep_file}: {e}", exc_info=True)
        return False

def deploy_resources(bicep_files, subscriptionid, ipgrouprg, policiesrg, tenant_id=None):
    """
    Deploy the specified Bicep resources to Azure.
    
    Args:
        bicep_files: Dictionary with 'policies' key containing file paths
        subscriptionid: Azure subscription ID
        ipgrouprg: Resource group for IP groups (not used)
        policiesrg: Resource group for policies
        tenant_id: Azure tenant ID (optional)
        
    Returns:
        bool: True if deployment was successful, False otherwise
    """
    policy_files = bicep_files.get('policies', [])
    
    if not policy_files:
        logging.error("No policy files provided for deployment")
        return False
    
    deployment_success = True
    
    # Deploy Bicep files for policies
    if policy_files:
        logging.info(f"Deploying {len(policy_files)} policy Bicep files...")
        policy_success = deploy_policies(policy_files, subscriptionid, policiesrg, tenant_id)
        if not policy_success:
            logging.warning("Some policy deployments failed")
            deployment_success = False
    
    return deployment_success

def deploy_policies(files, subscriptionid, policiesrg, tenant_id=None):
    """
    Deploy multiple policy Bicep files to Azure.
    
    Args:
        files: List of Bicep file paths
        subscriptionid: Azure subscription ID
        policiesrg: Resource group to deploy to
        tenant_id: Azure tenant ID (optional)
        
    Returns:
        bool: True if all deployments were successful, False otherwise
    """
    all_success = True
    
    for file in files:
        if not deploy_bicep(file, subscriptionid, policiesrg, tenant_id):
            all_success = False
    
    return all_success

