"""
Assignment utilities for Azure Firewall Policy Manager.

This module provides the core functionality for assigning Azure Firewall policies
to Azure Firewalls.
"""
import copy
import glob
import json
import logging
import os
import subprocess
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.libraries.CommonUtils import CommonConfiguration, CommonData
from src.libraries.Parameters import Config, Paths

##########################################################################
# AzureCommon Class
##########################################################################

class AzureCommon:
    """Azure common utilities class."""
    
    @staticmethod
    def ensure_azure_login(subscription_id=None, tenant_id=None):
        """
        Ensure user is logged into Azure with the correct tenant and subscription.
        This function should be called before any Azure CLI operations.
        
        Args:
            subscription_id (str): Azure subscription ID
            tenant_id (str): Azure tenant ID (not required for managed identity mode)
        
        Returns:
            bool: True if login was successful, False otherwise
            
        Raises:
            ValueError: If subscription_id is not provided, or tenant_id is missing in interactive mode
        """
        from src.libraries.Parameters import Config
        
        # Validate subscription ID is always required
        if not subscription_id:
            error_msg = "No subscription ID provided. Cannot ensure Azure login."
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        try:
            # Managed Identity Mode (Azure Pipeline/Automation Account)
            if Config.USE_MANAGED_IDENTITY:
                logging.info("Running in managed identity mode (Azure Pipeline/Service Connection)")
                
                # Check if already authenticated (e.g., by AzureCLI@2 task)
                check_cmd = ["az", "account", "show"]
                result = subprocess.run(check_cmd, shell=Config.USE_SHELL_IN_SUBPROCESS, capture_output=True, text=True)
                
                if result.returncode == 0:
                    # Already authenticated - skip login
                    user_type_cmd = ["az", "account", "show", "--query", "user.type", "-o", "tsv"]
                    user_type_result = subprocess.run(user_type_cmd, shell=Config.USE_SHELL_IN_SUBPROCESS, capture_output=True, text=True)
                    user_type = user_type_result.stdout.strip() if user_type_result.returncode == 0 else "unknown"
                    
                    logging.info(f"Already authenticated with {user_type}, skipping login")
                else:
                    # Not authenticated - this should not happen in Azure Pipeline with AzureCLI@2 task
                    # but might happen in Azure Automation Account with managed identity
                    error_msg = "Running in managed identity mode but Azure CLI is not authenticated. " \
                               "Ensure the script runs inside an AzureCLI@2 task in Azure Pipeline, " \
                               "or use 'az login --identity' manually in Azure Automation Account."
                    logging.error(error_msg)
                    raise ValueError(error_msg)
            
            # Interactive Mode (Local Development)
            else:
                # Validate tenant_id is required for interactive mode
                if not tenant_id:
                    error_msg = "No tenant ID provided. Cannot ensure Azure login in interactive mode."
                    logging.error(error_msg)
                    raise ValueError(error_msg)
                
                # Check if already logged in with correct tenant
                check_cmd = ["az", "account", "show", "--query", "tenantId", "-o", "tsv"]
                result = subprocess.run(check_cmd, shell=Config.USE_SHELL_IN_SUBPROCESS, capture_output=True, text=True, check=True)
                
                if result.stdout.strip() != tenant_id:
                    # Login with specific tenant
                    login_cmd = ["az", "login", "--tenant", tenant_id]
                    logging.info(f"Logging in to Azure tenant {tenant_id}...")
                    subprocess.run(login_cmd, shell=Config.USE_SHELL_IN_SUBPROCESS, capture_output=True, text=True, check=True)
                    logging.info("Azure login completed")
                else:
                    # Get current user info
                    user_cmd = ["az", "account", "show", "--query", "user.name", "-o", "tsv"]
                    user_result = subprocess.run(user_cmd, shell=Config.USE_SHELL_IN_SUBPROCESS, capture_output=True, text=True, check=True)
                    current_user = user_result.stdout.strip() if user_result.returncode == 0 else "Unknown"
                    logging.info(f"Already logged in to Azure tenant {tenant_id} as {current_user}")
            
            # Set the active subscription (common for both modes)
            set_cmd = ["az", "account", "set", "--subscription", subscription_id]
            logging.info(f"Setting active subscription to: {subscription_id}")
            subprocess.run(set_cmd, shell=Config.USE_SHELL_IN_SUBPROCESS, capture_output=True, text=True, check=True)
            
            mode = "managed identity" if Config.USE_MANAGED_IDENTITY else f"tenant {tenant_id}"
            logging.info(f"Successfully authenticated with {mode} and set subscription {subscription_id}")
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to login to Azure: {e.stderr if e.stderr else str(e)}"
            logging.error(error_msg)
            raise ValueError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during Azure login: {str(e)}"
            logging.error(error_msg)
            raise ValueError(error_msg)
    
    @staticmethod
    def get_policies_in_resource_group(subscription_id, resource_group, tenant_id, resource_type="Microsoft.Network/firewallPolicies"):
        """
        List all Azure Firewall Policies in a resource group.
        
        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group name
            tenant_id: Optional Azure tenant ID. If provided, will be used for authentication.
            resource_type: Azure resource type to filter (default: "Microsoft.Network/firewallPolicies")
            
        Returns:
            list: List of policy dictionaries with name and ID
        """
        
        logging.info(f"Listing policies in resource group {resource_group}")
        
        # If tenant_id is provided, ensure Azure login first
        if tenant_id:
            try:
                AzureCommon.ensure_azure_login(subscription_id, tenant_id)
            except ValueError as e:
                logging.error(f"Azure login failed: {str(e)}")
                return []
        
        try:
            cmd = [
                "az", "resource", "list",
                "--subscription", subscription_id,
                "--resource-group", resource_group,
                "--resource-type", resource_type
            ]
            
            result = subprocess.run(cmd, shell=Config.USE_SHELL_IN_SUBPROCESS, capture_output=True, text=True, check=True)
            
            all_resources = json.loads(result.stdout)
            
            if not all_resources:
                logging.warning(f"No firewall policies found in resource group {resource_group}")
                return []
                
            # Extract just the name and ID
            resources = []
            for resource in all_resources:
                name = resource.get('name', '')
                if name:
                    resources.append({
                        'name': name,
                        'id': resource.get('id', ''),
                        'resourceGroup': resource_group,
                        'subscriptionId': subscription_id
                    })
                    
            return resources
        
        except subprocess.CalledProcessError as e:
            logging.error(f"Error listing policies: {e.stderr}")
            return []
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing Azure CLI output: {str(e)}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error listing policies: {str(e)}")
            return []

##########################################################################
# AzureAssign Class
##########################################################################

class AzureAssign:
    """Azure firewall assignment utilities class."""
    
    @staticmethod
    def get_firewalls_in_resource_group(subscription_id, resource_group, tenant_id):
        """
        Get all Azure Firewalls in a resource group.
        
        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group name
            tenant_id: Azure tenant ID
            
        Returns:
            list: List of firewall dictionaries with name and ID
        """
        logging.info(f"Getting Azure Firewalls in resource group {resource_group}")
        
        # Validate required parameters
        if not subscription_id:
            error_msg = "No subscription ID provided. Cannot list firewalls."
            logging.error(error_msg)
            return []
        
        if not tenant_id:
            error_msg = "No tenant ID provided. Cannot list firewalls."
            logging.error(error_msg)
            return []
        
        # Ensure Azure login before executing Azure CLI commands
        try:
            AzureCommon.ensure_azure_login(subscription_id, tenant_id)
        except ValueError as e:
            logging.error(f"Azure login failed: {str(e)}")
            return []
        
        try:
            command = [
                "az", "resource", "list",
                "--subscription", subscription_id,
                "--resource-group", resource_group,
                "--query", "[?type=='Microsoft.Network/azureFirewalls']"
            ]
            
            result = subprocess.run(command, shell=Config.USE_SHELL_IN_SUBPROCESS, capture_output=True, text=True, check=True, timeout=30)
            
            firewalls = json.loads(result.stdout)
            
            if not firewalls:
                logging.warning(f"No Azure Firewalls found in resource group {resource_group}")
                return []
                
            # Extract just the name and ID
            firewall_list = []
            for fw in firewalls:
                name = fw.get('name', '')
                if name:
                    firewall_list.append({
                        'name': name,
                        'id': fw.get('id', ''),
                        'resourceGroup': resource_group,
                        'subscriptionId': subscription_id
                    })
                    
            return firewall_list
        
        except subprocess.CalledProcessError as e:
            logging.error(f"Error getting Azure Firewalls: {e.stderr}")
            return []
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing Azure CLI output: {str(e)}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error getting Azure Firewalls: {str(e)}")
            return []

    @staticmethod
    def get_current_policy_assignment(subscription_id, resource_group, firewall_name, tenant_id):
        """
        Get the current policy assigned to an Azure Firewall.
        
        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group name containing the firewall
            firewall_name: Azure Firewall name to check for policy assignment
            tenant_id: Azure tenant ID
            
        Returns:
            dict: Policy information with name and ID, or None if no policy is assigned or firewall not found
        """
        logging.info(f"Getting current policy assignment for firewall {firewall_name}")
        
        # Validate required parameters
        if not subscription_id:
            error_msg = "No subscription ID provided. Cannot get policy assignment."
            logging.error(error_msg)
            return None
        
        if not tenant_id:
            error_msg = "No tenant ID provided. Cannot get policy assignment."
            logging.error(error_msg)
            return None
        
        # Verify Azure authentication before proceeding with CLI operations
        # This ensures the subsequent commands will execute with proper credentials
        try:
            AzureCommon.ensure_azure_login(subscription_id, tenant_id)
        except ValueError as e:
            logging.error(f"Azure login failed: {str(e)}")
            return None
        
        try:
            # Construct Azure CLI command to retrieve firewall details
            # We use 'az network firewall show' to get all properties of the specified firewall
            command = [
                "az", "network", "firewall", "show",
                "--subscription", subscription_id,
                "--resource-group", resource_group,
                "--name", firewall_name
            ]
            
            # Execute the command with output capture
            result = subprocess.run(command, shell=Config.USE_SHELL_IN_SUBPROCESS, capture_output=True, text=True, check=True)
            
            # Parse the JSON response from Azure CLI
            firewall = json.loads(result.stdout)
            
            # Handle case where firewall resource was not found
            if not firewall:
                logging.warning(f"Firewall {firewall_name} not found in resource group {resource_group}")
                return None
            
            # Extract the firewall policy object from the firewall properties
            # The firewallPolicy property contains the reference to any assigned policy
            firewall_policy = firewall.get('firewallPolicy', None)
            if not firewall_policy:
                logging.info(f"No policy currently assigned to firewall {firewall_name}")
                return None
                
            # Extract the policy ID and parse the policy name from the resource ID
            # The policy name is the last segment of the resource ID path
            policy_id = firewall_policy.get('id', '')
            policy_name = policy_id.split('/')[-1] if policy_id else ''
            
            # Return policy details if a name was successfully extracted
            if policy_name:
                return {
                    'name': policy_name,  # The policy's display name
                    'id': policy_id       # The full Azure resource ID of the policy
                }
            
            return None
        
        except subprocess.CalledProcessError as e:
            logging.error(f"Error getting firewall policy assignment: {e.stderr}")
            return None
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing Azure CLI output: {str(e)}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error getting firewall policy assignment: {str(e)}")
            return None

    @staticmethod
    def assign_policy_to_firewall(subscription_id, resource_group, firewall_name, policy_id, tenant_id):
        """
        Assign a policy to an Azure Firewall.
        
        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group name
            firewall_name: Azure Firewall name
            policy_id: Azure Firewall Policy ID
            tenant_id: Azure tenant ID
            
        Returns:
            bool: True if assignment was successful, False otherwise
        """
        logging.info(f"Assigning policy {policy_id} to firewall {firewall_name}")
        
        # Validate required parameters
        if not subscription_id:
            error_msg = "No subscription ID provided. Cannot assign policy."
            logging.error(error_msg)
            return False
        
        if not tenant_id:
            error_msg = "No tenant ID provided. Cannot assign policy."
            logging.error(error_msg)
            return False
        
        # Ensure Azure login before executing Azure CLI commands
        try:
            AzureCommon.ensure_azure_login(subscription_id, tenant_id)
        except ValueError as e:
            logging.error(f"Azure login failed: {str(e)}")
            return False
        
        try:
            command = [
                "az", "network", "firewall", "update",
                "--subscription", subscription_id,
                "--resource-group", resource_group,
                "--name", firewall_name,
                "--firewall-policy", policy_id
            ]
            
            result = subprocess.run(command, shell=Config.USE_SHELL_IN_SUBPROCESS, capture_output=True, text=True, check=True)
            
            # Verify the update was successful
            updated_firewall = json.loads(result.stdout)
            updated_policy_id = updated_firewall.get('firewallPolicy', {}).get('id', '')
            
            if updated_policy_id == policy_id:
                logging.info(f"Successfully assigned policy to firewall {firewall_name}")
                return True
            else:
                logging.error(f"Failed to assign policy to firewall {firewall_name}")
                return False
        
        except subprocess.CalledProcessError as e:
            logging.error(f"Error assigning policy to firewall: {e.stderr}")
            return False
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing Azure CLI output: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error assigning policy to firewall: {str(e)}")
            return False

##########################################################################
# AzureDeploy Class
##########################################################################

class AzureDeploy:
    """Azure deployment utilities class for Bicep resources."""
    
    @staticmethod
    def find_bicep_files(bicep_dir=Paths.BICEP_DIR):
        """
        Find all Bicep files in the bicep directory.
        
        Args:
            bicep_dir: Directory to search for Bicep files
            
        Returns:
            list: List containing file paths
        """
        bicep_files = []
        
        # Ensure bicep directory exists
        if not os.path.isdir(bicep_dir):
            logging.error(f"Bicep directory does not exist: {bicep_dir}")
            return bicep_files
        
        # Find all bicep files
        all_bicep_files = glob.glob(os.path.join(bicep_dir, "*.bicep"))
        
        # Process all bicep files
        for file_path in all_bicep_files:
            file_name = os.path.basename(file_path)
            bicep_files.append(file_path)
            logging.debug(f"Found Bicep file: {file_name}")
        
        return bicep_files

    @staticmethod
    def select_bicep_files(bicep_files):
        """
        Allow user to select which Bicep files to deploy and deployment mode.
        
        Args:
            bicep_files: List containing file paths
            
        Returns:
            tuple: (selected_files, parallel_mode)
                - selected_files: List of file paths to deploy
                - parallel_mode: True for parallel deployment, False for sequential with confirmation
        """
        if not bicep_files:
            logging.warning("No Bicep files found")
            return [], True
        
        # Show available files
        print("\nAvailable Bicep files:")
        for i, file_path in enumerate(bicep_files):
            print(f"  {i+1}. {os.path.basename(file_path)}")
        
        # Ask for deployment mode
        print("\nSelect deployment mode:")
        print("  1. Deploy all in parallel (default)")
        print("  2. Deploy one by one with confirmation")
        
        mode_input = input("Enter selection (1-2): ").strip()
        parallel_mode = mode_input != '2'
        
        logging.info(f"Selected {'parallel' if parallel_mode else 'sequential'} deployment mode")
        return bicep_files, parallel_mode

    @staticmethod
    def _validate_deployment_params(subscription_id, tenant_id, operation):
        """
        Validate required deployment parameters.
        
        Args:
            subscription_id: Azure subscription ID
            tenant_id: Azure tenant ID
            operation: Operation name for error messages
            
        Raises:
            ValueError: If required parameters are missing
        """
        if not subscription_id:
            error_msg = f"No subscription ID provided. Cannot run {operation}."
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        if not tenant_id:
            error_msg = f"No tenant ID provided. Cannot run {operation}."
            logging.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def _prepare_file_list(bicep_files, policiesrg, operation, whatif):
        """
        Prepare and validate the list of files to process.
        
        Args:
            bicep_files: Either a list of Bicep file paths or a single Bicep file path
            policiesrg: Resource group for deployment
            operation: Operation name for logging
            whatif: Whether this is a what-if operation
            
        Returns:
            tuple: (files_to_process, resource_group) or (None, None) on error
        """
        files_to_process = []
        
        # Validate resource group
        if not policiesrg:
            logging.error(f"Resource group is required for {operation}")
            return (None, None)
        
        # Normalize input to list
        if isinstance(bicep_files, str):
            files_to_process = [bicep_files]
        elif isinstance(bicep_files, list):
            files_to_process = bicep_files
            action = "Running what-if for" if whatif else "Deploying"
            logging.info(f"{action} {len(files_to_process)} Bicep files...")
        else:
            logging.error(f"Unsupported bicep_files type: {type(bicep_files)}")
            return (None, None)
        
        # Validate all files exist
        for file_path in files_to_process:
            if not os.path.exists(file_path):
                logging.error(f"Bicep file does not exist: {file_path}")
                return (None, None)
        
        return (files_to_process, policiesrg)

    @staticmethod
    def _build_deployment_command(file_path, deployment_name, resource_group, subscription_id, complete_mode, whatif):
        """
        Build the Azure CLI deployment command.
        
        Args:
            file_path: Path to Bicep file
            deployment_name: Name for the deployment
            resource_group: Target resource group
            subscription_id: Azure subscription ID
            complete_mode: Whether to use complete deployment mode
            whatif: Whether this is a what-if command
            
        Returns:
            list: Command arguments for subprocess
        """
        if whatif:
            return [
                "az", "deployment", "group", "what-if",
                "-g", resource_group,
                "-o", "table",
                "--subscription", subscription_id,
                "--template-file", file_path,
                "--name", deployment_name,
                "--exclude-change-types", "Ignore", "NoChange", "Unsupported"
            ]
        else:
            command = [
                "az", "deployment", "group", "create",
                "-g", resource_group,
                "-o", "json",
                "--subscription", subscription_id,
                "--template-file", file_path,
                "--name", deployment_name
            ]
            
            if complete_mode:
                command.extend(["--mode", "Complete"])
            
            return command

    @staticmethod
    def _save_whatif_output(result, file_name_without_ext, file_path):
        """
        Save what-if command output to comparison directory.
        
        Args:
            result: Subprocess result object
            file_name_without_ext: File name without extension
            file_path: Path to the Bicep file
        """
        comparison_dir = Paths.COMPARISON_DIR if hasattr(Paths, 'COMPARISON_DIR') else os.path.join(os.path.dirname(file_path), '..', 'comparison')
        os.makedirs(comparison_dir, exist_ok=True)
        output_txt_path = os.path.join(comparison_dir, f"{file_name_without_ext}.txt")
        with open(output_txt_path, 'w', encoding='utf-8') as f:
            f.write(result.stdout)

    @staticmethod
    def _handle_deployment_error(e, file_path, file_name, whatif):
        """
        Handle deployment or what-if errors.
        
        Args:
            e: Exception object
            file_path: Path to the Bicep file
            file_name: Name of the Bicep file
            whatif: Whether this is a what-if operation
            
        Returns:
            dict: Error details (None for what-if operations)
        """
        operation_verb = "what-if" if whatif else "deploy"
        error_message = f"Failed to {operation_verb} {file_path}: {e}"
        if hasattr(e, 'stderr') and e.stderr:
            error_message += f"\nError details: {e.stderr}"
        logging.error(error_message, exc_info=True)
        
        if not whatif:
            return {
                "file": file_name,
                "error": str(e),
                "stderr": e.stderr if hasattr(e, 'stderr') and e.stderr else "No detailed error information available"
            }
        return None

    @staticmethod
    def deploy_resources(bicep_files, subscription_id, tenant_id, git_id, policiesrg=None, complete_mode=False, whatif=False, parallel=True):
        """
        Deploy Bicep resources to Azure or run what-if analysis.
        
        Args:
            bicep_files: Either a list of Bicep file paths or a single Bicep file path
            subscription_id: Azure subscription ID
            tenant_id: Azure tenant ID
            git_id: Git commit ID for deployment naming
            policiesrg: Resource group for deployment
            complete_mode: If True, use complete deployment mode (default: False, ignored in whatif mode)
            whatif: If True, run what-if analysis instead of actual deployment (default: False)
            parallel: If True, deploy all files in parallel; False for sequential (default: True)
            
        Returns:
            For deployment: tuple (bool, list) - success status and error details
            For what-if: bool - True if all what-if operations were successful
            
        Raises:
            ValueError: If subscription_id or tenant_id is not provided
        """
        operation = "what-if" if whatif else "deployment"
        
        # Step 1: Validate required parameters
        AzureDeploy._validate_deployment_params(subscription_id, tenant_id, operation)
        
        # Step 2: Ensure Azure login
        try:
            AzureCommon.ensure_azure_login(subscription_id, tenant_id)
        except ValueError as e:
            logging.error(f"Azure login failed: {str(e)}")
            return False if whatif else (False, [])
        
        # Step 3: Prepare file list and validate
        files_to_process, resource_group = AzureDeploy._prepare_file_list(bicep_files, policiesrg, operation, whatif)
        if files_to_process is None:
            return False if whatif else (False, [])
        
        # Step 4: Deploy files
        if parallel:
            return AzureDeploy._deploy_parallel(files_to_process, resource_group, subscription_id, git_id, complete_mode, whatif)
        else:
            return AzureDeploy._deploy_sequential(files_to_process, resource_group, subscription_id, git_id, complete_mode, whatif)

    @staticmethod
    def _deploy_single_file(file_path, resource_group, subscription_id, git_id, complete_mode, whatif):
        """
        Deploy a single Bicep file.
        
        Args:
            file_path: Path to the Bicep file
            resource_group: Target resource group
            subscription_id: Azure subscription ID
            git_id: Git commit ID for deployment naming
            complete_mode: Whether to use complete deployment mode
            whatif: Whether this is a what-if operation
            
        Returns:
            tuple: (file_name, success, error_detail)
        """
        file_name = os.path.basename(file_path)
        file_name_without_ext = os.path.splitext(file_name)[0]
        deployment_name = f"{file_name_without_ext}_{git_id}"
        
        try:
            command = AzureDeploy._build_deployment_command(
                file_path, deployment_name, resource_group,
                subscription_id, complete_mode, whatif
            )
            
            operation_verb = "what-if" if whatif else "deployment"
            logging.info(f"Running {operation_verb}: {file_path}")
            
            if whatif:
                result = subprocess.run(
                    command,
                    shell=Config.USE_SHELL_IN_SUBPROCESS,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                AzureDeploy._save_whatif_output(result, file_name_without_ext, file_path)
            else:
                subprocess.run(command, shell=Config.USE_SHELL_IN_SUBPROCESS, check=True)
                logging.info(f"Successfully deployed: {file_path}")
            
            return file_name, True, None
            
        except subprocess.CalledProcessError as e:
            error_detail = AzureDeploy._handle_deployment_error(e, file_path, file_name, whatif)
            return file_name, False, error_detail

    @staticmethod
    def _deploy_parallel(files_to_process, resource_group, subscription_id, git_id, complete_mode, whatif):
        """Deploy files in parallel using ThreadPoolExecutor."""
        operation = "what-if" if whatif else "deployment"
        logging.info(f"Starting parallel {operation} for {len(files_to_process)} files")
        print(f"\n🚀 Starting parallel {operation}...")
        
        all_success = True
        error_details = []
        
        with ThreadPoolExecutor(max_workers=len(files_to_process)) as executor:
            futures = {
                executor.submit(
                    AzureDeploy._deploy_single_file,
                    f, resource_group, subscription_id, git_id, complete_mode, whatif
                ): f for f in files_to_process
            }
            
            for future in as_completed(futures):
                file_name, success, error_detail = future.result()
                
                if success:
                    print(f"  ✓ {file_name}: Success")
                else:
                    print(f"  ✗ {file_name}: Failed")
                    all_success = False
                    if error_detail:
                        error_details.append(error_detail)
        
        # Print summary
        AzureDeploy._print_deployment_summary(files_to_process, error_details)
        
        return all_success if whatif else (all_success, error_details)

    @staticmethod
    def _deploy_sequential(files_to_process, resource_group, subscription_id, git_id, complete_mode, whatif):
        """Deploy files sequentially with user confirmation for each file."""
        operation = "what-if" if whatif else "deployment"
        logging.info(f"Starting sequential {operation} with confirmation")
        
        all_success = True
        error_details = []
        skipped = []
        
        for file_path in files_to_process:
            file_name = os.path.basename(file_path)
            
            # Ask for confirmation
            confirm = input(f"\nDeploy {file_name}? (y/n): ").lower()
            
            if confirm != 'y':
                logging.info(f"Skipping: {file_name}")
                print(f"  ⏭ Skipped: {file_name}")
                skipped.append(file_name)
                continue
            
            file_name, success, error_detail = AzureDeploy._deploy_single_file(
                file_path, resource_group, subscription_id, git_id, complete_mode, whatif
            )
            
            if success:
                print(f"  ✓ {file_name}: Success")
            else:
                print(f"  ✗ {file_name}: Failed")
                all_success = False
                if error_detail:
                    error_details.append(error_detail)
        
        # Print summary
        AzureDeploy._print_deployment_summary(files_to_process, error_details, skipped)
        
        return all_success if whatif else (all_success, error_details)

    @staticmethod
    def _print_deployment_summary(files, error_details, skipped=None):
        """Print deployment summary."""
        skipped = skipped or []
        failed_count = len(error_details)
        skipped_count = len(skipped)
        success_count = len(files) - failed_count - skipped_count
        
        print("\n" + "=" * 50)
        print("📊 Deployment Summary")
        print("=" * 50)
        print(f"  ✓ Successful: {success_count}")
        print(f"  ✗ Failed: {failed_count}")
        if skipped_count > 0:
            print(f"  ⏭ Skipped: {skipped_count}")
        
        if error_details:
            print("\n❌ Failed deployments:")
            for err in error_details:
                print(f"  - {err['file']}: {err['error']}")

    @staticmethod
    def deploy_resources_parallel_all(deployment_jobs, git_id, complete_mode=False, whatif=False):
        """
        Deploy all Bicep files across all firewalls in parallel.
        
        Args:
            deployment_jobs: List of dicts containing:
                - file: Bicep file path
                - firewall_name: Name of the firewall
                - subscription_id: Azure subscription ID
                - tenant_id: Azure tenant ID
                - resource_group: Resource group name
            git_id: Git commit ID or deployment identifier
            complete_mode: Whether to use complete deployment mode
            whatif: Whether to run what-if analysis instead of actual deployment
        
        Returns:
            bool if whatif=True, tuple(bool, list) if whatif=False
            - bool: True if all deployments succeeded
            - list: List of error details for failed deployments
        """
        if not deployment_jobs:
            logging.warning("No deployment jobs provided")
            return True if whatif else (True, [])
        
        operation_verb = "analyze" if whatif else "deploy"
        logging.info(f"Starting parallel {operation_verb} for {len(deployment_jobs)} file(s) across all firewalls")
        
        # Group jobs by tenant/subscription for authentication
        auth_cache = {}
        
        def deploy_job(job):
            """Deploy a single job (file + metadata)"""
            file_path = job['file']
            firewall_name = job['firewall_name']
            subscription_id = job['subscription_id']
            tenant_id = job['tenant_id']
            resource_group = job['resource_group']
            
            # Authenticate once per tenant/subscription combination
            auth_key = f"{tenant_id}_{subscription_id}"
            if auth_key not in auth_cache:
                try:
                    AzureCommon.ensure_azure_login(subscription_id, tenant_id)
                    auth_cache[auth_key] = True
                except Exception as e:
                    logging.error(f"Failed to authenticate for {firewall_name}: {str(e)}")
                    return (os.path.basename(file_path), False, {
                        'file': os.path.basename(file_path),
                        'firewall': firewall_name,
                        'error': f"Authentication failed: {str(e)}",
                        'stderr': 'Authentication error'
                    })
            
            # Deploy the file
            file_name, success, error_detail = AzureDeploy._deploy_single_file(
                file_path, resource_group, subscription_id, git_id, complete_mode, whatif
            )
            
            # Add firewall name to result for better error reporting
            if error_detail:
                error_detail['firewall'] = firewall_name
            
            return (file_name, success, error_detail)
        
        # Execute all deployments in parallel
        print("\n🚀 Starting parallel deployment across all firewalls...")
        all_success = True
        error_details = []
        
        with ThreadPoolExecutor(max_workers=len(deployment_jobs)) as executor:
            future_to_job = {executor.submit(deploy_job, job): job for job in deployment_jobs}
            
            for future in as_completed(future_to_job):
                job = future_to_job[future]
                try:
                    file_name, success, error_detail = future.result()
                    
                    if success:
                        print(f"  ✓ {file_name} ({job['firewall_name']}): Success")
                    else:
                        print(f"  ✗ {file_name} ({job['firewall_name']}): Failed")
                        all_success = False
                        if error_detail:
                            error_details.append(error_detail)
                
                except Exception as e:
                    file_name = os.path.basename(job['file'])
                    firewall_name = job['firewall_name']
                    logging.error(f"Exception during deployment of {file_name} for {firewall_name}: {str(e)}")
                    print(f"  ✗ {file_name} ({firewall_name}): Exception")
                    all_success = False
                    error_details.append({
                        'file': file_name,
                        'firewall': firewall_name,
                        'error': f"Exception: {str(e)}",
                        'stderr': 'Unexpected error'
                    })
        
        # Print summary
        print("\n" + "=" * 50)
        print("📊 Deployment Summary (All Firewalls)")
        print("=" * 50)
        
        successful = len(deployment_jobs) - len(error_details)
        print(f"  ✓ Successful: {successful}")
        print(f"  ✗ Failed: {len(error_details)}")
        
        if error_details:
            print("\n❌ Failed deployments:")
            for error in error_details:
                firewall = error.get('firewall', 'Unknown')
                file = error.get('file', 'Unknown')
                error_msg = error.get('error', 'Unknown error')
                print(f"  - [{firewall}] {file}: {error_msg}")
        
        return all_success if whatif else (all_success, error_details)

##########################################################################
# AzureDownload Class
##########################################################################

class AzureDownload:
    """Azure ARM template download utilities class."""
    
    # Helper methods (private)
    
    @staticmethod
    def _replace_resource_policy_name(policy_json, original_name, new_name):
        """
        Replace policy name in the resources section of the ARM JSON template.
        
        Args:
            policy_json: Loaded JSON template
            original_name: Original policy name
            new_name: New policy name to use
            
        Returns:
            dict: Updated JSON template
        """
        if not policy_json or not isinstance(policy_json, dict):
            return policy_json
        
        # Create a deep copy to avoid modifying the original
        result_json = copy.deepcopy(policy_json)
        
        # Update resources section
        if 'resources' in result_json:
            for resource in result_json['resources']:
                if resource.get('type') == 'Microsoft.Network/firewallPolicies':
                    if resource.get('name') == original_name:
                        resource['name'] = new_name
                        logging.info(f"Changed policy name from {original_name} to {new_name}")
        
        return result_json

    @staticmethod
    def _export_policy_template(subscription_id, resource_group, policy_id):
        """
        Export a policy to an ARM template.
        
        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group name
            policy_id: Policy resource ID
            
        Returns:
            dict: ARM template JSON or None on error
        """
        try:
            export_cmd = [
                "az", "group", "export",
                "--subscription", subscription_id,
                "--resource-group", resource_group,
                "--resource-ids", policy_id,
                "--skip-all-params",
                "--output", "json"
            ]
            
            result = subprocess.run(
                export_cmd, 
                shell=Config.USE_SHELL_IN_SUBPROCESS, 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            return json.loads(result.stdout)
            
        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing Azure CLI export command: {e.stderr}")
            return None
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing Azure CLI export output: {e}")
            return None

    @staticmethod
    def _find_exact_policy(subscription_id, resource_group, policy_name):
        """
        Find a policy with exact name match in resource group.
        
        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group name
            policy_name: Exact policy name to find
            
        Returns:
            str: Policy resource ID if found, None otherwise
        """
        try:
            find_cmd = [
                "az", "resource", "show",
                "--subscription", subscription_id,
                "--resource-group", resource_group,
                "--resource-type", "Microsoft.Network/firewallPolicies",
                "--name", policy_name,
                "--query", "id",
                "-o", "tsv"
            ]
            
            result = subprocess.run(
                find_cmd, 
                shell=Config.USE_SHELL_IN_SUBPROCESS, 
                capture_output=True, 
                text=True, 
                check=False  # Don't raise on error
            )
            
            if result.returncode == 0 and result.stdout.strip():
                policy_id = result.stdout.strip()
                logging.info(f"Found exact policy match: {policy_name}")
                return policy_id
            
            return None
            
        except Exception as e:
            logging.warning(f"Error searching for exact policy {policy_name}: {e}")
            return None

    @staticmethod
    def _get_firewall_assigned_policy(subscription_id, resource_group, firewall_name):
        """
        Get the policy currently assigned to a firewall.
        
        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group name containing the firewall
            firewall_name: Firewall name
            
        Returns:
            tuple: (policy_id, policy_name, policy_resource_group) or (None, None, None) if not found
        """
        try:
            show_cmd = [
                "az", "network", "firewall", "show",
                "--subscription", subscription_id,
                "--resource-group", resource_group,
                "--name", firewall_name,
                "-o", "json"
            ]
            
            result = subprocess.run(
                show_cmd, 
                shell=Config.USE_SHELL_IN_SUBPROCESS, 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            fw_json = json.loads(result.stdout)
            policy_id = fw_json.get('firewallPolicy', {}).get('id')
            
            if not policy_id:
                logging.info(f"No policy assigned to firewall {firewall_name}")
                return None, None, None
            
            # Parse policy information from resource ID
            parts = policy_id.split('/')
            policy_name = parts[-1]
            policy_rg = parts[parts.index('resourceGroups') + 1]
            
            logging.info(f"Firewall {firewall_name} uses policy {policy_name} in resource group {policy_rg}")
            return policy_id, policy_name, policy_rg
            
        except subprocess.CalledProcessError as e:
            logging.warning(f"Error getting firewall policy assignment: {e.stderr}")
            return None, None, None
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logging.warning(f"Error parsing firewall policy information: {e}")
            return None, None, None
        except Exception as e:
            logging.warning(f"Unexpected error getting firewall policy: {e}")
            return None, None, None

    @staticmethod
    def _find_latest_policy_by_base_name(subscription_id, resource_group, base_name):
        """
        Find the latest policy with matching base name (sorted by creation time).
        
        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group name
            base_name: Base name to match (without date suffix)
            
        Returns:
            tuple: (policy_id, policy_name) or (None, None) if not found
        """
        try:
            # Find latest policy with matching base name
            find_cmd = [
                "az", "resource", "list",
                "--subscription", subscription_id,
                "--resource-group", resource_group,
                "--resource-type", "Microsoft.Network/firewallPolicies",
                "--query", f"[?contains(name, '{base_name}')] | sort_by(@, &createdTime)[-1].[id, name]",
                "-o", "tsv"
            ]
            
            logging.info(f"Step 3: Executing command: {' '.join(find_cmd)}")
            
            result = subprocess.run(
                find_cmd, 
                shell=Config.USE_SHELL_IN_SUBPROCESS, 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            output = result.stdout.strip()
            logging.info(f"Step 3: Command output: '{output}'")
            logging.info(f"Step 3: Command stderr: '{result.stderr}'")
            
            if not output:
                logging.warning(f"No policy found with base name '{base_name}' in resource group {resource_group}")
                return None, None
            
            # Parse output (can be tab-separated or newline-separated: id, name)
            # Try tab first, then newline
            if '\t' in output:
                parts = output.split('\t')
            else:
                parts = output.split('\n')
            
            logging.info(f"Step 3: Parsed parts: {parts} (count: {len(parts)})")
            
            if len(parts) >= 2:
                policy_id = parts[0].strip()
                policy_name = parts[1].strip()
                logging.info(f"Found latest policy for base name '{base_name}': {policy_name}")
                return policy_id, policy_name
            
            logging.warning(f"Step 3: Unexpected output format. Expected 2 parts (id, name), got {len(parts)}")
            return None, None
            
        except subprocess.CalledProcessError as e:
            logging.error(f"Error searching for latest policy with base name {base_name}: {e.stderr}")
            logging.error(f"Command exit code: {e.returncode}")
            logging.exception("Full exception details:")
            return None, None
        except Exception as e:
            logging.error(f"Unexpected error searching for latest policy: {e}")
            logging.exception("Full exception details:")
            return None, None

    @staticmethod
    def _resolve_policy_to_download(subscription_id, firewall_subscription_id, policies_resource_group, policy_name, firewall_name, firewall_resource_group):
        """
        Resolve which policy to download using fallback logic.
        
        Args:
            subscription_id: Azure subscription ID for policies
            firewall_subscription_id: Azure subscription ID for firewall
            policies_resource_group: Resource group for policies
            policy_name: Policy name from configuration
            firewall_name: Firewall name
            firewall_resource_group: Resource group containing the firewall
            
        Returns:
            tuple: (policy_id, actual_policy_name, policy_resource_group, base_name) or (None, None, None, None) if not found
        """
        # Get base name (without date suffix)
        base_name, _ = CommonData.separate_name_suffix(policy_name, with_date=False)
        logging.info(f"Processing policy: {policy_name} (base name: {base_name})")
        
        # Step 1: Try exact name match in policies resource group
        logging.info(f"Step 1: Looking for exact policy match '{policy_name}' in {policies_resource_group}")
        policy_id = AzureDownload._find_exact_policy(subscription_id, policies_resource_group, policy_name)
        if policy_id:
            logging.info(f"✓ Found exact policy match: {policy_name}")
            return policy_id, policy_name, policies_resource_group, base_name
        
        # Step 2: Try to get policy assigned to firewall
        logging.info(f"Step 2: Getting policy assigned to firewall '{firewall_name}'")
        policy_id, assigned_policy_name, assigned_policy_rg = AzureDownload._get_firewall_assigned_policy(
            firewall_subscription_id, firewall_resource_group, firewall_name
        )
        if policy_id and assigned_policy_name:
            # Check if the assigned policy matches our base name
            assigned_base_name, _ = CommonData.separate_name_suffix(assigned_policy_name, with_date=False)
            if assigned_base_name == base_name:
                logging.info(f"✓ Found matching policy assigned to firewall: {assigned_policy_name}")
                return policy_id, assigned_policy_name, assigned_policy_rg, base_name
            else:
                logging.warning(f"Firewall has policy {assigned_policy_name} (base: {assigned_base_name}), but we need {base_name}")
        
        # Step 3: Try to find latest policy with matching base name
        logging.info(f"Step 3: Looking for latest policy with base name '{base_name}' in {policies_resource_group}")
        policy_id, latest_policy_name = AzureDownload._find_latest_policy_by_base_name(
            subscription_id, policies_resource_group, base_name
        )
        if policy_id and latest_policy_name:
            logging.info(f"✓ Found latest policy with matching base name: {latest_policy_name}")
            return policy_id, latest_policy_name, policies_resource_group, base_name
        
        # All attempts failed
        logging.error(f"✗ Could not find any policy matching '{policy_name}' (base: {base_name})")
        return None, None, None, None

    @staticmethod
    def _download_single_policy(subscription_id, firewall_subscription_id, policies_resource_group, policy_name, 
                                firewall_name, firewall_resource_group, output_dir):
        """
        Download a single policy ARM template.
        
        Args:
            subscription_id: Azure subscription ID for policies
            firewall_subscription_id: Azure subscription ID for firewall
            policies_resource_group: Resource group for policies
            policy_name: Policy name from configuration
            firewall_name: Firewall name
            firewall_resource_group: Resource group containing the firewall
            output_dir: Directory to save the ARM template
            
        Returns:
            tuple: (success, policy_name, message) where success is boolean
        """
        try:
            # Resolve which policy to download (with fallback logic)
            policy_id, actual_policy_name, policy_rg, base_name = AzureDownload._resolve_policy_to_download(
                subscription_id,
                firewall_subscription_id,
                policies_resource_group, 
                policy_name,
                firewall_name,
                firewall_resource_group
            )
            
            if not policy_id:
                error_msg = f"Failed to resolve policy: {policy_name}"
                logging.error(error_msg)
                return False, policy_name, error_msg
            
            # Export the policy to ARM template
            logging.info(f"Exporting ARM template for policy: {actual_policy_name}")
            template_json = AzureDownload._export_policy_template(
                subscription_id, 
                policy_rg, 
                policy_id
            )
            
            if not template_json:
                error_msg = f"Failed to export ARM template for policy: {actual_policy_name}"
                logging.error(error_msg)
                return False, policy_name, error_msg
            
            # Replace policy name with base name in template
            template_json = AzureDownload._replace_resource_policy_name(
                template_json, 
                actual_policy_name, 
                base_name
            )
            
            # Save template to file
            output_file = os.path.join(output_dir, f"{base_name}.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(template_json, f, indent=2)
            
            success_msg = f"Successfully downloaded ARM template: {base_name}.json (from {actual_policy_name})"
            logging.info(f"✓ {success_msg}")
            return True, policy_name, success_msg
            
        except Exception as e:
            error_msg = f"Unexpected error processing policy {policy_name}: {e}"
            logging.error(error_msg, exc_info=True)
            return False, policy_name, error_msg

    # Public methods
    
    @staticmethod
    def download_arm_template(environment_name=None):
        """
        Download ARM templates for firewall policies in the production environment.
        
        This function uses a fallback strategy to find and download policies:
        1. Try exact policy name match in policies resource group
        2. If not found, get policy assigned to the firewall
        3. If still not found, get latest policy with matching base name
        
        Policies are downloaded in parallel using ThreadPoolExecutor for better performance.
        
        Args:
            environment_name: Name of the environment (string)
            
        Returns:
            tuple: (success, message) - success is boolean, message provides operation info
        """
        # Step 1: Get production firewall environment
        logging.info(f"Getting production firewall configuration for environment: {environment_name}")
        required_fields = ['policiesSubscriptionId', 'firewallSubscriptionId', 'tenantId', 'policiesResourceGroup', 'policiesName', 'firewallName', 'firewallResourceGroup']
        
        fw, error_msg = CommonConfiguration.get_environment(
            environment_name=environment_name,
            regiontype="Prod",
            prod_firewall=True,
            required_fields=required_fields
        )
        
        if not fw:
            return False, error_msg
        
        # Step 2: Extract required configuration
        subscription_id = fw["policiesSubscriptionId"]
        firewall_subscription_id = fw["firewallSubscriptionId"]
        tenant_id = fw["tenantId"]
        policies_resource_group = fw["policiesResourceGroup"]
        policies_name_raw = fw["policiesName"]
        firewall_name = fw["firewallName"]
        firewall_resource_group = fw["firewallResourceGroup"]
        
        # Convert to list if it's a dict with integer keys
        if isinstance(policies_name_raw, dict):
            policies_name_list = [policies_name_raw[k] for k in sorted(policies_name_raw.keys())]
        else:
            policies_name_list = policies_name_raw
        
        logging.info(f"Processing production firewall: {firewall_name}")
        logging.info(f"Policies resource group: {policies_resource_group}")
        logging.info(f"Policies to download: {', '.join(policies_name_list)}")
        
        # Ensure output directory exists
        os.makedirs(Paths.ARM_DIR, exist_ok=True)
        
        # Step 3: Ensure Azure authentication
        logging.info("Ensuring Azure authentication...")
        try:
            AzureCommon.ensure_azure_login(subscription_id, tenant_id)
        except ValueError as e:
            error_msg = f"Failed to authenticate with Azure: {str(e)}"
            logging.error(error_msg)
            return False, error_msg
        
        # Step 4: Download policies in parallel
        success_count = 0
        failed_policies = []
        
        # Limit workers to avoid overwhelming Azure API
        max_workers = min(10, len(policies_name_list))
        
        logging.info(f"Downloading {len(policies_name_list)} policies using {max_workers} parallel workers...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all download tasks
            futures = {
                executor.submit(
                    AzureDownload._download_single_policy,
                    subscription_id,
                    firewall_subscription_id,
                    policies_resource_group,
                    policy_name,
                    firewall_name,
                    firewall_resource_group,
                    Paths.ARM_DIR
                ): policy_name
                for policy_name in policies_name_list
            }
            
            # Process completed downloads
            for future in as_completed(futures):
                policy_name = futures[future]
                try:
                    success, returned_policy_name, message = future.result()
                    if success:
                        success_count += 1
                    else:
                        failed_policies.append(returned_policy_name)
                except Exception as e:
                    logging.error(f"Exception downloading policy {policy_name}: {e}", exc_info=True)
                    failed_policies.append(policy_name)
        
        # Step 5: Return results
        total_policies = len(policies_name_list)
        
        if success_count == 0:
            return False, f"Failed to download any ARM templates for environment {environment_name}"
        elif success_count == total_policies:
            return True, f"Successfully downloaded {success_count}/{total_policies} ARM templates for environment {environment_name}"
        else:
            failed_list = ', '.join(failed_policies)
            return False, f"Partially successful: downloaded {success_count}/{total_policies} ARM templates. Failed: {failed_list}"

