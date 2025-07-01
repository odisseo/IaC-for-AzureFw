"""
Orchestrator utilities for Azure Firewall Policy Manager.

This module provides the core functionality for managing Azure Firewall policies,
including importing, exporting, synchronizing, and deploying policies.
"""
import os
import logging
import sys
import copy
from src.libraries.CommonUtils import (
    clean_directory, 
    commit_changes_to_git, 
    pull_changes_from_git, 
    get_id_with_date,
    remove_date_suffix
)
from src.libraries.ImportUtils import import_policies, download_latest_arm_template
from src.libraries.ExportUtils import export_policies
from src.libraries.DeployUtils import deploy_resources, find_bicep_files, select_bicep_files
from src.libraries.Parameters import (
    get_environment_list, 
    Paths, 
    FIREWALL_DATA, 
    get_firewalls_by_key, 
    get_environment_from_cmdline, 
    list_available_environments,
    parse_arguments
)
from src.libraries.SyncUtils import compare_policy_files, update_sync_lock, has_user_changes, calculate_content_hash
from src.libraries.YamlUtils import create_yaml_from_policies, process_csv_file as yaml_process_csv_file
from src.libraries.CsvUtils import csv_collect_policy_data, csv_render_csv

def print_header():
    """Print the header for the application."""
    print("\n" + "=" * 80)
    print(" " * 25 + "AZURE FIREWALL POLICY MANAGER")
    print("=" * 80)
    print("\nThis tool helps manage Azure Firewall Policies through multiple formats:")
    print(" - Import from ARM templates to YAML structure")
    print(" - Export from YAML structure to Bicep")
    print(" - Synchronize between formats")
    print(" - Deploy Bicep templates to Azure")
    print("=" * 80 + "\n")

def sync_policies_workflow():
    """
    Execute the workflow for synchronizing policies between _csv and _policies folders.
    
    This function:
    1. Checks if sync is required by comparing content hashes and timestamps
    2. Determines which folder has been modified by a user
    3. If _policies is modified, exports YAML to CSV
    4. If _csv is modified, exports CSV to YAML
    
    Returns:
        bool: True if sync was successful, False otherwise
    """
    logging.info("Starting policy synchronization...")
    
    # Check if the folders exist
    if not os.path.isdir(Paths.POLICIES_DIR):
        os.makedirs(Paths.POLICIES_DIR, exist_ok=True)
        logging.info(f"Created policies directory: {Paths.POLICIES_DIR}")
    
    if not os.path.isdir(Paths.CSV_DIR):
        os.makedirs(Paths.CSV_DIR, exist_ok=True)
        logging.info(f"Created CSV directory: {Paths.CSV_DIR}")
    
    # Get comparison result once and reuse it
    result = compare_policy_files()
    
    # Check if sync is required based on the result
    if result == "SAME" or result == "NO_FILES":
        logging.info("No synchronization required. Folders are already in sync.")
        return True

    if result == "CONFLICT":
        logging.warning("Both directories have been modified - checking resolution method")
        
        # Check if we're running in non-interactive mode with conflict resolution parameter
        args = parse_arguments()
        
        if args.non_interactive and args.conflict_resolution:
            logging.info(f"Using non-interactive conflict resolution: {args.conflict_resolution}")
            if args.conflict_resolution.lower() == "policies":
                result = "POLICIES"
            elif args.conflict_resolution.lower() == "csv":
                result = "CSV"
            else:  # "cancel" or any other value
                logging.info("Sync operation cancelled by conflict resolution parameter")
                return False
        else:
            # Interactive conflict resolution
            print("\nWARNING: Both _policies and _csv directories have been modified.")
            print("Please manually resolve conflicts by deciding which version to keep.")
            print("Options:")
            print("1. Use policy files as source of truth")
            print("2. Use CSV files as source of truth")
            print("3. Cancel sync operation")
            
            choice = input("\nEnter your choice (1-3): ")
            if choice == "1":
                result = "POLICIES"
            elif choice == "2":
                result = "CSV"
            else:
                logging.info("Sync operation cancelled by user")
                return False
    
    # Process based on which folder has more recent files
    if result == "POLICIES":
        logging.info("Policies folder has more recent data. Exporting from YAML to CSV...")
        
        # Clean the _csv directory
        clean_directory(Paths.CSV_DIR)
        logging.info(f"Cleaned CSV directory: {Paths.CSV_DIR}")
        
        # Create CSV destination files
        csv_network_path = os.path.join(Paths.CSV_DIR, "csv_network.csv")
        csv_nat_path = os.path.join(Paths.CSV_DIR, "csv_nat.csv")
        csv_application_path = os.path.join(Paths.CSV_DIR, "csv_application.csv")
        
        try:
            # Collect policy data from the policies directory
            nat_rules, network_rules, application_rules = csv_collect_policy_data(Paths.POLICIES_DIR)
            
            # Generate CSV files
            if nat_rules:
                csv_render_csv(nat_rules, csv_nat_path, "NatRule")
                logging.info(f"Generated NAT rules CSV: {csv_nat_path}")

            if network_rules:
                csv_render_csv(network_rules, csv_network_path, "NetworkRule")
                logging.info(f"Generated Network rules CSV: {csv_network_path}")

            if application_rules:
                csv_render_csv(application_rules, csv_application_path, "ApplicationRule")
                logging.info(f"Generated Application rules CSV: {csv_application_path}")
            
            # Update sync lock after successful sync
            update_sync_lock("POLICIES")
            
            logging.info("Successfully exported policies to CSV")
            return True
                
        except Exception as e:
            logging.error(f"Error exporting policies to CSV: {e}", exc_info=True)
            return False
            
    elif result == "CSV":
        logging.info("CSV folder has more recent data. Exporting from CSV to YAML...")
        
        # Clean the _policies directory
        clean_directory(Paths.POLICIES_DIR)
        logging.info(f"Cleaned policies directory: {Paths.POLICIES_DIR}")
        
        try:
            # Dictionary to track policy info
            policies = {}
            
            # Process all CSV files in the directory
            csv_files = [f for f in os.listdir(Paths.CSV_DIR) if f.endswith('.csv')]
            for csv_file in csv_files:
                csv_path = os.path.join(Paths.CSV_DIR, csv_file)
                
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
                    yaml_process_csv_file(csv_path, rule_type, policies)
                else:
                    logging.warning(f"Could not determine rule type for CSV file: {csv_file}")
            
            # Create policy structure and YAML files
            create_yaml_from_policies(policies, Paths.POLICIES_DIR)
            
            # Update sync lock after successful sync
            update_sync_lock("CSV")
            
            logging.info("Successfully exported CSV to YAML")
            return True
            
        except Exception as e:
            logging.error(f"Error exporting CSV to YAML: {e}", exc_info=True)
            return False
    
    # If we reach here, something unexpected happened
    logging.warning("Unexpected state in sync workflow")
    return False

def import_policies_workflow(firewall_key=None):
    """
    Execute the workflow for importing policies.
    
    Args:
        firewall_key: Optional firewall key to use for the import
        
    Returns:
        bool: True if the import was successful, False otherwise
    """
    logging.info(f"Starting policy import operation{' for ' + firewall_key if firewall_key else ''}...")
    
    success, message = import_policies(firewall_key)
    
    if success:
        logging.info(f"Policy import completed successfully. {message}")
        return True
    else:
        logging.error(f"Policy import failed. {message}")
        return False

def handle_git_operations(skip_git, non_interactive, commit_message_prefix):
    """
    Handle Git operations for the repository.
    
    Args:
        skip_git: Whether to skip Git operations
        non_interactive: Whether to run in non-interactive mode
        commit_message_prefix: Prefix for the commit message
        
    Returns:
        tuple: (success, git_id) where success is a boolean and git_id is the commit ID
    """
    if skip_git:
        logging.info("Skipping Git operations as requested")
        return True, None
    
    # Pull latest changes
    logging.info("Pulling latest changes from Git repository...")
    if not non_interactive:
        print("\nPulling latest changes from Git repository...")
        
    pull_success = pull_changes_from_git()
    if not pull_success:
        if not non_interactive:
            print("\nWARNING: Failed to pull latest changes from Git repository.")
        logging.warning("Failed to pull latest changes from Git repository")
    
    # Commit changes
    if non_interactive:
        commit_message = f"{commit_message_prefix} - Automated operation"
    else:
        commit_message = input("\nEnter a description for the Git commit (or press Enter to skip): ")
        if not commit_message:
            logging.info("Skipping Git commit as no message was provided")
            return True, None
        commit_message = f"{commit_message_prefix} - {commit_message}"
    
    # Generate current datetime string
    from datetime import datetime
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Get commit suffix directly from get_id_with_date
    try:
        from src.libraries.CommonUtils import get_id_with_date
        random_id = get_id_with_date()
        commit_suffix = None
        if random_id:
            id_parts = random_id.split('_')
            commit_suffix = id_parts[1] if len(id_parts) > 1 else random_id
            
        # Format the commit message with datetime and commit_suffix
        formatted_commit_message = f"[{current_datetime}][{commit_suffix}] {commit_message}"
        
        logging.info(f"Committing changes with message: {formatted_commit_message}")
        if not non_interactive:
            print(f"\nCommitting changes with message: {formatted_commit_message}")
            
        commit_success, git_id = commit_changes_to_git(formatted_commit_message)
    except ValueError as e:
        error_message = str(e)
        logging.error(f"Failed to generate commit ID: {error_message}")
        if not non_interactive:
            print(f"\nERROR: Failed to generate commit ID: {error_message}")
            print("\nPlease run a policy sync operation and try again.")
        return False, None
    if not commit_success:
        if not non_interactive:
            print("\nWARNING: Failed to commit changes to Git repository.")
        logging.warning("Failed to commit changes to Git repository")
        return False, None
    
    return True, git_id

def deploy_firewall_resources(firewall_params, files, non_interactive):
    """
    Deploy firewall resources to Azure.
    
    Args:
        firewall_params: Parameters for the firewall deployment
        files: Dictionary of files to deploy
        non_interactive: Whether to run in non-interactive mode
        
    Returns:
        bool: True if deployment was successful, False otherwise
    """
    # Create selected_files structure for deployment
    selected_files = {
        'policies': files.get('policies', [])
    }
    
    # Get deployment parameters
    subscription_id = firewall_params.get('subscriptionid', '')
    ipgroup_rg = firewall_params.get('ipgrouprg', '')
    policies_rg = firewall_params.get('policiesrg', '')
    tenant_id = firewall_params.get('tenantid', '')  # Extract tenant ID from parameters
    
    # Count total files to deploy
    total_files = len(selected_files['policies'])
    
    # Confirm deployment in interactive mode
    if not non_interactive:
        print(f"\nYou are about to deploy {total_files} Bicep files to Azure:")
        print(f"  - {len(selected_files['policies'])} Policy files")
        print(f"\nSubscription: {subscription_id}")
        print(f"Tenant: {tenant_id}")
        print(f"Policies Resource Group: {policies_rg}")
        
        confirm = input("\nDo you want to proceed with deployment? (y/n): ").lower()
        if confirm != 'y':
            logging.info("Deployment cancelled by user")
            print("\nDeployment cancelled.")
            return False
    
    # Deploy resources
    logging.info(f"Deploying {total_files} resources to Azure...")
    if not non_interactive:
        print(f"\nDeploying {total_files} resources to Azure...")
        
    success = deploy_resources(selected_files, subscription_id, ipgroup_rg, policies_rg, tenant_id)
    
    if success:
        logging.info("Deployment completed successfully")
        if not non_interactive:
            print("\nDeployment completed successfully.")
    else:
        logging.warning("Deployment completed with warnings or errors")
        if not non_interactive:
            print("\nDeployment completed with warnings or errors. Check the logs for details.")
    
    return success

def export_policies_workflow(firewall_key, skip_git=False, non_interactive=False):
    """
    Execute the workflow for exporting policies for all firewalls in a firewall key group.
    
    Modified workflow:
    1. Sync policies
    2. Generate random ID (instead of Git commit ID)
    3. Export all firewalls sequentially
    4. Commit changes to Git
    5. Deploy each firewall sequentially if requested
    
    Args:
        firewall_key: The firewall key for the group of firewalls to export
        skip_git: Whether to skip final Git operations
        non_interactive: Whether to run in non-interactive mode
        
    Returns:
        tuple: (success, exported_files) where:
               - success is a boolean indicating if all exports were successful
               - exported_files is a dictionary of exported files by firewall
    """
    # 1. Sync policies
    logging.info("Starting policy synchronization before export...")
    sync_result = sync_policies_workflow()
    if sync_result:
        logging.info("Synchronization completed successfully. Proceeding with export.")
    else:
        logging.warning("Synchronization had issues. Proceeding with export using available data.")
    
    # 2. Generate random ID for file naming
    try:
        random_id = get_id_with_date()
        
        # Extract just the unique part of the ID (without the date)
        id_parts = random_id.split('_')
        unique_id = id_parts[1] if len(id_parts) > 1 else random_id
        
        logging.info(f"Using random ID for policy names: {random_id}")
    except ValueError as e:
        error_message = str(e)
        logging.error(f"Failed to generate ID: {error_message}")
        if not non_interactive:
            print(f"\nERROR: Failed to generate ID: {error_message}")
            print("\nPlease run a policy sync operation and try again.")
        return False, None, None, None
    
    # 3. Clean the bicep directory once for all firewalls
    logging.info("Cleaning the bicep directory before export...")
    if not clean_directory(Paths.BICEP_DIR):
        logging.error(f"Failed to clean Bicep directory: {Paths.BICEP_DIR}")
        return False, None
    logging.info(f"Cleaned Bicep directory: {Paths.BICEP_DIR}")
    
    # 4. Get all firewalls for this key
    firewalls = get_firewalls_by_key(firewall_key)
    if not firewalls:
        logging.error(f"No firewalls found for key: {firewall_key}")
        if not non_interactive:
            print(f"\nERROR: No firewalls found for key: {firewall_key}")
        return False, None
    
    logging.info(f"Found {len(firewalls)} firewalls for key: {firewall_key}")
    if not non_interactive:
        print(f"\nFound {len(firewalls)} firewalls for key: {firewall_key}")
        for i, fw in enumerate(firewalls, 1):
            print(f"{i}. {fw.get('firewallName', 'Unknown')}")
    
    # 5. PHASE 1: Export all firewalls first
    all_success = True
    exported_files = {}
    firewall_params = []
    
    for fw in firewalls:
        fw_name = fw.get("firewallName", "")
        if not fw_name:
            logging.warning("Skipping firewall with no name")
            continue
        
        # Get IP Group Resource Group from the firewall YAML
        ipgroup_rg = fw.get("ipGroupsResourceGroup", "")
        
        # Get IP Groups Subscription ID from the firewall YAML (may be different from policies subscription)
        ipgroups_subscription_id = fw.get("ipGroupssubscriptionId", fw.get("subscriptionId", ""))
        
        # Create params for this firewall
        params = {
            "subscriptionid": fw.get("subscriptionId", ""),
            "ipgrouprg": ipgroup_rg,
            "ipgroupssubscriptionid": ipgroups_subscription_id,
            "policiesrg": fw.get("policiesResourceGroup", ""),
            "firewallname": fw_name,
            "regionName": fw.get("regionName", Paths.DEFAULT_LOCATION),
            "tenantid": fw.get("tenantId", "")
        }
        
        # Store params for later deployment
        firewall_params.append(params)
        
        # Export policies for this firewall
        logging.info(f"Exporting policies for firewall: {fw_name}")
        if not non_interactive:
            print(f"\nExporting policies for firewall: {fw_name}")
        
        export_result, files = export_policies(
            params["subscriptionid"], 
            params["ipgrouprg"], 
            params["policiesrg"], 
            fw_name,
            random_id,
            params.get("regionName", Paths.DEFAULT_LOCATION),
            params["ipgroupssubscriptionid"]
        )
        
        if not export_result:
            logging.error(f"Failed to export policies for firewall: {fw_name}")
            if not non_interactive:
                print(f"\nERROR: Failed to export policies for firewall: {fw_name}")
            all_success = False
            continue
        
        logging.info(f"Successfully exported policies for firewall: {fw_name}")
        
        if not non_interactive:
            print(f"\nSuccessfully exported policies for firewall: {fw_name}")
            print(f"\nGenerated files:")
            for file_type, file_list in files.items():
                print(f"\n{file_type.capitalize()}:")
                for file_path in file_list:
                    print(f"  - {os.path.basename(file_path)}")
        
        # Store exported files for this firewall
        exported_files[fw_name] = files
    
    # 6. Skip Git commit in this function - it will be handled by handle_export_policies
    if skip_git:
        logging.info("Skipping Git commit as requested")
    
    # Return the success status and exported files, but don't do Git commit or ask about deployment here
    # The deployment prompt will be handled in handle_export_policies
    return all_success, exported_files, firewall_key, unique_id

def handle_update_repository(args):
    """
    Handle the update repository operation.
    
    Args:
        args: Command line arguments
        
    Returns:
        bool: True if update was successful, False otherwise
    """
    try:
        logging.info("Starting repository update...")
        print("\nUpdating repository from remote...")
        
        pull_success = pull_changes_from_git()
        
        if pull_success:
            logging.info("Repository update completed successfully")
            print("\nRepository updated successfully.")
            return True
        else:
            logging.error("Failed to update repository")
            print("\nFailed to update repository. Check the logs for details.")
            return False
            
    except Exception as e:
        logging.error(f"Error during repository update: {str(e)}", exc_info=True)
        print(f"\nError during repository update: {str(e)}")
        return False

def handle_download_templates(args):
    """Handle the download ARM templates operation."""
    try:
        # Get environment from command line or ask user
        if args.non_interactive:
            environment = get_environment_from_cmdline(args.environment)
            if not environment:
                print("Error: Environment must be specified in non-interactive mode")
                return 1
        else:
            # Use list_available_environments in interactive mode
            selected = list_available_environments(interactive=True)
            if not selected:
                print("No environment selected. Operation cancelled.")
                return 1
            # selected is a tuple of (idx, key), we want the key
            environment = selected[1]

        print(f"\nDownloading latest ARM templates for environment {environment}...")
        success, message = download_latest_arm_template(environment)
        if success:
            print(message)
            return 0
        else:
            print(f"Download failed: {message}")
            return 1
            
    except Exception as e:
        print(f"Error during download operation: {str(e)}")
        logging.exception("Error during download operation")
        return 1

def handle_import_policies(args):
    """Handle the import policies operation."""
    try:
        # Get environment
        environment = args.environment
        if not environment and not args.non_interactive:
            selected_env = list_available_environments(interactive=True)
            if not selected_env:
                return False
            env_name, firewall_key = selected_env
        else:
            # Get firewall data from command line
            env_name, firewall_key = get_environment_from_cmdline(environment)
            if not firewall_key:
                logging.error(f"Environment not found: {environment}")
                if not args.non_interactive:
                    print(f"\nEnvironment not found: {environment}")
                return False

        logging.info(f"Importing policies for environment: {env_name} (key: {firewall_key})")
        if not args.non_interactive:
            print(f"\nImporting policies for environment: {env_name}")

        # Execute import with the firewall key
        success, message = import_policies(firewall_key)
        if success:
            print("Import completed successfully")
            return 0
        else:
            print(f"Import failed: {message}")
            return 1
            
    except Exception as e:
        print(f"Error during import operation: {str(e)}")
        logging.exception("Error during import operation")
        return 1

def handle_sync_policies(args):
    """
    Handle the policy synchronization operation.
    
    Args:
        args: Command line arguments
        
    Returns:
        int: Exit code (0 = success, 1 = failure)
    """
    sync_result = sync_policies_workflow()
    if sync_result:
        logging.info("Synchronization completed successfully.")
        if not args.non_interactive:
            print("\nSynchronization completed successfully.")
        return 0
    else:
        logging.error("Synchronization failed. Check the logs for details.")
        if not args.non_interactive:
            print("\nSynchronization failed. Check the logs for details.")
        return 1

def handle_export_policies(args):
    """
    Handle the export policies operation.
    
    Args:
        args: Command line arguments
        
    Returns:
        bool: True if export was successful, False otherwise
    """
    try:
        logging.info("Starting policy export...")
        
        # Get environment
        environment = args.environment
        if not environment and not args.non_interactive:
            selected_env = list_available_environments(interactive=True)
            if not selected_env:
                return False
            env_name, firewall_key = selected_env
        else:
            # Get firewall data from command line
            env_name, firewall_key = get_environment_from_cmdline(environment)
            if not firewall_key:
                logging.error(f"Environment not found: {environment}")
                if not args.non_interactive:
                    print(f"\nEnvironment not found: {environment}")
                return False
        
        logging.info(f"Exporting policies for environment: {env_name} (key: {firewall_key})")
        if not args.non_interactive:
            print(f"\nExporting policies for environment: {env_name}")
        
        # Execute export workflow
        success, exported_files, firewall_key, unique_id = export_policies_workflow(firewall_key, skip_git=True, non_interactive=args.non_interactive)
        
        if not success:
            logging.error("Policy export failed")
            if not args.non_interactive:
                print("\nPolicy export failed. Check the logs for details.")
            return False
        
        # If we're in non-interactive mode or the export failed, return here
        if args.non_interactive:
            logging.info("Policy export completed successfully (non-interactive mode)")
            return True
        
        # In interactive mode, ask if user wants to compare
        print("\nPolicy export completed successfully.")
        compare_choice = input("\nDo you want to compare the newly created Bicep with existing ARM templates? (y/n): ").lower()
        
        if compare_choice == 'y':
            logging.info("User chose to compare ARM templates")
            print("\nComparing ARM templates...")
            
            # Create a copy of args to modify
            compare_args = copy.deepcopy(args)
            compare_args.include_diff = True  # Show diff by default in this workflow
            
            # Run the compare ARM templates operation
            compare_success = handle_compare_arm(compare_args)
            
            if not compare_success:
                print("\nComparison completed with warnings or errors. Check the logs for details.")
            else:
                print("\nComparison completed successfully.")
        
        # Ask if user wants to commit changes to Git
        git_choice = input("\nDo you want to commit the changes to Git? (y/n): ").lower()
        
        if git_choice == 'y' and not args.skip_git:
            logging.info("User chose to commit changes to Git")
            
            # Create a copy of args to modify
            commit_args = copy.deepcopy(args)
            # Add firewall info to args for use in handle_commit_repository
            commit_args.firewall_key = firewall_key
            # No longer setting unique_id as it will be generated during commit
            
            # Call the repository commit handler
            handle_commit_repository(commit_args)
        else:
            if args.skip_git:
                logging.info("Git operations are disabled by command line flag")
                print("\nSkipping Git commit as it's disabled by command line flag.")
            else:
                logging.info("User chose not to commit changes to Git")
                print("\nSkipping Git commit as requested.")
        
        # Ask if user wants to deploy
        deploy_choice = input("\nDo you want to deploy the generated Bicep files? (y/n): ").lower()
        
        if deploy_choice == 'y':
            logging.info("User chose to deploy Bicep files")
            print("\nDeploying Bicep files...")
            
            # Run the deploy Bicep operation
            deploy_success = handle_deploy_bicep(args)
            
            if not deploy_success:
                print("\nDeployment completed with warnings or errors. Check the logs for details.")
                return False
            else:
                print("\nDeployment completed successfully.")
        else:
            logging.info("User chose not to deploy Bicep files")
            print("\nSkipping deployment. Bicep files have been created in the bicep/ directory.")
        
        return True
            
    except Exception as e:
        logging.error(f"Error during policy export: {str(e)}", exc_info=True)
        if not args.non_interactive:
            print(f"\nPolicy export failed: {str(e)}")
        return False

def handle_deploy_bicep(args):
    """
    Handle the deploy bicep operation.
    
    Args:
        args: Command line arguments
        
    Returns:
        bool: True if deployment was successful, False otherwise
    """
    try:
        logging.info("Starting Bicep deployment...")
        
        # Get environment
        environment = args.environment
        if not environment and not args.non_interactive:
            selected_env = list_available_environments(interactive=True)
            if not selected_env:
                return False
            env_name, firewall_key = selected_env
        else:
            # Get firewall data from command line
            env_name, firewall_key = get_environment_from_cmdline(environment)
            if not firewall_key:
                logging.error(f"Environment not found: {environment}")
                if not args.non_interactive:
                    print(f"\nEnvironment not found: {environment}")
                return False
        
        logging.info(f"Deploying Bicep for environment: {env_name} (key: {firewall_key})")
        if not args.non_interactive:
            print(f"\nDeploying Bicep for environment: {env_name}")
        
        # Find Bicep files
        bicep_files = find_bicep_files(Paths.BICEP_DIR)
        if not bicep_files:
            logging.error("No Bicep files found for deployment")
            if not args.non_interactive:
                print("\nNo Bicep files found for deployment.")
            return False
        
        # Select files to deploy
        selected_files = None
        if args.non_interactive:
            # In non-interactive mode, select all files
            selected_files = bicep_files
        else:
            # In interactive mode, let the user select files
            selected_files = select_bicep_files(bicep_files)
            if not selected_files:
                logging.info("No files selected for deployment")
                print("\nNo files selected for deployment.")
                return False
        
        # Get firewalls for this key
        firewalls = get_firewalls_by_key(firewall_key)
        if not firewalls:
            logging.error(f"No firewalls found for key: {firewall_key}")
            if not args.non_interactive:
                print(f"\nERROR: No firewalls found for key: {firewall_key}")
            return False
        
        # Deploy to each firewall
        all_success = True
        for fw in firewalls:
            fw_name = fw.get("firewallName", "")
            if not fw_name:
                logging.warning("Skipping firewall with no name")
                continue
            
            logging.info(f"Deploying to firewall: {fw_name}")
            if not args.non_interactive:
                print(f"\nDeploying to firewall: {fw_name}")
            
            # Create params for this firewall
            params = {
                "subscriptionid": fw.get("subscriptionId", ""),
                "ipgrouprg": fw.get("ipGroupsResourceGroup", ""),
                "policiesrg": fw.get("policiesResourceGroup", ""),
                "firewallname": fw_name,
                "regionName": fw.get("regionName", Paths.DEFAULT_LOCATION),
                "tenantid": fw.get("tenantId", "")  # Include tenant ID from firewall configuration
            }
            
            # Deploy resources
            deploy_success = deploy_firewall_resources(params, selected_files, args.non_interactive)
            if not deploy_success:
                all_success = False
        
        if all_success:
            logging.info("Bicep deployment completed successfully")
            if not args.non_interactive:
                print("\nBicep deployment completed successfully.")
            return True
        else:
            logging.warning("Bicep deployment completed with warnings or errors")
            if not args.non_interactive:
                print("\nBicep deployment completed with warnings or errors. Check the logs for details.")
            return False
            
    except Exception as e:
        logging.error(f"Error during Bicep deployment: {str(e)}", exc_info=True)
        if not args.non_interactive:
            print(f"\nError during Bicep deployment: {str(e)}")
        return False

def handle_compare_arm(args):
    """
    Handle the comparison of ARM templates between import and export directories.
    
    This function orchestrates the comparison of ARM templates between the arm_import
    and arm_export directories, finds matching templates, compares them, and saves
    the results to the comparison directory.
    
    Args:
        args: Command line arguments containing include_diff and save_results flags
        
    Returns:
        bool: True if the comparison was successful, False otherwise
    """
    from src.libraries.CompareUtils import (
        find_matching_templates, compare_arm_templates, 
        save_comparison_result, generate_arm_templates_from_bicep
    )
    
    logging.info("Starting ARM template comparison...")
    print("\nStarting ARM template comparison...")
    
    # Ask if user wants to download the latest ARM templates first
    if not args.non_interactive:
        download_choice = input("\nDo you want to download the latest ARM templates from Azure before comparing? (y/n): ").lower()
        if download_choice == 'y':
            print("\nDownloading the latest ARM templates...")
            
            # Show environment selection to user
            selected = list_available_environments(interactive=True)
            if not selected:
                print("No environment selected. Proceeding with comparison using existing templates.")
            else:
                # selected is a tuple of (idx, key), we want the key
                environment = selected[1]
                
                print(f"\nDownloading latest ARM templates for environment {environment}...")
                success, message = download_latest_arm_template(environment)
                
                if success:
                    print(message)
                else:
                    print(f"Download failed: {message}")
                    print("Proceeding with comparison using existing templates.")
    
    # First, generate ARM templates from Bicep files
    logging.info("Generating ARM templates from Bicep files...")
    print("\nGenerating ARM templates from Bicep files...")
    
    generation_success, generated_templates = generate_arm_templates_from_bicep()
    
    if not generation_success:
        msg = "Failed to generate one or more ARM templates from Bicep files. Please check the logs for details."
        logging.error(msg)
        print(f"\nERROR: {msg}")
        print("\nComparison workflow stopped due to ARM template generation failure.")
        return False
    
    if not generated_templates:
        msg = "No ARM templates were generated from Bicep files"
        logging.warning(msg)
        print(f"\n{msg}")
    else:
        logging.info(f"Successfully generated {len(generated_templates)} ARM templates")
        print(f"\nSuccessfully generated {len(generated_templates)} ARM templates")
    
    # Find matching templates between import and export directories
    matches = find_matching_templates()
    
    if not matches:
        msg = "No matching ARM templates found to compare"
        logging.warning(msg)
        print(f"\n{msg}")
        return False
    
    logging.info(f"Found {len(matches)} matching template(s) to compare")
    print(f"\nFound {len(matches)} matching template(s) to compare")
    
    # Compare each pair of templates
    successful_comparisons = 0
    
    for import_file, export_file in matches:
        import_name = os.path.basename(import_file)
        export_name = os.path.basename(export_file)
        
        logging.info(f"Comparing {import_name} with {export_name}...")
        print(f"\nComparing {import_name} with {export_name}...")
        
        # Perform comparison
        result = compare_arm_templates(import_file, export_file, include_diff=args.include_diff)
        
        if result["success"]:
            # Always save the result to file unless explicitly disabled
            save_to_file = True if not hasattr(args, 'save_results') else args.save_results
            
            # Save and display results
            summary = save_comparison_result(result, save_to_file=save_to_file)
            print(f"\n{summary}")
            
            # Show detailed differences if requested
            if result["has_differences"] and args.include_diff:
                print("\nSample of differences (first 5 per category):")
                differences = result.get("differences", {})
                
                # Show items only in import file
                import_only = differences.get("import_only", {})
                if import_only:
                    print("\nItems only in ARM Import file:")
                    for i, (key, value) in enumerate(import_only.items()):
                        if i >= 5:  # Limit to 5 items
                            print(f"  ... and {len(import_only) - 5} more items")
                            break
                        print(f"  {key}")
                
                # Show items only in export file
                export_only = differences.get("export_only", {})
                if export_only:
                    print("\nItems only in ARM Export file:")
                    for i, (key, value) in enumerate(export_only.items()):
                        if i >= 5:  # Limit to 5 items
                            print(f"  ... and {len(export_only) - 5} more items")
                            break
                        print(f"  {key}")
                
                # Show items with different values
                values_changed = differences.get("values_changed", {})
                if values_changed:
                    print("\nItems with different values:")
                    for i, (key, value) in enumerate(values_changed.items()):
                        if i >= 5:  # Limit to 5 items
                            print(f"  ... and {len(values_changed) - 5} more items")
                            break
                        print(f"  {key}")
            
            successful_comparisons += 1
        else:
            error_msg = result.get("error", "Unknown error during comparison")
            logging.error(f"Failed to compare {import_name} with {export_name}: {error_msg}")
            print(f"\nError: Failed to compare {import_name} with {export_name}: {error_msg}")
    
    if successful_comparisons > 0:
        print(f"\nSuccessfully compared {successful_comparisons} of {len(matches)} template pairs.")
        print("\nNote: Resource names are normalized for comparison. For example:")
        print("  - 'TestEW_VNET00_GLOBAL_POLICY_P01/RCG_Name' is treated as equivalent to:")
        print("  - '[format('{0}/{1}', 'TestEW_VNET00_GLOBAL_POLICY_P01_20250627_v7wlxg', 'RCG_Name')]'")
        return True
    else:
        print("\nNo templates were successfully compared.")
        return False

def handle_commit_repository(args):
    """
    Handle the commit operation for the repository.
    
    This function commits all changes to the Git repository, 
    prompting the user for a commit message.
    
    Args:
        args: Command line arguments
        
    Returns:
        bool: True if commit was successful, False otherwise
    """
    try:
        logging.info("Starting repository commit...")
        
        if args.skip_git:
            logging.info("Skipping Git operations as requested")
            print("\nSkipping Git operations as requested via command line flag.")
            return True
        
        # Prompt for commit message
        if args.non_interactive:
            commit_message = "Automated commit from Azure Firewall Policy Manager"
        else:
            print("\nCommitting changes to Git repository...")
            
            # Check if we have firewall export information
            has_firewall_info = hasattr(args, 'firewall_key')
            
            commit_message = input("\nEnter a description for the Git commit (or press Enter to skip): ")
            if not commit_message:
                if has_firewall_info:
                    commit_message = f"Firewall {args.firewall_key}: Manual export"
                else:
                    logging.info("Skipping Git commit as no message was provided")
                    print("\nSkipping Git commit as no message was provided.")
                    return True
        
        # Generate current datetime string
        from datetime import datetime
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Get commit suffix directly from get_id_with_date
            from src.libraries.CommonUtils import get_id_with_date
            random_id = get_id_with_date()
            commit_suffix = None
            if random_id:
                id_parts = random_id.split('_')
                commit_suffix = id_parts[1] if len(id_parts) > 1 else random_id
            
            # Format the commit message with datetime and commit_suffix
            formatted_commit_message = f"[{current_datetime}][{commit_suffix}] {commit_message}"
            
            # Commit the changes
            logging.info(f"Committing changes with message: {formatted_commit_message}")
            if not args.non_interactive:
                print(f"\nCommitting changes with message: {formatted_commit_message}")
            
            commit_success, git_id = commit_changes_to_git(formatted_commit_message)
        except ValueError as e:
            error_message = str(e)
            logging.error(f"Failed to generate commit ID: {error_message}")
            if not args.non_interactive:
                print(f"\nERROR: Failed to generate commit ID: {error_message}")
                print("\nPlease run a policy sync operation and try again.")
            return False
        
        if commit_success:
            logging.info(f"Changes committed successfully with ID: {git_id}")
            if not args.non_interactive:
                print(f"\nChanges committed successfully with ID: {git_id}")
            return True
        else:
            logging.error("Failed to commit changes to Git repository")
            if not args.non_interactive:
                print("\nFailed to commit changes to Git repository. Check the logs for details.")
            return False
            
    except Exception as e:
        logging.error(f"Error during repository commit: {str(e)}", exc_info=True)
        if not args.non_interactive:
            print(f"\nError during repository commit: {str(e)}")
        return False


