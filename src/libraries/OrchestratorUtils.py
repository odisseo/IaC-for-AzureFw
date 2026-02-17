"""
Orchestrator utilities for Azure Firewall Policy Manager.

This module provides the core functionality for managing Azure Firewall policies,
including importing, exporting, synchronizing, and deploying policies.
"""
import copy
import glob
import logging
import os
from datetime import datetime
from src.libraries.AzureUtils import AzureAssign, AzureCommon, AzureDeploy, AzureDownload
from src.libraries.CommonUtils import CommonConfiguration, CommonFile, CommonData, CommonInteraction
from src.libraries.GitUtils import commit_changes_to_git, pull_changes_from_git, switch_git_branch, get_available_branches, get_current_branch
from src.libraries.CompareUtils import ComparePolicy
from src.libraries.InventoryUtils import ImportExport
from src.libraries.Parameters import Config, Paths

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

def handle_update_repository(args):
    """
    Handle the update repository operation.
    
    Args:
        args: Command line arguments
        
    Returns:
        int: Exit code (0 = success, 1 = failure)
    """
    try:
        # Set Windows list separator to semicolon for CSV compatibility
        # CommonConfiguration.set_list_separator(Config.SEPARATOR)
        
        logging.info("Starting repository update...")
        
        pull_success = pull_changes_from_git()
        
        if pull_success:
            print("\nRepository updated successfully.")
            return 0
        else:
            print("\nFailed to update repository. See log for details.")
            return 1
            
    except Exception as e:
        logging.error(f"Error in handle_update_repository: {str(e)}", exc_info=True)
        print(f"\nError updating repository: {str(e)}")
        return 1

def handle_git_branch(args):
    """
    Handle the Git branch switch operation.
    
    Args:
        args: Command line arguments
            - args.git_branch: Branch name (optional, required in non-interactive mode)
            - args.non_interactive: If True, run without user prompts
        
    Returns:
        int: Exit code (0 = success, 1 = failure)
    """
    try:
        logging.info("Starting Git branch operation...")
        
        branch_name = None
        
        # Non-interactive mode
        if args.non_interactive:
            if not hasattr(args, 'git_branch') or not args.git_branch:
                logging.error("Branch name must be specified in non-interactive mode")
                return 1
            
            branch_name = args.git_branch
            logging.info(f"Non-interactive mode: switching to branch '{branch_name}'")
        
        # Interactive mode
        else:
            print("\nSwitching Git Branch...")
            
            # Get current branch
            current_branch = get_current_branch()
            if current_branch:
                print(f"\nCurrent branch: {current_branch}")
            
            # Get available branches
            branches = get_available_branches()
            if not branches:
                logging.error("Unable to retrieve Git branches")
                return 1
            
            # Combine all branches for selection
            all_branches = branches['local'] + [
                b.replace('origin/', '', 1) for b in branches['remote']
            ]
            
            # Create formatter to show local/remote status and current marker
            def branch_formatter(index, branch):
                is_local = index <= len(branches['local'])
                marker = " (current)" if branch == current_branch else ""
                branch_type = "" if is_local else " (remote)"
                return f"{branch}{marker}{branch_type}"
            
            # Use CommonInteraction for selection
            selected_branch, action = CommonInteraction.prompt_user_selection(
                items=all_branches,
                prompt_message="Select a branch (number) or enter branch name, or 'q' to cancel",
                item_formatter=branch_formatter,
                allow_cancel=True,
                allow_skip=False,
                allow_text_input=True
            )
            
            if action == 'cancelled' or not selected_branch:
                logging.info("Branch switch cancelled by user")
                return 1
            
            branch_name = selected_branch
            
            print(f"\nSwitching to branch: {branch_name}")
        
        # Switch to the selected branch
        success, switched_branch = switch_git_branch(branch_name)
        
        if success and switched_branch:
            logging.info(f"Successfully switched to branch: {switched_branch}")
            
            # Automatically pull the latest changes after switching branch
            print("\nPulling the latest changes from the remote...")
            pull_success = pull_changes_from_git()
            
            if pull_success:
                logging.info("Branch updated successfully")
            else:
                logging.warning("Failed to update branch")
            
            return 0
        else:
            logging.error(f"Failed to switch to branch: {branch_name}")
            return 1
        
    except Exception as e:
        logging.error(f"Error in handle_git_branch: {str(e)}", exc_info=True)
        print(f"\nError switching Git branch: {str(e)}")
        return 1

def handle_download_templates(args):
    """Handle the download ARM templates operation and automatically import policies."""
    try:
        # Get firewall from command line or ask user
        if args.non_interactive:
            if not args.firewall:
                print("Error: Firewall must be specified in non-interactive mode")
                return 1
            environment_name = args.firewall
        else:
            # Interactive mode - prompt for firewall selection
            print("\nSelect firewall for ARM template download...")
            
            # Get list of available firewalls
            environments, error_msg = CommonConfiguration.get_available_environments()
            if error_msg:
                print(f"\nError: {error_msg}")
                return 1
            
            # Format environment for display
            def env_formatter(index, env_tuple):
                idx, env_name, _ = env_tuple
                return f"{env_name}"
            
            # Use CommonInteraction for selection
            selected_env, action = CommonInteraction.prompt_user_selection(
                items=environments,
                prompt_message="Available firewall environments",
                item_formatter=env_formatter,
                allow_cancel=True,
                allow_skip=False,
                allow_text_input=False
            )
            
            if action == 'cancelled' or not selected_env:
                logging.info("Environment selection cancelled by user")
                return 1
            
            # Extract environment name from selected tuple
            _, environment_name, _ = selected_env
        
        # Clean the ARM directory before downloading new templates
        logging.info("Cleaning ARM directory before downloading new templates...")
        CommonFile.clean_directory(Paths.ARM_DIR)
        
        # Download ARM templates for the environment
        print(f"\nDownloading ARM templates for environment {environment_name}...")
        success, message = AzureDownload.download_arm_template(environment_name)
        
        if not success:
            print(f"Download failed: {message}")
            # Delete ARM import directory even on failure
            logging.info("Deleting ARM import directory after failed download...")
            if CommonFile.delete_directory(Paths.ARM_DIR):
                print("🗑️  ARM import directory deleted")
            else:
                print("⚠️  Warning: Failed to delete ARM import directory")
            return 1
        
        print(message)
        
        # Automatically import policies after successful download
        logging.info(f"Starting automatic import of policies for environment: {environment_name}")
        print(f"\nImporting policies from downloaded ARM templates...")
        
        import_success, import_message = ImportExport.import_policies(environment_name)
        
        if not import_success:
            print(f"Import failed: {import_message}")
            # Delete ARM import directory even on failure
            logging.info("Deleting ARM import directory after failed import...")
            if CommonFile.delete_directory(Paths.ARM_DIR):
                print("🗑️  ARM import directory deleted")
            else:
                print("⚠️  Warning: Failed to delete ARM import directory")
            return 1
        
        print(f"Import successful: {import_message}")
        
        # Trigger the sync workflow to update CSV files after successful import
        logging.info("Running sync workflow to update CSV files...")
        print("\nSynchronizing policies to CSV format...")
        
        sync_success = handle_sync_policies(args)
        if sync_success == 0:
            logging.info("CSV files updated successfully")
            print("✅ Download, import, and sync completed successfully!")
            
            # Delete ARM import directory after successful completion
            logging.info("Deleting ARM import directory after successful processing...")
            if CommonFile.delete_directory(Paths.ARM_DIR):
                print("🗑️  ARM import directory deleted")
            else:
                print("⚠️  Warning: Failed to delete ARM import directory")
            
            return 0
        else:
            logging.warning("Download and import successful, but CSV generation failed")
            print("⚠️ Download and import successful, but CSV generation failed")
            # Delete ARM import directory even when sync fails
            logging.info("Deleting ARM import directory after failed sync...")
            if CommonFile.delete_directory(Paths.ARM_DIR):
                print("🗑️  ARM import directory deleted")
            else:
                print("⚠️  Warning: Failed to delete ARM import directory")
            return 1
            
    except Exception as e:
        print(f"Error during download operation: {str(e)}")
        logging.exception("Error during download operation")
        # Delete ARM import directory even on exception
        logging.info("Deleting ARM import directory after exception...")
        if CommonFile.delete_directory(Paths.ARM_DIR):
            print("🗑️  ARM import directory deleted")
        else:
            print("⚠️  Warning: Failed to delete ARM import directory")
        return 1

def handle_import_policies(args):
    """Handle the import policies operation."""
    try:
        # Get firewall
        environment = args.firewall
        if not environment and not args.non_interactive:
            # Interactive mode: prompt for firewall selection
            print("\nSelect firewall for policy import...")
            
            # Get list of available firewalls
            environments, error_msg = CommonConfiguration.get_available_environments()
            if error_msg:
                print(f"\nError: {error_msg}")
                return 1
            
            # Format environment for display
            def env_formatter(index, env_tuple):
                idx, env_name, _ = env_tuple
                return f"{env_name}"
            
            # Use CommonInteraction for selection
            selected_env, action = CommonInteraction.prompt_user_selection(
                items=environments,
                prompt_message="Available firewall environments",
                item_formatter=env_formatter,
                allow_cancel=True,
                allow_skip=False,
                allow_text_input=False
            )
            
            if action == 'cancelled' or not selected_env:
                logging.info("Environment selection cancelled by user")
                return 1
            
            # Extract environment name from selected tuple
            _, environment_name, _ = selected_env
        else:
            # Get environment data from command line
            environment_name, error_msg = CommonConfiguration.get_environment(
                environment_name=environment, 
                load_yaml=False
            )
            if not environment_name:
                logging.error(f"Environment not found: {environment}")
                return 1

        logging.info(f"Importing policies for environment: {environment_name}")

        # Execute import with the environment_name
        success, message = ImportExport.import_policies(environment_name)
        if success:
            # Trigger the sync workflow to update CSV files after successful import
            logging.info("Import completed successfully. Running sync workflow to update CSV files...")
            sync_success = handle_sync_policies(args)
            if sync_success == 0:  # handle_sync_policies returns 0 for success
                logging.info("CSV files updated successfully")
            else:
                logging.warning("Import successful, but CSV generation failed")
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
    sync_result = ImportExport.sync_policies(Paths.POLICIES_DIR, Paths.CSV_DIR, args)
    if sync_result:
        logging.info("Synchronization completed successfully")
        return 0
    else:
        logging.error("Synchronization failed")
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
        
        # Get firewall
        environment_name = args.firewall
        if not environment_name and not args.non_interactive:
            # Interactive mode - prompt for firewall selection
            print("\nSelect firewall for policy export...")
            
            # Get list of available firewalls
            environments, error_msg = CommonConfiguration.get_available_environments()
            if error_msg:
                print(f"\nError: {error_msg}")
                return 1
            
            # Format environment for display
            def env_formatter(index, env_tuple):
                idx, env_name, _ = env_tuple
                return f"{env_name}"
            
            # Use CommonInteraction for selection
            selected_env, action = CommonInteraction.prompt_user_selection(
                items=environments,
                prompt_message="Available firewall environments",
                item_formatter=env_formatter,
                allow_cancel=True,
                allow_skip=False,
                allow_text_input=False
            )
            
            if action == 'cancelled' or not selected_env:
                logging.info("Environment selection cancelled by user")
                return 1
            
            # Extract environment name from selected tuple
            _, environment_name, _ = selected_env
        
        if not environment_name:
            logging.error("Environment not specified")
            return 1
        
        logging.info(f"Exporting policies for environment: {environment_name}")
        
        # 1. Sync policies before export
        logging.info("Synchronizing policies before export...")
        
        handle_sync_policies(args)
        
        # 2. Generate unique ID for policy names
        try:
            random_id = CommonData.get_id_with_date()
            logging.info(f"Using ID for policy names: {random_id}")
        except ValueError as e:
            logging.error(f"Failed to generate ID: {str(e)}")
            return 1
        
        # 3. Clean the bicep directory
        logging.info("Cleaning the bicep directory before export...")
        if not CommonFile.clean_directory(Paths.BICEP_DIR):
            logging.error(f"Failed to clean Bicep directory: {Paths.BICEP_DIR}")
            return 1
        
        # 4. Export policies for the environment
        export_result, files = ImportExport.export_policies(
            environment_name=environment_name,
            version=random_id
        )
        
        if not export_result:
            logging.error(f"Failed to export policies for environment: {environment_name}")
            return 1
        
        logging.info(f"Successfully exported policies for environment: {environment_name}")
        print(f"\nGenerated files:")
        for file_type, file_list in files.items():
            print(f"\n{file_type.capitalize()}:")
            for file_path in file_list:
                print(f"  - {os.path.basename(file_path)}")
        
        # If we're in non-interactive mode, we're done
        if args.non_interactive:
            logging.info("Policy export completed successfully (non-interactive mode)")
            return 0
        
        # 5. Run comparison between local and Azure policies
        print("\n" + "="*80)
        print("🔍 Running comparison between exported Bicep and Azure...")
        print("="*80)
        
        comparison_args = copy.deepcopy(args)
        comparison_args.firewall = environment_name
        comparison_args.non_interactive = True  # Use the same firewall without prompting
        comparison_result = handle_compare_arm(comparison_args)
        
        if comparison_result == 0:
            print("\n✅ Comparison completed successfully")
        else:
            print("\n⚠️ Comparison completed with warnings or errors")
        
        # 6. Ask if user wants to commit changes to Git
        git_choice = input("\nDo you want to commit the changes to Git? (y/n): ").lower()
        
        if git_choice == 'y' and not args.skip_git:
            logging.info("User chose to commit changes to Git")
            
            commit_args = copy.deepcopy(args)
            commit_args.firewall_key = environment_name
            
            handle_commit_repository(commit_args)
        else:
            if args.skip_git:
                logging.info("Git operations are disabled by command line flag")
            else:
                logging.info("User chose not to commit changes to Git")
            
    except Exception as e:
        logging.error(f"Error during policy export: {str(e)}", exc_info=True)
        print(f"\nPolicy export failed: {str(e)}")
        return 1

def handle_deploy_bicep(args):
    """
    Handle the deploy bicep operation.
    
    This function:
    1. Gets firewall environment data from YAML files in firewalls folder
    2. Finds Bicep files in the bicep directory
    3. Selects files to deploy (interactive or all in non-interactive mode)
    4. For each firewall in the selected environment, deploys the policies
       that match the firewall's policiesName list
    
    Args:
        args: Command line arguments
        
    Returns:
        bool: True if deployment was successful, False otherwise
    """
    try:
        logging.info("Starting Bicep deployment...")
        
        # 1. Get firewall name first (load_yaml=False)
        environment_name = args.firewall
        firewalls_data = None
        
        if not environment_name and not args.non_interactive:
            # Interactive mode - prompt for firewall selection
            print("\nSelect firewall for Bicep deployment...")
            
            # Get list of available firewalls
            environments, error_msg = CommonConfiguration.get_available_environments()
            if error_msg:
                print(f"\nError: {error_msg}")
                return 1
            
            # Format environment for display
            def env_formatter(index, env_tuple):
                idx, env_name, _ = env_tuple
                return f"{env_name}"
            
            # Use CommonInteraction for selection
            selected_env, action = CommonInteraction.prompt_user_selection(
                items=environments,
                prompt_message="Available firewall environments",
                item_formatter=env_formatter,
                allow_cancel=True,
                allow_skip=False,
                allow_text_input=False
            )
            
            if action == 'cancelled' or not selected_env:
                logging.info("Environment selection cancelled by user")
                return 1
            
            # Extract environment name from selected tuple
            _, environment_name, _ = selected_env
        
        # Now load the firewall data for the selected environment (works for both interactive and non-interactive)
        firewalls_data, error_msg = CommonConfiguration.get_environment(
            environment_name=environment_name, 
            load_yaml=True
        )
        if not firewalls_data:
            logging.error(f"Environment not found: {environment_name}")
            return 1
        env_name = environment_name
        
        logging.info(f"Deploying Bicep for environment: {env_name}")
            
        # 2. Find all available Bicep files
        bicep_files = AzureDeploy.find_bicep_files(Paths.BICEP_DIR)
        if not bicep_files:
            logging.error("No Bicep files found for deployment")
            return 1
        
        # 3. Select Bicep files to deploy and deployment mode
        parallel_mode = True  # Default for non-interactive
        
        if args.non_interactive:
            # In non-interactive mode, deploy all files in parallel
            selected_files = bicep_files
            logging.info(f"Non-interactive mode: deploying all {len(bicep_files)} Bicep files in parallel")
        else:
            # In interactive mode, let user select mode
            selected_files, parallel_mode = AzureDeploy.select_bicep_files(bicep_files)
            if not selected_files:
                logging.warning("No Bicep files selected for deployment")
                return 1
        
        # 4. Deploy to each firewall
        all_success = True
        deployed_count = 0
        
        # Get deployment ID once for all firewalls
        git_id = None
        try:
            git_id = CommonData.get_id_with_date()
            if git_id:
                logging.info(f"Using ID from get_id_with_date: {git_id}")
        except Exception as e:
            logging.warning(f"Could not get ID from get_id_with_date: {e}")
        
        # Fallback to git commit ID if get_id_with_date failed
        if not git_id:
            from src.libraries.GitUtils import get_git_commit_id
            git_id = get_git_commit_id()
            if git_id:
                logging.info(f"Using git commit ID: {git_id}")
            else:
                git_id = "bicep-deployment"  # Final fallback
                logging.warning("Could not retrieve any ID, using default deployment name")
        
        whatif_mode = hasattr(args, 'whatif') and args.whatif
        
        # PARALLEL MODE: Deploy all firewalls simultaneously
        if parallel_mode:
            # Collect all deployment jobs (files + metadata) from all firewalls
            all_deployment_jobs = []
            
            for fw in firewalls_data:
                fw_name = fw.get("firewallName", "")
                if not fw_name:
                    logging.warning("Skipping firewall with no name")
                    continue
                
                logging.info(f"Processing firewall: {fw_name}")
                
                # Get policy names for this firewall
                policy_names_raw = fw.get("policiesName", [])
                if not policy_names_raw:
                    logging.warning(f"No policies defined for firewall: {fw_name}")
                    continue
                
                # Convert to list if it's a dict with integer keys
                if isinstance(policy_names_raw, dict):
                    policy_names = [policy_names_raw[k] for k in sorted(policy_names_raw.keys())]
                elif isinstance(policy_names_raw, str):
                    policy_names = [policy_names_raw]
                else:
                    policy_names = policy_names_raw
                
                # Filter selected files to only include those matching this firewall's policies
                fw_files = []
                for file in selected_files:
                    file_name_no_ext = os.path.splitext(os.path.basename(file))[0]
                    if any(policy_name in file_name_no_ext for policy_name in policy_names):
                        fw_files.append(file)
                
                if not fw_files:
                    logging.warning(f"No matching Bicep files found for firewall {fw_name} with policies: {', '.join(policy_names)}")
                    continue
                
                # Log the files being deployed
                policy_filenames = [os.path.basename(f) for f in fw_files]
                logging.info(f"Deploying {len(fw_files)} Bicep file(s) for {fw_name}: {', '.join(policy_filenames)}")
                
                # Get deployment parameters for this firewall
                subscription_id = fw.get("policiesSubscriptionId", "")
                tenant_id = fw.get("tenantId", "")
                policies_rg = fw.get("policiesResourceGroup", "")
                
                # Add each file as a separate job
                for file in fw_files:
                    all_deployment_jobs.append({
                        'file': file,
                        'firewall_name': fw_name,
                        'subscription_id': subscription_id,
                        'tenant_id': tenant_id,
                        'resource_group': policies_rg
                    })
            
            if not all_deployment_jobs:
                logging.warning("No files to deploy for any firewall")
                if not args.non_interactive:
                    print("\nWARNING: No files to deploy for any firewall.")
                return 1
            
            # Deploy all files across all firewalls in parallel
            operation = "what-if" if whatif_mode else "deployment"
            logging.info(f"Running parallel {operation} for {len(all_deployment_jobs)} file(s) across {len(firewalls_data)} firewall(s)...")
            if not args.non_interactive:
                print(f"\n🚀 Running parallel {operation} for {len(all_deployment_jobs)} file(s) across all firewalls...")
            
            try:
                complete_mode = hasattr(args, 'complete_mode') and args.complete_mode
                result = AzureDeploy.deploy_resources_parallel_all(
                    all_deployment_jobs,
                    git_id,
                    complete_mode,
                    whatif_mode
                )
                
                # Handle different return types: bool for whatif, tuple for deployment
                if whatif_mode:
                    success = result
                    error_details = []
                else:
                    success, error_details = result
                
                if success:
                    deployed_count = len(all_deployment_jobs)
                    logging.info(f"Parallel {operation} completed successfully")
                    print(f"\n✅ Parallel {operation} completed successfully")
                else:
                    all_success = False
                    deployed_count = len(all_deployment_jobs) - len(error_details)
                    logging.warning(f"Parallel {operation} completed with {len(error_details)} error(s)")
                    print(f"\n⚠️ Parallel {operation} completed with {len(error_details)} error(s)")
                    
                    # Log error details for failed deployments
                    if error_details:
                        for error in error_details:
                            logging.error(f"  - {error}")
                            print(f"  ERROR: {error}")
                        
            except ValueError as e:
                all_success = False
                logging.error(f"Parallel {operation} failed: {str(e)}")
                print(f"\nParallel {operation} failed: {str(e)}")
        
        # SEQUENTIAL MODE: Deploy firewalls one by one, with per-file confirmation
        else:
            for fw in firewalls_data:
                fw_name = fw.get("firewallName", "")
                if not fw_name:
                    logging.warning("Skipping firewall with no name")
                    continue
                
                logging.info(f"Processing firewall: {fw_name}")
                
                # Get policy names for this firewall
                policy_names_raw = fw.get("policiesName", [])
                if not policy_names_raw:
                    logging.warning(f"No policies defined for firewall: {fw_name}")
                    continue
                
                # Convert to list if it's a dict with integer keys
                if isinstance(policy_names_raw, dict):
                    policy_names = [policy_names_raw[k] for k in sorted(policy_names_raw.keys())]
                elif isinstance(policy_names_raw, str):
                    policy_names = [policy_names_raw]
                else:
                    policy_names = policy_names_raw
                
                # Filter selected files to only include those matching this firewall's policies
                fw_files = []
                for file in selected_files:
                    file_name_no_ext = os.path.splitext(os.path.basename(file))[0]
                    if any(policy_name in file_name_no_ext for policy_name in policy_names):
                        fw_files.append(file)
                
                if not fw_files:
                    logging.warning(f"No matching Bicep files found for firewall {fw_name} with policies: {', '.join(policy_names)}")
                    continue
                
                # Log the files being deployed
                policy_filenames = [os.path.basename(f) for f in fw_files]
                logging.info(f"Deploying {len(fw_files)} Bicep file(s) for {fw_name}: {', '.join(policy_filenames)}")
                
                # Get deployment parameters
                subscription_id = fw.get("policiesSubscriptionId", "")
                tenant_id = fw.get("tenantId", "")
                policies_rg = fw.get("policiesResourceGroup", "")
                
                # Deploy resources for this firewall
                operation = "what-if" if whatif_mode else "deployment"
                logging.info(f"Running {operation} for {len(fw_files)} file(s)...")
                if not args.non_interactive:
                    print(f"\nRunning {operation} for {fw_name}: {len(fw_files)} file(s)...")
                
                try:
                    complete_mode = hasattr(args, 'complete_mode') and args.complete_mode
                    result = AzureDeploy.deploy_resources(
                        fw_files, 
                        subscription_id, 
                        tenant_id, 
                        git_id, 
                        policies_rg, 
                        complete_mode, 
                        whatif_mode,
                        parallel_mode  # Will be False in sequential mode
                    )
                    
                    # Handle different return types: bool for whatif, tuple for deployment
                    if whatif_mode:
                        success = result
                        error_details = []
                    else:
                        success, error_details = result
                    
                    if success:
                        deployed_count += 1
                        logging.info(f"{operation.capitalize()} completed successfully for {fw_name}")
                        print(f"\n{operation.capitalize()} completed successfully for {fw_name}")
                    else:
                        all_success = False
                        logging.warning(f"{operation.capitalize()} completed with warnings or errors for {fw_name}")
                        print(f"\n{operation.capitalize()} completed with warnings or errors for {fw_name}")
                        
                        # Log error details for failed deployments
                        if error_details:
                            for error in error_details:
                                logging.error(f"  - {error}")
                                print(f"  ERROR: {error}")
                            
                except ValueError as e:
                    all_success = False
                    logging.error(f"{operation.capitalize()} failed for {fw_name}: {str(e)}")
                    print(f"\n{operation.capitalize()} failed for {fw_name}: {str(e)}")
        
        if deployed_count == 0:
            logging.warning("No policies were deployed for any firewall")
            if not args.non_interactive:
                print("\nWARNING: No policies were deployed for any firewall.")
            return 1
        
        if all_success:
            logging.info("Bicep deployment completed successfully")
            if not args.non_interactive:
                print("\nBicep deployment completed successfully.")
            return 0
        else:
            logging.warning("Bicep deployment completed with warnings or errors")
            if not args.non_interactive:
                print("\nBicep deployment completed with warnings or errors. Check the logs for details.")
            return 1
            
    except Exception as e:
        logging.error(f"Error during Bicep deployment: {str(e)}", exc_info=True)
        if not args.non_interactive:
            print(f"\nError during Bicep deployment: {str(e)}")
        return 1

def handle_compare_arm(args):
    """
    Handle the comparison of local YAML policies with Azure-deployed policies.
    
    This function orchestrates the comparison workflow:
    1. Select firewall environment (interactive or from args)
    2. Extract policy information from firewall YAML
    3. Download ARM templates from Azure (via AzureDownload)
    4. Normalize ARM JSON to standard structure
    5. Load local YAML policies
    6. Compare policies with identity-based matching
    7. Generate Markdown comparison report in root directory
    
    Args:
        args: Command line arguments
        
    Returns:
        int: Exit code (0 = success, 1 = failure)
    """
    
    logging.info("Starting policy comparison workflow...")
    
    try:
        # Step 0: Get firewall selection
        if args.non_interactive:
            if not args.firewall:
                print("Error: Firewall must be specified in non-interactive mode")
                return 1
            environment_name = args.firewall
        else:
            # Interactive mode - prompt for firewall selection
            print("\nSelect firewall for policy comparison...")
            
            # Get list of available firewalls
            environments, error_msg = CommonConfiguration.get_available_environments()
            if error_msg:
                print(f"\nError: {error_msg}")
                return 1
            
            # Format environment for display
            def env_formatter(index, env_tuple):
                idx, env_name, _ = env_tuple
                return f"{env_name}"
            
            # Use CommonInteraction for selection
            selected_env, action = CommonInteraction.prompt_user_selection(
                items=environments,
                prompt_message="Available firewall environments",
                item_formatter=env_formatter,
                allow_cancel=True,
                allow_skip=False,
                allow_text_input=False
            )
            
            if action == 'cancelled' or not selected_env:
                logging.info("Environment selection cancelled by user")
                return 1
            
            # Extract environment name from selected tuple
            _, environment_name, _ = selected_env
        
        print(f"\n🔥 Selected firewall: {environment_name}")
        
        # Load firewall configuration to get policy information
        logging.info(f"Loading firewall configuration for: {environment_name}")
        firewall_data, error_msg = CommonConfiguration.get_environment(
            environment_name,
            load_yaml=True,
            prod_firewall=True,  # Get single production firewall
            required_fields=['policiesName', 'policiesResourceGroup', 'policiesSubscriptionId']
        )
        
        if error_msg or not firewall_data:
            logging.error(f"Failed to load firewall configuration: {error_msg}")
            print(f"\n❌ Error: {error_msg}")
            return 1
        
        # Extract policy information from firewall YAML
        policies_name_dict = firewall_data.get('policiesName', {})
        
        # Handle both dict and list formats for policiesName
        if isinstance(policies_name_dict, dict):
            # Get the first policy (index 0)
            policy_name = policies_name_dict.get(0) or policies_name_dict.get('0')
        elif isinstance(policies_name_dict, list):
            policy_name = policies_name_dict[0] if policies_name_dict else None
        else:
            policy_name = policies_name_dict
        
        if not policy_name:
            logging.error("No policy name found in firewall configuration")
            print("\n❌ Error: No policy name found in firewall configuration")
            return 1
        
        policy_resource_group = firewall_data.get('policiesResourceGroup')
        policy_subscription_id = firewall_data.get('policiesSubscriptionId')
        tenant_id = firewall_data.get('tenantId')
        
        print(f"📋 Policy: {policy_name}")
        print(f"📁 Resource Group: {policy_resource_group}")
        print(f"🔑 Subscription: {policy_subscription_id}")
        
        # Ensure Azure authentication before downloading
        logging.info("Ensuring Azure authentication...")
        try:
            AzureCommon.ensure_azure_login(policy_subscription_id, tenant_id)
        except ValueError as e:
            logging.error(f"Azure login failed: {str(e)}")
            print(f"\n❌ Error: Azure login failed: {str(e)}")
            return 1
        
        # Step 1: Download ARM template from Azure
        logging.info("Step 1: Downloading ARM template from Azure...")
        print("\n📥 Downloading policy from Azure...")
        
        # Clean the ARM directory before downloading new template
        logging.info("Cleaning ARM directory before downloading new template...")
        CommonFile.clean_directory(Paths.ARM_DIR)
        
        # Download ARM template for the environment
        success, message = AzureDownload.download_arm_template(environment_name)
        
        if not success:
            logging.error(f"Failed to download ARM template: {message}")
            print(f"\n❌ Error: {message}")
            # Delete ARM import directory even on failure
            if CommonFile.delete_directory(Paths.ARM_DIR):
                logging.info("ARM import directory deleted")
            return 1
        
        print(f"✅ {message}")
        
        # Find the downloaded ARM file
        arm_files = glob.glob(os.path.join(Paths.ARM_DIR, "*.json"))
        if not arm_files:
            logging.error("No ARM template files found after download")
            print("\n❌ Error: No ARM template files found after download")
            if CommonFile.delete_directory(Paths.ARM_DIR):
                logging.info("ARM import directory deleted")
            return 1
        
        # Use the first ARM file (should be the policy we downloaded)
        arm_file_path = arm_files[0]
        logging.info(f"Using ARM template: {arm_file_path}")
        
        # Step 2: Normalize ARM template
        logging.info("Step 2: Normalizing ARM template...")
        print("\n🔄 Normalizing ARM template...")
        
        azure_policy = ComparePolicy.normalize_arm_template(arm_file_path)
        if not azure_policy:
            logging.error("Failed to normalize ARM template")
            print("\n❌ Error: Failed to parse ARM template")
            return 1
        
        print(f"✅ Normalized Azure policy: {azure_policy['name']}")
        
        # Step 3: Load local YAML policy
        logging.info("Step 3: Loading local YAML policy...")
        print("\n📂 Loading local YAML policy...")
        
        # Build path to YAML policy directory
        policy_dir = os.path.join(Paths.POLICIES_DIR, policy_name)
        
        if not os.path.exists(policy_dir):
            logging.error(f"Local policy directory not found: {policy_dir}")
            print(f"\n❌ Error: Local policy directory not found: {policy_dir}")
            return 1
        
        local_policy = ComparePolicy.load_policy_from_yaml(policy_dir)
        if not local_policy:
            logging.error("Failed to load local YAML policy")
            print("\n❌ Error: Failed to parse local YAML policy")
            return 1
        
        print(f"✅ Loaded local policy: {local_policy['name']}")
        
        # Step 4: Compare policies
        logging.info("Step 4: Comparing policies...")
        print("\n🔍 Comparing local vs Azure policies...")
        
        comparison_result = ComparePolicy.compare_policies(local_policy, azure_policy)
        if not comparison_result:
            logging.error("Failed to compare policies")
            print("\n❌ Error: Failed to compare policies")
            return 1
        
        # Display summary
        summary = comparison_result['summary']
        print(f"✅ Comparison complete:")
        print(f"   - 🟢 Added: {summary['added']} RCGs")
        print(f"   - 🔴 Deleted: {summary['deleted']} RCGs")
        print(f"   - 🟡 Modified: {summary['modified']} RCGs")
        
        # Step 5: Generate comparison report
        logging.info("Step 5: Generating comparison report...")
        print("\n📝 Generating comparison report...")
        
        # Save to root directory as CHANGES.md
        output_file = os.path.join(Paths.INVENTORY_PATH, "CHANGES.md")
        
        if ComparePolicy.generate_comparison_report(comparison_result, output_file):
            print(f"✅ Comparison report saved to: {output_file}")
            logging.info(f"Comparison report saved to: {output_file}")
            
            # Clean up downloaded ARM directory
            logging.info("Deleting ARM import directory after successful comparison...")
            if CommonFile.delete_directory(Paths.ARM_DIR):
                print("🗑️  ARM import directory deleted")
            else:
                print("⚠️  Warning: Failed to delete ARM import directory")
            
            print("\n✨ Comparison workflow completed successfully!")
            return 0
        else:
            logging.error("Failed to generate comparison report")
            print("\n❌ Error: Failed to generate comparison report")
            return 1
            
    except Exception as e:
        logging.error(f"Error during comparison workflow: {str(e)}", exc_info=True)
        print(f"\n❌ Error during comparison: {str(e)}")
        return 1
        return 1

def handle_commit_repository(args):
    """
    Handle the commit operation for the repository.
    
    This function commits all changes to the Git repository, 
    prompting the user for a commit message.
    
    Args:
        args: Command line arguments
        
    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    try:
        logging.info("Starting repository commit...")
        
        if args.skip_git:
            logging.info("Skipping Git operations as requested")
            return 0
        
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
                    return 0
        
        # Generate current datetime string
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Get commit suffix directly from get_id_with_date
            random_id = CommonData.get_id_with_date()
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
            
            commit_success = commit_changes_to_git(formatted_commit_message)
        except ValueError as e:
            error_message = str(e)
            logging.error(f"Failed to generate commit ID: {error_message}")
            if not args.non_interactive:
                print(f"\nERROR: Failed to generate commit ID: {error_message}")
                print("\nPlease run a policy sync operation and try again.")
            return 1
        
        if commit_success:
            logging.info(f"Changes committed successfully with ID: {random_id}")
            if not args.non_interactive:
                print(f"\nChanges committed successfully with ID: {random_id}")
            return 0
        else:
            logging.error("Failed to commit changes to Git repository")
            if not args.non_interactive:
                print("\nFailed to commit changes to Git repository. Check the logs for details.")
            return 1
            
    except Exception as e:
        logging.error(f"Error during repository commit: {str(e)}", exc_info=True)
        if not args.non_interactive:
            print(f"\nError during repository commit: {str(e)}")
        return 1

def handle_assign_policy(args):
    """
    Handle the workflow for assigning Azure Firewall Policies to Azure Firewalls.
    
    This function:
    1. Gets the environment configuration with all firewalls
    2. For each firewall in the environment:
       a. Ensures Azure login with firewall's subscription and tenant
       b. Gets firewall resource details
       c. Shows current policy assignment for the firewall
       d. Lists available policies in the firewall's policy resource group
       e. Lets the user assign a policy to the firewall
    
    Args:
        args: Command line arguments
        
    Returns:
        int: Exit code (0 for success, non-zero for errors)
    """
    logging.info("Starting policy assignment workflow...")
    
    # 1. Determine firewall
    environment_name = None
    
    if args.non_interactive:
        if not hasattr(args, 'firewall') or not args.firewall:
            logging.error("Firewall must be specified in non-interactive mode")
            return 1
        
        environment_name = args.firewall
    else:
        # Interactive firewall selection
        if hasattr(args, 'firewall') and args.firewall:
            environment_name = args.firewall
        else:
            print("\nSelect firewall for policy assignment...")
            
            # Get list of available firewalls
            environments, error_msg = CommonConfiguration.get_available_environments()
            if error_msg:
                print(f"\nError: {error_msg}")
                return 1
            
            # Format firewall for display
            def env_formatter(index, env_tuple):
                idx, env_name, _ = env_tuple
                return f"{env_name}"
            
            # Use CommonInteraction for selection
            selected_env, action = CommonInteraction.prompt_user_selection(
                items=environments,
                prompt_message="Available firewall environments",
                item_formatter=env_formatter,
                allow_cancel=True,
                allow_skip=False,
                allow_text_input=False
            )
            
            if action == 'cancelled' or not selected_env:
                logging.info("Environment selection cancelled by user")
                return 1
            
            # Extract environment name from selected tuple
            _, environment_name, _ = selected_env
    
    # Get environment data - returns a list of firewall configurations
    firewalls_data, error_msg = CommonConfiguration.get_environment(
        environment_name=environment_name,
        load_yaml=True
    )
    
    if not firewalls_data:
        logging.error("Failed to get environment configuration")
        return 1
    
    if not isinstance(firewalls_data, list):
        logging.error("Unexpected environment data format")
        return 1
    
    # Show available firewalls from the environment
    print(f"\nFound {len(firewalls_data)} firewalls in the environment:")
    for i, fw in enumerate(firewalls_data, 1):
        fw_name = fw.get('firewallName', 'Unknown')
        region = fw.get('regionName', 'Unknown')
        rg = fw.get('firewallResourceGroup', 'Unknown')
        print(f"{i}. {fw_name} (Region: {region}, Resource Group: {rg})")
    
    # 2. Process each firewall in the environment
    for fw_index, fw_config in enumerate(firewalls_data, 1):
        fw_name = fw_config.get('firewallName', '')
        if not fw_name:
            logging.warning(f"Skipping firewall at index {fw_index} with no name")
            continue
        
        subscription_id = fw_config.get('policiesSubscriptionId', '')
        firewall_subscription_id = fw_config.get('firewallSubscriptionId', '')
        tenant_id = fw_config.get('tenantId', '')
        resource_group = fw_config.get('firewallResourceGroup', '')
        policies_resource_group = fw_config.get('policiesResourceGroup', '')
        
        print(f"\n{'='*80}")
        print(f"Processing firewall {fw_index}/{len(firewalls_data)}: {fw_name}")
        print(f"{'='*80}")
        print(f"  Policies Subscription ID: {subscription_id}")
        print(f"  Firewall Subscription ID: {firewall_subscription_id}")
        print(f"  Firewall Resource Group: {resource_group}")
        print(f"  Policies Resource Group: {policies_resource_group}")
        
        if not subscription_id or not firewall_subscription_id or not resource_group or not policies_resource_group:
            logging.error(f"Firewall {fw_name} configuration is missing required properties")
            print("Skipping to next firewall...")
            continue
        
        # 3.1 Ensure user is logged into Azure with the correct subscription
        try:
            AzureCommon.ensure_azure_login(firewall_subscription_id, tenant_id)
        except ValueError as e:
            logging.error(f"Azure login failed for firewall {fw_name}: {str(e)}")
            print(f"\nError: Azure login failed for firewall {fw_name}: {str(e)}")
            print("Skipping to next firewall...")
            continue
        
        # 3.2 Get the actual firewall resource details
        firewalls = AzureAssign.get_firewalls_in_resource_group(firewall_subscription_id, resource_group, tenant_id)
        
        if not firewalls:
            logging.error(f"No firewalls found in resource group {resource_group}")
            print("Skipping to next firewall...")
            continue
        
        # Find the specific firewall in the resource group
        selected_fw = None
        for fw in firewalls:
            if fw['name'].lower() == fw_name.lower():
                selected_fw = fw
                break
        
        if not selected_fw:
            logging.error(f"Firewall '{fw_name}' not found in resource group {resource_group}")
            print("Skipping to next firewall...")
            continue
        
        # 3.3 Get the current policy assignment
        current_policy = AzureAssign.get_current_policy_assignment(
            firewall_subscription_id, 
            resource_group, 
            selected_fw['name'],
            tenant_id
        )
        
        if current_policy:
            print(f"\nCurrent policy assigned to {selected_fw['name']}: {current_policy['name']}")
        else:
            print(f"\nNo policy currently assigned to {selected_fw['name']}")
        
        # 3.4 Get available policies from the policies resource group
        policies = AzureCommon.get_policies_in_resource_group(subscription_id, policies_resource_group, tenant_id)
        
        if not policies:
            logging.error(f"No firewall policies found in resource group {policies_resource_group}")
            print("Skipping to next firewall...")
            continue
        
        # Show available policies
        print(f"\nAvailable Azure Firewall Policies in resource group {policies_resource_group}:")
        for i, policy in enumerate(policies, 1):
            print(f"{i}. {policy['name']}")
        
        # 3.5 Let user select a policy to assign
        selected_policy_index = None
        if args.non_interactive if hasattr(args, 'non_interactive') else False:
            if hasattr(args, 'policy_name') and args.policy_name:
                # Find the policy by name in non-interactive mode
                for i, policy in enumerate(policies):
                    if policy['name'].lower() == args.policy_name.lower():
                        selected_policy_index = i
                        break
                
                if selected_policy_index is None:
                    logging.error(f"Policy '{args.policy_name}' not found in resource group {policies_resource_group}")
                    print("Skipping to next firewall...")
                    continue
            else:
                logging.error("Non-interactive mode requires --policy-name parameter")
                return 1
        else:
            # Interactive selection
            continue_to_next = False
            while True:
                try:
                    choice = input(f"\nSelect a policy to assign to {fw_name} (number), 's' to skip this firewall, or 'q' to quit: ")
                    if choice.lower() == 'q':
                        logging.info("Operation cancelled by user")
                        return 0
                    elif choice.lower() == 's':
                        logging.info(f"Skipping firewall {fw_name}")
                        continue_to_next = True
                        break
                    
                    selected_policy_index = int(choice) - 1
                    if 0 <= selected_policy_index < len(policies):
                        break
                    else:
                        print("Invalid selection. Please try again.")
                except ValueError:
                    print("Please enter a valid number, 's', or 'q'.")
            
            if continue_to_next:
                continue
        
        selected_policy = policies[selected_policy_index]
        logging.info(f"Selected policy: {selected_policy['name']} for firewall {fw_name}")
        
        # 3.6 Confirm assignment
        proceed_with_assignment = True
        if not (args.non_interactive if hasattr(args, 'non_interactive') else False):
            confirm = input(f"\nAssign policy '{selected_policy['name']}' to firewall '{selected_fw['name']}'? (y/n): ")
            if confirm.lower() != 'y':
                logging.info(f"Assignment cancelled for firewall {fw_name}")
                proceed_with_assignment = False
        
        if proceed_with_assignment:
            # 3.7 Assign the policy
            success = AzureAssign.assign_policy_to_firewall(
                firewall_subscription_id,
                resource_group,
                selected_fw['name'],
                selected_policy['id'],
                tenant_id
            )
            
            if success:
                logging.info(f"Successfully assigned policy '{selected_policy['name']}' to firewall '{selected_fw['name']}'")
                print(f"\nSuccess: Assigned policy '{selected_policy['name']}' to firewall '{selected_fw['name']}'")
            else:
                logging.error(f"Failed to assign policy '{selected_policy['name']}' to firewall '{selected_fw['name']}'")
                print(f"\nError: Failed to assign policy '{selected_policy['name']}' to firewall '{selected_fw['name']}'")
    
    print("\nPolicy assignment workflow completed.")
    return 0

