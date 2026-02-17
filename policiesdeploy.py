#!/usr/bin/env python3
"""
Azure Firewall Policy Manager

This script provides a management interface for Azure Firewall Policies,
enabling importing, exporting, synchronizing, and deploying firewall policies.
"""
import logging
import sys

# Version information
__version__ = "1.3"
from src.libraries.CommonUtils import CommonConfiguration
from src.libraries.OrchestratorUtils import handle_assign_policy, handle_commit_repository, handle_compare_arm, handle_deploy_bicep, handle_download_templates, handle_export_policies, handle_git_branch, handle_import_policies, handle_sync_policies, handle_update_repository, print_header
from src.libraries.Parameters import Paths, Config, parse_arguments

# Configure logging
CommonConfiguration.configure_logging()

def main():
    """
    Main function to manage Azure Firewall policies.
    
    Provides a simple interface to choose between importing policies from ARM templates,
    exporting policies to Bicep templates, synchronizing policies between formats,
    updating the local repository, or deploying Bicep templates.
    """
    args = parse_arguments()
    
    # Set Windows list separator to semicolon for CSV compatibility
    # CommonConfiguration.set_list_separator(Config.SEPARATOR)
    
    # Check if user just wants to see the version
    if args.version:
        print(f"PoliFire (Azure Firewall Policy Manager) version {__version__}")
        return 0
    
    # Initialize paths when module is imported
    try:
        Paths.ensure_directories_exist()
    except Exception as e:
        logging.warning(f"Failed to create one or more directories: {str(e)}")
        
    # Configure verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled")
    
    # Check if user just wants to list firewalls
    if args.list_firewall:
        # List the available firewalls
        print("\nAvailable firewall environments:")
        environments, error_msg = CommonConfiguration.get_available_environments()
        if error_msg:
            print(f"\nError: {error_msg}")
            return 1
        
        for idx, env_name, _ in environments:
            print(f"{idx}. {env_name}")
        return 0
    
    # Handle specific operations if provided via command line
    # These bypass the interactive menu
    
    # Git operations
    if args.git_branch:
        logging.info(f"Executing git branch switch: {args.git_branch}")
        return handle_git_branch(args)
    
    if args.git_update:
        logging.info("Executing git update")
        return handle_update_repository(args)
    
    if args.git_save:
        logging.info(f"Executing git save: {args.git_save}")
        args.commit_message = args.git_save
        return handle_commit_repository(args)
    
    # Download/Import operations
    if args.download:
        logging.info("Executing download policies")
        return handle_download_templates(args)
    
    if args.import_policies:
        logging.info("Executing import policies")
        return handle_import_policies(args)
    
    # Synchronize operation
    if args.synchronize:
        logging.info("Executing synchronize policies")
        return handle_sync_policies(args)
    
    # Export/Deploy operations
    if args.export:
        logging.info("Executing export policies")
        return handle_export_policies(args)
    
    if args.compare:
        logging.info("Executing compare policies")
        return handle_compare_arm(args)
    
    if args.deploy:
        logging.info("Executing deploy bicep")
        return handle_deploy_bicep(args)
    
    if args.assign:
        logging.info("Executing assign policy")
        return handle_assign_policy(args)
    
    # If no operation specified, enter interactive mode
    # Only loop if --loop parameter is provided
    run_once = not args.loop
    
    while True:
        # In interactive mode, show the header
        print_header()
        
        # Show menu
        print("\n" + "="*40)
        print("🛠️  Select an Operation")
        print("="*40)
        print("🔧 GIT Operations")
        print("1. Select Firewall Branch")
        print("2. Update local Git from Azure DevOps")
        print("3. Save all change to Azure DevOps")
        print("📥 Import from Azure")
        print("4. Download current active policy from Azure Firewall")
        print("5. Synchronize policies between YAML and CSV")
        print("🚀 Deploy to Azure")
        print("6. Export policies to Bicep")
        print("7. Compare created bicep with current active policy from Azure Firewall")
        print("8. Deploy created bicep to Azure")
        print("9. Assign policy to Firewall")
        print("❌ Quit")
        print("10. Quit (q)")
        print("="*40)

        choice = input("\nSelect operation (1-10 or q): ")
        # Quit options should break out of the loop
        # If not in loop mode, always break out of the loop after executing an operation
        should_break = choice.lower() in ["q", "quit", "10"] or run_once
        
        # Process the operation choice
        exit_code = 0
        
        if choice == "1":
            exit_code = handle_git_branch(args)
            
        elif choice == "2":
            exit_code = handle_update_repository(args)
        
        elif choice == "3":
            exit_code = handle_commit_repository(args)
        
        elif choice == "4":
            exit_code = handle_download_templates(args)
        
        elif choice == "5":
            exit_code = handle_sync_policies(args)
        
        elif choice == "6":
            exit_code = handle_export_policies(args)
        
        elif choice == "7":
            exit_code = handle_compare_arm(args)
        
        elif choice == "8":
            exit_code = handle_deploy_bicep(args)
        
        elif choice == "9":
            exit_code = handle_assign_policy(args)
        
        elif choice.lower() in ["q", "quit", "10"]:
            print("👋 Exiting... Goodbye!")
            return 0
        
        else:
            print("Invalid choice. Please select a number between 1 and 10 or 'q' to quit.")
            exit_code = 1
        
        # In non-interactive mode or if the user chose to quit, break out of the loop
        if should_break:
            return exit_code
        
    # End of while loop
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        logging.warning("Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {str(e)}")
        logging.exception("An unexpected error occurred")
        sys.exit(1)