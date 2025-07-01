#!/usr/bin/env python3
"""
Azure Firewall Policy Manager

This script provides a management interface for Azure Firewall Policies,
enabling importing, exporting, synchronizing, and deploying firewall policies.
"""

import sys
import logging
# Update imports to use direct libraries path
from src.libraries.CommonUtils import configure_logging
from src.libraries.OrchestratorUtils import (
    print_header,
    handle_update_repository,
    handle_import_policies,
    handle_sync_policies,
    handle_export_policies,
    handle_download_templates,
    handle_compare_arm,
    handle_deploy_bicep,
    handle_commit_repository
)
from src.libraries.Parameters import parse_arguments, list_available_environments

# Configure logging
configure_logging()

def main():
    """
    Main function to manage Azure Firewall policies.
    
    Provides a simple interface to choose between importing policies from ARM templates,
    exporting policies to Bicep templates, synchronizing policies between formats,
    updating the local repository, or deploying Bicep templates.
    """
    args = parse_arguments()
    
    # Configure verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled")
    
    # Check if user just wants to list environments
    if args.list_environments:
        list_available_environments()
        return 0
    
    # Non-interactive mode requires both environment and operation
    if args.non_interactive:
        if not args.operation:
            print("Error: Non-interactive mode requires the --operation parameter")
            print("Use --help for more information")
            return 1
        # When in non-interactive mode and sync operation (4) is selected, conflict resolution should be specified
        if (args.operation == 4) and not args.conflict_resolution:
            print("Warning: When running sync in non-interactive mode, --conflict-resolution is recommended")
            # Continue anyway, as the function will use a default behavior
    
    # In interactive mode, show the header
    if not args.non_interactive:
        print_header()
      # If operation specified via command line, execute it directly
    if args.operation:
        choice = str(args.operation)
    else:        # Otherwise show menu
        print("\nSelect an operation:")
        print("1. Update local Git repository")
        print("2. Download the latest ARM templates")
        print("3. Import policies from ARM templates")
        print("4. Synchronize policies between YAML and CSV")
        print("5. Export policies to Bicep")
        print("6. Compare ARM Templates (Import vs Export)")
        print("7. Commit all changes to Git")
        print("8. Deploy new Bicep to Azure")
        
        choice = input("\nSelect operation (1-8): ")    # Process the operation choice
    if choice == "1":
        return handle_update_repository(args)
    
    elif choice == "2":
        return handle_download_templates(args)
    
    elif choice == "3":
        return handle_import_policies(args)
    
    elif choice == "4":
        return handle_sync_policies(args)
    
    elif choice == "5":
        return handle_export_policies(args)
    
    elif choice == "6":
        return handle_compare_arm(args)
    
    elif choice == "7":
        return handle_commit_repository(args)
    
    elif choice == "8":
        return handle_deploy_bicep(args)
    
    else:
        print("Invalid choice. Please select a number between 1 and 8.")
        return 1


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