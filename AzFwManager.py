#!/usr/bin/env python3
"""
Azure Firewall Policy Manager

This script provides a management interface for Azure Firewall Policies,
enabling importing, exporting, synchronizing, and deploying firewall policies.
"""

import sys
import logging
# Update imports to use direct libraries path
from scripts.libraries.CommonUtils import configure_logging
from scripts.libraries.OrchestratorUtils import (
    print_header,
    handle_update_repository,
    handle_import_policies,
    handle_sync_policies,
    handle_export_policies
)
from scripts.libraries.Parameters import parse_arguments, get_environment_from_cmdline, list_available_environments

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
        # When in non-interactive mode and sync operation (3) is selected, conflict resolution should be specified
        if (args.operation == 3 or args.operation == 4) and not args.conflict_resolution:
            print("Warning: When running sync in non-interactive mode, --conflict-resolution is recommended")
            # Continue anyway, as the function will use a default behavior
    
    # In interactive mode, show the header
    if not args.non_interactive:
        print_header()
    
    # If operation specified via command line, execute it directly
    if args.operation:
        choice = str(args.operation)
    else:
        # Otherwise show menu
        print("\nSelect an operation:")
        print("1. Update your local repository")
        print("2. Import policies from ARM templates")
        print("3. Synchronize policies between YAML and CSV")
        print("4. Export policies to Bicep")
        
        choice = input("\nSelect operation (1-4): ")

    # Process the operation choice
    if choice == "1":
        return handle_update_repository(args)
    
    elif choice == "2":
        return handle_import_policies(args)
    
    elif choice == "3":
        return handle_sync_policies(args)
    
    elif choice == "4":
        return handle_export_policies(args)
    
    else:
        print("Invalid choice. Please select a number between 1 and 4.")
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