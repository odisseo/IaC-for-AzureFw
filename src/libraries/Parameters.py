import argparse
import logging
import os
import sys
import platform

##########################################################################
# Global Variables
##########################################################################

def get_inventory_path():
    """Get the inventory repository path from command line argument or default to current working directory."""
    # This will be set by parse_arguments() when --inventory-path is provided
    return getattr(get_inventory_path, '_inventory_path', os.getcwd())

def set_inventory_path(path):
    """Set the inventory repository path."""
    if path:
        get_inventory_path._inventory_path = os.path.abspath(path)
    
# Project directory structure
class Paths:
    DEFAULT_LOCATION = 'westeurope'
    # Templates directory is relative to this file's location (works for both .py and .exe)
    TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'templates')
    INVENTORY_PATH = get_inventory_path()  # New: path to inventory repository
    
    # Folder names (relative to policies directory)
    POLICIES_FOLDER_NAME = 'yaml'
    CSV_FOLDER_NAME = 'csv'
    
    # Base directories - using INVENTORY_PATH for data directories
    ARM_DIR = os.path.join(INVENTORY_PATH, 'arm_import')  # ARM import directory
    ARM_EXPORT_DIR = os.path.join(INVENTORY_PATH, 'arm_export')  # Directory for exported ARM templates
    POLICIES_DIR = os.path.join(INVENTORY_PATH, 'policies', POLICIES_FOLDER_NAME)
    CSV_DIR = os.path.join(INVENTORY_PATH, 'policies', CSV_FOLDER_NAME)
    BICEP_DIR = os.path.join(INVENTORY_PATH, 'bicep')
    FIREWALLS_DIR = os.path.join(INVENTORY_PATH, 'firewalls')
    RESOURCE_GROUPS_DIR = os.path.join(INVENTORY_PATH, '_resourceGroups')  # New directory for resource groups
    IPGROUPS_DIR = os.path.join(INVENTORY_PATH, '_ipgroups')  # Directory for IP groups
    COMPARISON_DIR = os.path.join(INVENTORY_PATH, 'comparison')  # Directory for comparison results
    LOCK_FILE = os.path.join(INVENTORY_PATH, '.lock')  # Lock file for tracking changes
    
    # Template files are relative to TEMPLATES_DIR (which is relative to this file's location)
    TEMPLATE_COMPARISON = os.path.join(TEMPLATES_DIR, 'comparisonPretty.txt.jinja2')
    TEMPLATE_CSV = os.path.join(TEMPLATES_DIR, 'policy.csv.jinja2')
    TEMPLATE_POLICY_BICEP = os.path.join(TEMPLATES_DIR, 'policy.bicep.jinja2')
    TEMPLATE_POLICY_YAML = os.path.join(TEMPLATES_DIR, 'policy.yaml.jinja2')
    TEMPLATE_RCG_YAML = os.path.join(TEMPLATES_DIR, 'rcg.yaml.jinja2')
    TEMPLATE_RC_YAML = os.path.join(TEMPLATES_DIR, 'rc.yaml.jinja2')
    TEMPLATE_NAT = os.path.join(TEMPLATES_DIR, 'nat_rules.csv.jinja2')
    TEMPLATE_NETWORK = os.path.join(TEMPLATES_DIR, 'network_rules.csv.jinja2')
    TEMPLATE_APPLICATION = os.path.join(TEMPLATES_DIR, 'application_rules.csv.jinja2')
    TEMPLATE_IPGROUPS_BICEP = os.path.join(TEMPLATES_DIR, 'ipgroups.bicep.jinja2')

    # Ensure all directories exist
    @staticmethod
    def ensure_directories_exist():
        """
        Create all required directories if they don't exist.
        """
        directories = [
            Paths.POLICIES_DIR,
            Paths.CSV_DIR, 
            Paths.BICEP_DIR,
            Paths.FIREWALLS_DIR,
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            
        return True

# Default configuration
class Config:
    # BICEP API Version
    FIREWALL_API_VERSION = "2024-07-01"
    
    # Default firewall name
    FIREWALL_NAME = os.getenv('FIREWALL_NAME', 'DEFAULT')
    
    # Log settings
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # Azure settings
    DEFAULT_LOCATION = os.getenv('AZURE_LOCATION', 'westeurope')
    DEFAULT_SUBSCRIPTION = os.getenv('AZURE_SUBSCRIPTION_ID', 'bca4dc33-1167-40aa-930c-0c0da34be971')
    DEFAULT_TENANT = os.getenv('AZURE_TENANT_ID', '088e9b00-ffd0-458e-bfa1-acf4c596d3cb')
    
    # Service Account / Managed Identity settings
    # Set to True when running in Azure Pipeline or Automation Account with Managed Identity
    USE_MANAGED_IDENTITY = os.getenv('USE_MANAGED_IDENTITY', 'false').lower() in ('true', '1', 'yes')
    
    # Subprocess shell setting (True on Windows, False on other platforms)
    IS_WINDOWS = platform.system().lower() == 'windows'
    USE_SHELL_IN_SUBPROCESS = IS_WINDOWS
    
    # Default firewall environment (index 1) - lazy loaded via property
    _default_firewall = None
    
    SEPARATOR = ";"

############################################################################
# In line parameters
############################################################################

def parse_arguments():
    """Parse command line arguments with detailed help information."""
    parser = argparse.ArgumentParser(
        description='''PoliFire (Azure Firewall Policies Infrastructure as Code)
        
This tool provides a complete workflow for managing Azure Firewall Policies using YAML files as the source of truth,
with conversion to/from CSV and ARM/Bicep templates for deployment to Azure. 

AFPIAC stands for "Azure Firewall Policies Infrastructure as Code" - a methodology for managing 
firewall policies through version-controlled configuration files rather than manual configuration.''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Workflow Overview:
  1. Select Firewall Branch (--git-branch <branch>)
  2. Update local Git repository (--git-update)
  3. Save all changes to Git (--git-save <message>)
  4. Download policies from Azure (--download-policies / -do with -f)
  5. Synchronize policies between YAML and CSV (--synchronize / -s with optional conflict resolution)
  6. Import policies from ARM templates to YAML (--import / -i with -f)
  7. Export policies to Bicep (--export / -x with -f)
  8. Compare policies (--compare with -f)
  9. Deploy new Bicep to Azure (--deploy / -d with -f)
  10. Assign policy to Firewall (--assign / -a with -f)

Examples:
  # List available firewalls
  python policiesdeploy.py --list-firewall
  
  # Specify inventory repository path (for multi-repo setups)
  python policiesdeploy.py --inventory-path /path/to/inventory/repo --list-firewall
  
  # Select a firewall branch
  python policiesdeploy.py --git-branch feature/new-rules
  
  # Update local Git repository
  python policiesdeploy.py --git-update
  
  # Save changes to Git
  python policiesdeploy.py --git-save "Updated firewall policies"
  
  # Download policies from Azure for Test environment
  python policiesdeploy.py --download --firewall Test
  
  # Download with custom inventory path
  python policiesdeploy.py --inventory-path /path/to/inventory --download --firewall Test
  
  # Synchronize policies (with conflict resolution)
  python policiesdeploy.py --synchronize --conflict-resolution policies
  
  # Import policies from ARM templates
  python policiesdeploy.py --import --firewall Test
  
  # Export policies to Bicep
  python policiesdeploy.py --export --firewall Test
  
  # Export with custom inventory path
  python policiesdeploy.py --inventory-path /path/to/inventory --export --firewall Test
  
  # Compare policies
  python policiesdeploy.py --compare --firewall Test
  
  # Deploy Bicep templates to Azure
  python policiesdeploy.py --deploy --firewall Test
  
  # Deploy with what-if analysis
  python policiesdeploy.py --deploy --firewall Test --whatif
  
  # Assign policy to firewall
  python policiesdeploy.py --assign --firewall Test
  
  # Enable verbose logging
  python policiesdeploy.py --export --firewall Test --verbose
  
  # Loop mode (keep running after operation)
  python policiesdeploy.py --export --firewall Test --loop
''')
    
    # Git operations
    parser.add_argument('--git-branch', type=str, metavar='BRANCH',
                        help='Select and switch to a firewall branch')
    parser.add_argument('--git-update', action='store_true',
                        help='Update local Git repository (pull latest changes)')
    parser.add_argument('--git-save', type=str, metavar='MESSAGE',
                        help='Save all changes to Git with custom commit message')
    
    # Download/Import operations
    parser.add_argument('--download', '-w', action='store_true',
                        help='Download policies from Azure. Requires --firewall parameter')
    parser.add_argument('--import', '-i', dest='import_policies', action='store_true',
                        help='Import policies from ARM templates to YAML format. Requires --firewall parameter')
    
    # Synchronize operation
    parser.add_argument('--synchronize', '-s', action='store_true',
                        help='Synchronize policies between YAML and CSV formats')
    parser.add_argument('--conflict-resolution', type=str, choices=['policies', 'csv', 'cancel'],
                        help='Specify how to resolve conflicts during synchronization: "policies" to use YAML policies as source, "csv" to use CSV files as source, or "cancel" to abort')
    
    # Export/Deploy operations
    parser.add_argument('--export', '-x', action='store_true',
                        help='Export policies to Bicep templates. Requires --firewall parameter')
    parser.add_argument('--compare', action='store_true',
                        help='Compare policies between import and export. Requires --firewall parameter')
    parser.add_argument('--deploy', '-d', action='store_true',
                        help='Deploy new Bicep templates to Azure. Requires --firewall parameter')
    parser.add_argument('--assign', '-a', action='store_true',
                        help='Assign policy to Firewall. Requires --firewall parameter')
    
    # Firewall selection
    parser.add_argument('--firewall', '-f', type=str, metavar='ENV',
                        help='Specify the firewall key, index, or firewall name')
    
    # Repository paths
    parser.add_argument('--inventory-path', type=str, metavar='PATH',
                        help='Absolute path to the inventory repository (where policies, bicep, firewalls folders are located). If not specified, uses current directory')
    
    # Information and control
    parser.add_argument('--list-firewall', '-l', action='store_true',
                        help='List available Azure Firewall groups and exit')
    parser.add_argument('--version', '-v', action='store_true',
                        help='Show version information and exit')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--loop', action='store_true', default=False,
                        help='Loop the main program after an operation completes instead of exiting')
    parser.add_argument('--whatif', action='store_true', default=False,
                        help='If set, run what-if analysis instead of actual deployment. Default is False.')
    
    # Legacy/internal parameters (deprecated, kept for compatibility)
    parser.add_argument('--save-results', '-r', action='store_true', default=True,
                        help=argparse.SUPPRESS)  # Hidden parameter
    parser.add_argument('--skip-git', action='store_true',
                        help=argparse.SUPPRESS)  # Hidden parameter
    parser.add_argument('--skip-download-prompt', '-p', action='store_true',
                        help=argparse.SUPPRESS)  # Hidden parameter
    parser.add_argument('--clean-export', action='store_true', default=True,
                        help=argparse.SUPPRESS)  # Hidden parameter
    parser.add_argument('--firewall-name', type=str,
                        help=argparse.SUPPRESS)  # Hidden parameter
    parser.add_argument('--policy-name', type=str,
                        help=argparse.SUPPRESS)  # Hidden parameter
    
    args = parser.parse_args()
    
    # Set inventory path if provided
    if args.inventory_path:
        set_inventory_path(args.inventory_path)
        # Re-initialize Paths class attributes to use the new inventory path
        Paths.INVENTORY_PATH = get_inventory_path()
        Paths.ARM_DIR = os.path.join(Paths.INVENTORY_PATH, 'arm_import')
        Paths.ARM_EXPORT_DIR = os.path.join(Paths.INVENTORY_PATH, 'arm_export')
        Paths.POLICIES_DIR = os.path.join(Paths.INVENTORY_PATH, 'policies', Paths.POLICIES_FOLDER_NAME)
        Paths.CSV_DIR = os.path.join(Paths.INVENTORY_PATH, 'policies', Paths.CSV_FOLDER_NAME)
        Paths.BICEP_DIR = os.path.join(Paths.INVENTORY_PATH, 'bicep')
        Paths.FIREWALLS_DIR = os.path.join(Paths.INVENTORY_PATH, 'firewalls')
        Paths.RESOURCE_GROUPS_DIR = os.path.join(Paths.INVENTORY_PATH, '_resourceGroups')
        Paths.IPGROUPS_DIR = os.path.join(Paths.INVENTORY_PATH, '_ipgroups')
        Paths.COMPARISON_DIR = os.path.join(Paths.INVENTORY_PATH, 'comparison')
        Paths.LOCK_FILE = os.path.join(Paths.INVENTORY_PATH, '.lock')
    
    # Validate: --download requires --conflict-resolution
    if args.download and not args.conflict_resolution:
        parser.error("--download requires --conflict-resolution (choices: 'policies', 'csv', 'cancel')")
    
    # Determine if running in interactive or non-interactive mode
    # Interactive mode: only when no operation arguments are provided (just "python policiesdeploy.py")
    # Non-interactive mode: when any operation argument is used
    operation_args = [
        args.git_branch, args.git_update, args.git_save,
        args.download, args.import_policies, args.synchronize,
        args.export, args.compare, args.deploy, args.assign,
        args.list_firewall, args.version
    ]
    
    # If any operation argument is provided, run in non-interactive mode
    args.non_interactive = any(operation_args)
    
    return args

